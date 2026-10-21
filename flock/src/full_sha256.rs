use std::array;

use flock_prover::circuit::builder::{CircuitShape, GateType, ShapeBuilder, SlotId, SlotWitness};
use flock_prover::field::F128;
use flock_prover::r1cs::BlockR1cs;
use flock_prover::r1cs_hashes::sha2::{self, Compression};
use flock_prover::schedule::{IoWord, TableType};

use crate::circuit::{CircuitProof, CircuitSetup, WitnessBuffers, pack4, pack8, unpack4, unpack8};
use crate::{SHA256_BLOCK_BYTES, SHA256_LEN_BYTES, sha256_compression_count};

pub struct FullSha256Setup {
    pub(crate) circuit: CircuitSetup<Sha256Gate>,
}

pub type FullSha256Proof = CircuitProof;

pub(crate) struct Sha256Gate {
    r1cs: BlockR1cs,
}

impl GateType for Sha256Gate {
    type Row = Compression;
    type Hint = ();

    fn table(&self) -> TableType {
        // The pinned upstream layout puts H_in at bits 0..256, H_out at
        // 256..512, and the message block at 512..1024. Keep all matrices
        // unchanged and expose these aligned words to the wiring argument.
        TableType::from_block_r1cs(&self.r1cs).with_io_schema(vec![
            IoWord::input(0),
            IoWord::input(1),
            IoWord::input(4),
            IoWord::input(5),
            IoWord::input(6),
            IoWord::input(7),
            IoWord::output(2),
            IoWord::output(3),
        ])
    }

    fn eval(&self, inputs: &[F128], _hint: &(), outputs: &mut Vec<F128>) -> Compression {
        let cv = unpack8(inputs[0], inputs[1]);
        let mut message = [0u32; 16];
        for (words, &packed) in message.chunks_exact_mut(4).zip(&inputs[2..]) {
            words.copy_from_slice(&unpack4(packed));
        }
        outputs.extend_from_slice(&pack8(&sha2::sha256_compress(&cv, &message)));
        (cv, message)
    }

    fn witness(&self, _rows: &[Compression], _nu: usize) -> SlotWitness {
        SlotWitness::DeferredToRows
    }
}

fn padding_block(input_size: usize) -> [u8; SHA256_BLOCK_BYTES] {
    assert!(
        input_size.is_multiple_of(SHA256_BLOCK_BYTES),
        "SHA-256 benchmark inputs must contain complete 64-byte blocks"
    );
    let mut padding = [0u8; SHA256_BLOCK_BYTES];
    padding[0] = 0x80;
    let bit_len = u64::try_from(input_size)
        .expect("SHA-256 input length fits u64")
        .checked_mul(8)
        .expect("SHA-256 bit length fits u64");
    padding[SHA256_BLOCK_BYTES - SHA256_LEN_BYTES..].copy_from_slice(&bit_len.to_be_bytes());
    padding
}

fn pack_block(bytes: &[u8]) -> [F128; 4] {
    array::from_fn(|i| {
        pack4(array::from_fn(|j| {
            let offset = 16 * i + 4 * j;
            u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
        }))
    })
}

fn describe(input_size: usize) -> (CircuitShape, Vec<(SlotId, BlockR1cs)>, usize) {
    let padding = padding_block(input_size);
    let n_compressions = sha256_compression_count(input_size);
    // The published PCS configurations start at m=22. One k_log=15 table
    // therefore needs nu>=7; actual gate counts remain the message's count.
    let nu = (n_compressions.next_power_of_two().ilog2() as usize).max(7);
    let r1cs = sha2::build_block_r1cs(nu);
    let mut builder = ShapeBuilder::new(nu);
    let slot = builder.slot(Sha256Gate { r1cs: r1cs.clone() });
    let mut cv = pack8(&sha2::SHA256_IV).map(|word| builder.fixed_public_input(word));

    for _ in 0..input_size / SHA256_BLOCK_BYTES {
        let message = array::from_fn::<_, 4, _>(|_| builder.input());
        let inputs = [cv[0], cv[1], message[0], message[1], message[2], message[3]];
        cv = builder.gate(slot, &inputs).try_into().unwrap();
    }

    // The entire final block is fixed by the circuit: marker, zero padding,
    // and the big-endian message length. Data blocks remain private inputs.
    let padding = pack_block(&padding).map(|word| builder.fixed_public_input(word));
    let inputs = [cv[0], cv[1], padding[0], padding[1], padding[2], padding[3]];
    let digest = builder.gate(slot, &inputs);
    for word in digest {
        builder.publish(word);
    }

    (
        builder
            .finish()
            .expect("SHA-256 circuit shape must be valid"),
        vec![(slot, r1cs)],
        nu,
    )
}

fn generate_witness(rows: &[Compression], nu: usize) -> WitnessBuffers {
    sha2::generate_witness_batch_major_partial(rows, nu)
}

pub fn prepare(input_size: usize) -> FullSha256Setup {
    let _ = flock_prover::init_perf_thread_pool();
    let (message, expected_digest) = utils::generate_sha256_input(input_size);
    let padding = padding_block(input_size);
    let iv = pack8(&sha2::SHA256_IV);
    let padding_words = pack_block(&padding);
    let mut inputs = iv.to_vec();
    for block in message.chunks_exact(SHA256_BLOCK_BYTES) {
        inputs.extend(pack_block(block));
    }
    inputs.extend(padding_words);

    // Build the verifier's expected digest from the independent input
    // generator, rather than from the gate evaluator or a prover result.
    let digest_words = array::from_fn(|i| {
        u32::from_be_bytes(expected_digest[4 * i..4 * i + 4].try_into().unwrap())
    });
    let mut public = iv.to_vec();
    public.extend(padding_words);
    public.extend(pack8(&digest_words));

    let (shape, slots, nu) = describe(input_size);
    FullSha256Setup {
        circuit: CircuitSetup::new(
            shape,
            slots,
            nu,
            inputs,
            Vec::new(),
            public,
            generate_witness,
        ),
    }
}

pub fn prove(setup: &FullSha256Setup, transcript_domain: &[u8]) -> FullSha256Proof {
    setup.circuit.prove(transcript_domain)
}

pub fn verify(setup: &FullSha256Setup, proof: &FullSha256Proof, transcript_domain: &[u8]) {
    setup
        .circuit
        .verify(proof, transcript_domain)
        .expect("Flock full SHA-256 digest proof must verify");
}

pub fn num_constraints(setup: &FullSha256Setup) -> usize {
    setup.circuit.num_constraints()
}

pub fn preprocessing_size(setup: &FullSha256Setup) -> usize {
    setup.circuit.preprocessing_size()
}

pub fn proof_size(proof: &FullSha256Proof) -> usize {
    proof.proof_size()
}

#[cfg(test)]
mod tests {
    use std::any::Any;

    use flock_prover::circuit::{Cell, Circuit};

    use super::*;

    #[test]
    fn iv_and_complete_padding_block_are_fixed_public_inputs() {
        let (shape, _, _) = describe(128);
        let mut public = pack8(&sha2::SHA256_IV).to_vec();
        public.extend(pack_block(&padding_block(128)));
        public.extend([F128::ZERO; 2]);
        assert!(shape.circuit.check_public(&public));

        for i in 0..6 {
            let mut changed = public.clone();
            changed[i] += F128::ONE;
            assert!(!shape.circuit.check_public(&changed));
        }
        let padding = padding_block(128);
        assert_eq!(padding[0], 0x80);
        assert!(padding[1..56].iter().all(|&byte| byte == 0));
        assert_eq!(&padding[56..], &1024u64.to_be_bytes());
    }

    #[test]
    fn every_compression_output_is_wired_to_the_next_input() {
        let (shape, _, _) = describe(128);
        let wires = shape.circuit.wires();
        let index = |cell| shape.circuit.cells().cell_index(cell);
        for row in 0..2 {
            for word in 0..2 {
                assert!(wires.iter().any(|wire| {
                    wire.contains(&index(Cell::new(6 + word, row)))
                        && wire.contains(&index(Cell::new(word, row + 1)))
                }));
            }
        }
        for word in 0..2 {
            assert!(wires.iter().any(|wire| {
                wire.contains(&index(Cell::new(6 + word, 2)))
                    && wire.contains(&index(Cell::new(8, 6 + word)))
            }));
        }
    }

    #[test]
    fn prepared_statement_uses_the_independent_digest() {
        for input_size in [128, 256, 512, 1024, 2048] {
            let prepared = prepare(input_size);
            let hints: &[&(dyn Any + Sync)] = &[];
            let witness = prepared.circuit.shape.run(&prepared.circuit.inputs, hints);
            assert_eq!(witness.public, prepared.circuit.public, "size {input_size}");
            assert_eq!(
                prepared.circuit.shape.counts[0],
                sha256_compression_count(input_size)
            );

            let mut changed_digest = prepared.circuit.public.clone();
            changed_digest[6] += F128::ONE;
            assert_ne!(witness.public, changed_digest);
        }
    }

    #[test]
    fn proof_binds_the_public_digest_and_compression_chain() {
        let mut prepared = prepare(128);
        let proof = prepared.circuit.prove(crate::TRANSCRIPT_DOMAIN);
        prepared
            .circuit
            .verify(&proof, crate::TRANSCRIPT_DOMAIN)
            .unwrap();

        prepared.circuit.public[6] += F128::ONE;
        assert!(
            prepared
                .circuit
                .verify(&proof, crate::TRANSCRIPT_DOMAIN)
                .is_err()
        );
        prepared.circuit.public[6] += F128::ONE;

        // Keep the same matrices, dimensions, invocation counts and public
        // values, but exchange the two CV words on the first chain edge.
        let old_digest = prepared.circuit.shape.circuit.digest();
        let nu = prepared.circuit.nu;
        let swapped = [Cell::new(0, 1), Cell::new(1, 1)];
        let wires = prepared
            .circuit
            .shape
            .circuit
            .wires()
            .iter()
            .map(|wire| {
                wire.iter()
                    .map(|&index| {
                        let cell = Cell::new(index >> nu, index & ((1 << nu) - 1));
                        if cell == swapped[0] {
                            swapped[1]
                        } else if cell == swapped[1] {
                            swapped[0]
                        } else {
                            cell
                        }
                    })
                    .collect()
            })
            .collect();
        let fixed_public = prepared
            .circuit
            .public
            .iter()
            .enumerate()
            .map(|(index, &value)| (index < 6).then_some(value))
            .collect();
        prepared.circuit.shape.circuit = Circuit::new_with_fixed_public(
            &prepared.circuit.shape.registry,
            prepared.circuit.shape.counts.clone(),
            fixed_public,
            wires,
        )
        .unwrap();
        assert_ne!(prepared.circuit.shape.circuit.digest(), old_digest);
        assert!(
            prepared
                .circuit
                .verify(&proof, crate::TRANSCRIPT_DOMAIN)
                .is_err()
        );
    }
}

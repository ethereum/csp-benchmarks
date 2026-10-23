use flock_hash::blake3_compress;
use flock_prover::circuit::builder::{GateType, ShapeBuilder, SlotWitness, Wire};
use flock_prover::field::F128;
use flock_prover::r1cs::WitnessLayout;
use flock_prover::r1cs_hashes::blake3::{self, Compression};
use flock_prover::schedule::TableType;

use crate::blake3_compression_count;
use crate::circuit::{CircuitProof, CircuitSetup, pack4, pack8, unpack4, unpack8};

const BLOCK_BYTES: usize = 64;
const CHUNK_BYTES: usize = 1024;
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;

pub struct FullBlake3Setup {
    pub(crate) circuit: CircuitSetup<Blake3Gate>,
}

pub type FullBlake3Proof = CircuitProof;

pub(crate) struct Blake3Gate {
    nu: usize,
}

impl GateType for Blake3Gate {
    type Row = Compression;
    type Hint = ();

    fn table(&self) -> TableType {
        TableType::from_block_r1cs(&blake3::build_block_r1cs(self.nu))
            .with_io_schema(blake3::io_schema())
    }

    fn eval(&self, inputs: &[F128], _hint: &(), outputs: &mut Vec<F128>) -> Compression {
        let cv = unpack8(inputs[0], inputs[1]);
        let mut message = [0; 16];
        for (words, &packed) in message.chunks_exact_mut(4).zip(&inputs[2..6]) {
            words.copy_from_slice(&unpack4(packed));
        }
        let params = inputs[6];
        let (counter, block_len, flags) = (params.lo, params.hi as u32, (params.hi >> 32) as u32);
        let output = blake3_compress(&cv, &message, counter, block_len, flags);
        outputs.extend_from_slice(&pack8(&output[..8].try_into().unwrap()));
        outputs.extend_from_slice(&pack8(&output[8..].try_into().unwrap()));
        (cv, message, counter, block_len, flags)
    }

    fn witness(&self, _rows: &[Compression], _nu: usize) -> SlotWitness {
        SlotWitness::DeferredToRows
    }
}

pub fn prepare(input_size: usize) -> FullBlake3Setup {
    let _ = flock_prover::init_perf_thread_pool();
    assert!(
        matches!(input_size, 128 | 256 | 512 | 1024 | 2048),
        "unsupported BLAKE3 benchmark size"
    );
    let (message, expected_digest) = utils::generate_blake3_input(input_size);
    let n_compressions = blake3_compression_count(input_size);
    // The shipped Ligerito profiles start at m = K_LOG + nu = 22.
    // The union declares only the real rows; its unused rows are zero.
    let nu = blake3::min_n_blocks_log(n_compressions).max(8);
    let mut r1cs = blake3::build_block_r1cs(nu);
    r1cs.layout = WitnessLayout::BatchMajor;
    let mut builder = ShapeBuilder::new(nu);
    let slot = builder.slot(Blake3Gate { nu });
    let mut inputs = Vec::new();
    let mut public = Vec::new();
    let iv = pack8(&blake3::BLAKE3_IV)
        .map(|value| fixed_input(&mut builder, &mut inputs, &mut public, value));
    let mut chunk_cvs = Vec::new();

    for (chunk_index, chunk) in message.chunks(CHUNK_BYTES).enumerate() {
        let mut cv = iv;
        let n_blocks = chunk.len() / BLOCK_BYTES;
        for (block_index, block) in chunk.chunks_exact(BLOCK_BYTES).enumerate() {
            let mut gate_inputs = Vec::with_capacity(7);
            gate_inputs.extend_from_slice(&cv);
            for word in block.chunks_exact(16) {
                inputs.push(pack4(std::array::from_fn(|i| {
                    u32::from_le_bytes(word[i * 4..i * 4 + 4].try_into().unwrap())
                })));
                gate_inputs.push(builder.input());
            }
            let is_last = block_index + 1 == n_blocks;
            let flags = if block_index == 0 { CHUNK_START } else { 0 }
                | if is_last { CHUNK_END } else { 0 }
                | if is_last && input_size <= CHUNK_BYTES {
                    ROOT
                } else {
                    0
                };
            gate_inputs.push(fixed_input(
                &mut builder,
                &mut inputs,
                &mut public,
                compression_params(chunk_index as u64, flags),
            ));
            let output = builder.gate(slot, &gate_inputs);
            cv = [output[0], output[1]];
        }
        chunk_cvs.push(cv);
    }

    let digest = if input_size > CHUNK_BYTES {
        let params = fixed_input(
            &mut builder,
            &mut inputs,
            &mut public,
            compression_params(0, PARENT | ROOT),
        );
        let output = builder.gate(
            slot,
            &[
                iv[0],
                iv[1],
                chunk_cvs[0][0],
                chunk_cvs[0][1],
                chunk_cvs[1][0],
                chunk_cvs[1][1],
                params,
            ],
        );
        [output[0], output[1]]
    } else {
        chunk_cvs[0]
    };
    for word in digest {
        builder.publish(word);
    }
    // The verifier's digest comes from the reference input generator, rather
    // than from the gate evaluation that constructs the prover's witness.
    let expected_words = std::array::from_fn(|i| {
        u32::from_le_bytes(expected_digest[i * 4..i * 4 + 4].try_into().unwrap())
    });
    public.extend_from_slice(&pack8(&expected_words));
    assert_eq!(builder.rows_in_slot(slot), n_compressions);
    let shape = builder.finish().expect("valid full BLAKE3 circuit");
    let circuit = CircuitSetup::new(
        shape,
        vec![(slot, r1cs)],
        nu,
        inputs,
        Vec::new(),
        public,
        blake3::generate_witness_batch_major_partial,
    );
    FullBlake3Setup { circuit }
}

fn compression_params(counter: u64, flags: u32) -> F128 {
    F128::new(counter, BLOCK_BYTES as u64 | ((flags as u64) << 32))
}

fn fixed_input(
    builder: &mut ShapeBuilder,
    inputs: &mut Vec<F128>,
    public: &mut Vec<F128>,
    value: F128,
) -> Wire {
    inputs.push(value);
    public.push(value);
    builder.fixed_public_input(value)
}

pub fn prove(setup: &FullBlake3Setup, transcript_domain: &[u8]) -> FullBlake3Proof {
    setup.circuit.prove(transcript_domain)
}

pub fn verify(setup: &FullBlake3Setup, proof: &FullBlake3Proof, transcript_domain: &[u8]) {
    setup
        .circuit
        .verify(proof, transcript_domain)
        .expect("Flock full BLAKE3 digest proof must verify");
}

pub fn num_constraints(setup: &FullBlake3Setup) -> usize {
    setup.circuit.num_constraints()
}

pub fn preprocessing_size(setup: &FullBlake3Setup) -> usize {
    setup.circuit.preprocessing_size()
}

pub fn proof_size(proof: &FullBlake3Proof) -> usize {
    proof.proof_size()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flock_prover::circuit::{Cell, Circuit};

    #[test]
    fn full_hash_wiring_matches_the_requested_digest() {
        for input_size in [128, 256, 512, 1024, 2048] {
            let setup = prepare(input_size);
            let witness = setup.circuit.shape.run(&setup.circuit.inputs, &[]);
            assert_eq!(witness.public, setup.circuit.public, "size {input_size}");
            assert_eq!(
                setup.circuit.shape.counts[0],
                blake3_compression_count(input_size)
            );
            // Only the IV, per-compression parameters and digest are public.
            assert_eq!(
                setup.circuit.public.len(),
                setup.circuit.shape.counts[0] + 4
            );
            assert_eq!(
                setup.circuit.inputs.len(),
                input_size / 16 + setup.circuit.shape.counts[0] + 2
            );
        }
    }

    #[test]
    fn digest_parameters_and_chunk_wiring_are_bound() {
        let mut setup = prepare(128);
        let domain = b"csp-flock-blake3-wrapper-binding";
        let proof = prove(&setup, domain);
        setup.circuit.verify(&proof, domain).unwrap();

        let digest_index = setup.circuit.public.len() - 2;
        for (label, index, delta) in [
            ("digest", digest_index, F128::ONE),
            ("counter", 2, F128::new(1, 0)),
            ("block length", 2, F128::new(0, 1)),
            ("flags", 2, F128::new(0, 1 << 32)),
        ] {
            setup.circuit.public[index] += delta;
            assert!(
                setup.circuit.verify(&proof, domain).is_err(),
                "changed {label} accepted"
            );
            setup.circuit.public[index] += delta;
        }

        // Remove the first chaining equality while retaining the same gate
        // counts and public words. The original proof must not authenticate
        // this different full-hash relation.
        let shape = &mut setup.circuit.shape;
        let circuit = &shape.circuit;
        let nu = setup.circuit.nu;
        let cells = circuit.cells();
        let previous_output = cells.cell_index(Cell::new(7, 0));
        let next_input = cells.cell_index(Cell::new(0, 1));
        let mut removed = false;
        let wires = circuit
            .wires()
            .iter()
            .map(|class| {
                let is_chain = class.contains(&previous_output) && class.contains(&next_input);
                removed |= is_chain;
                class
                    .iter()
                    .filter(|&&index| !is_chain || index != next_input)
                    .map(|&index| Cell::new(index >> nu, index & ((1 << nu) - 1)))
                    .collect()
            })
            .collect();
        assert!(removed, "chunk chaining must be wired into the circuit");
        let fixed_public = setup.circuit.public[..digest_index]
            .iter()
            .copied()
            .map(Some)
            .chain([None, None])
            .collect();
        let changed = Circuit::new_with_fixed_public(
            &shape.registry,
            shape.counts.clone(),
            fixed_public,
            wires,
        )
        .unwrap();
        assert_ne!(changed.digest(), circuit.digest());
        shape.circuit = changed;
        assert!(setup.circuit.verify(&proof, domain).is_err());
    }
}

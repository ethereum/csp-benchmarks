mod artifacts;
mod comb_witness;
mod ecdsa_hints;
mod ecdsa_input;
mod poseidon;

use std::{borrow::Cow, cell::RefCell, rc::Rc};

use artifacts::{Artifacts, WitnessArtifacts};
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use spartan_whir::{
    DEFAULT_ZK_ELL, DEFAULT_ZK_MASK_LOG_INV_RATE, MatrixClosingMode, PoseidonZkProof,
    PoseidonZkProvingKey, PoseidonZkSetupConfig, PoseidonZkVerifyingKey, QuinticExtension,
    SecurityConfig, SoundnessAssumption, engine::F, recommended_quintic_zk_whir_params,
};
use utils::harness::{AuditStatus, BenchProperties};

pub const SECURITY_BITS: u32 = 115;

pub const SPARTAN_WHIR_BENCH_PROPERTIES: BenchProperties = BenchProperties {
    proving_system: Cow::Borrowed("Spartan-WHIR"),
    field_curve: Cow::Borrowed("KoalaBear"),
    iop: Cow::Borrowed("Spartan"),
    pcs: Some(Cow::Borrowed("WHIR")),
    arithm: Cow::Borrowed("R1CS"),
    is_zk: true,
    is_zkvm: false,
    security_bits: SECURITY_BITS as u64,
    is_pq: true,
    is_maintained: true,
    is_audited: AuditStatus::NotAudited,
    isa: None,
};

type ProvingKey = PoseidonZkProvingKey<QuinticExtension>;
type VerifyingKey = PoseidonZkVerifyingKey<QuinticExtension>;
pub type Proof = PoseidonZkProof<QuinticExtension>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    Sha256,
    Keccak,
    Poseidon,
    Ecdsa,
    EcdsaP256,
}

impl Target {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Keccak => "keccak",
            Self::Poseidon => "poseidon",
            Self::Ecdsa => "ecdsa",
            Self::EcdsaP256 => "ecdsa_p256",
        }
    }

    fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(message).to_vec(),
            Self::Keccak => Keccak256::digest(message).to_vec(),
            _ => panic!("{} is not a byte hash", self.as_str()),
        }
    }
}

struct Circuit {
    target: Target,
    artifacts: WitnessArtifacts,
    num_cons: usize,
    num_vars: usize,
    num_io: usize,
    #[cfg(test)]
    shape: spartan_whir::R1csShape<F>,
    proving_key: ProvingKey,
    verifying_key: VerifyingKey,
    preprocessing_size: usize,
}

// Linked Circom generators hold native circuit handles. Keep each handle on the
// Criterion thread and share its immutable setup across samples on that thread.
thread_local! {
    static CIRCUIT: RefCell<Option<(Target, usize, Rc<Circuit>)>> = const { RefCell::new(None) };
}

pub struct Prepared {
    circuit: Rc<Circuit>,
    input: Vec<u8>,
    expected_public_inputs: Vec<F>,
}

fn setup(target: Target, input_size: usize) -> Circuit {
    let Artifacts { shape, witness } = artifacts::load(target.as_str(), input_size)
        .expect("failed to compile or load the KoalaBear circuit");
    let num_cons = shape.num_cons;
    let num_vars = shape.num_vars;
    let num_io = shape.num_io;
    let num_variables = num_vars.next_power_of_two().ilog2() as usize;
    #[cfg(test)]
    let validation_shape = shape.clone();
    let config = PoseidonZkSetupConfig {
        matrix_closing: MatrixClosingMode::DirectSparse,
        security: SecurityConfig {
            security_level_bits: SECURITY_BITS,
            merkle_security_bits: SECURITY_BITS,
            soundness_assumption: SoundnessAssumption::JohnsonBound,
        },
        whir_params: recommended_quintic_zk_whir_params(num_variables),
        spark_whir_params: None,
        ell_zk: DEFAULT_ZK_ELL,
        mask_log_inv_rate: DEFAULT_ZK_MASK_LOG_INV_RATE,
    };
    let (proving_key, verifying_key) = ProvingKey::setup(shape, config)
        .expect("Spartan-WHIR setup rejected the circuit or security settings");
    let preprocessing_size =
        bincode::serialized_size(&proving_key).unwrap() as usize + witness.witness_artifact_size;
    Circuit {
        target,
        artifacts: witness,
        num_cons,
        num_vars,
        num_io,
        #[cfg(test)]
        shape: validation_shape,
        proving_key,
        verifying_key,
        preprocessing_size,
    }
}

pub fn prepare(target: Target, input_size: usize) -> Prepared {
    if target == Target::Poseidon {
        let (input, expected_public_inputs) = poseidon::input(input_size);
        return Prepared {
            circuit: circuit(target, input_size),
            input,
            expected_public_inputs,
        };
    }
    if matches!(target, Target::Ecdsa | Target::EcdsaP256) {
        assert_eq!(input_size, 32, "ECDSA uses a 32-byte message digest");
        let (input, expected_public_inputs) = ecdsa_input::input(target == Target::EcdsaP256);
        return Prepared {
            circuit: circuit(target, input_size),
            input,
            expected_public_inputs,
        };
    }
    let (message, _) = match target {
        Target::Sha256 => utils::generate_sha256_input(input_size),
        Target::Keccak => utils::generate_keccak_input(input_size),
        _ => panic!("unsupported target {}", target.as_str()),
    };
    prepare_message(target, &message)
}

/// Select the statement from the message and an independent native hash.
pub fn prepare_message(target: Target, message: &[u8]) -> Prepared {
    assert!(
        [128, 256, 512, 1024, 2048].contains(&message.len()),
        "unsupported hash input size: {}",
        message.len()
    );
    let circuit = circuit(target, message.len());
    let digest = target.digest(message);
    let expected_public_inputs = digest.iter().map(|&byte| F::from_u8(byte)).collect();
    // Circom places the public digest before the private message in its input ABI.
    let input = digest
        .iter()
        .chain(message)
        .flat_map(|&byte| u32::from(byte).to_le_bytes())
        .collect();
    Prepared {
        circuit,
        input,
        expected_public_inputs,
    }
}

fn circuit(target: Target, input_size: usize) -> Rc<Circuit> {
    CIRCUIT.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some((cached_target, cached_size, circuit)) = &*cache
            && (*cached_target, *cached_size) == (target, input_size)
        {
            return Rc::clone(circuit);
        }
        *cache = None;
        let circuit = Rc::new(setup(target, input_size));
        *cache = Some((target, input_size, Rc::clone(&circuit)));
        circuit
    })
}

pub fn num_constraints(prepared: &Prepared) -> usize {
    prepared.circuit.num_cons
}

pub fn preprocessing_size(prepared: &Prepared) -> usize {
    prepared.circuit.preprocessing_size
}

impl Prepared {
    fn witness_input(&self) -> Cow<'_, [u8]> {
        match self.circuit.target {
            Target::Ecdsa | Target::EcdsaP256 => Cow::Owned(
                ecdsa_hints::augment(self.circuit.target == Target::EcdsaP256, &self.input)
                    .expect("failed to generate ECDSA auxiliary witnesses"),
            ),
            _ => Cow::Borrowed(&self.input),
        }
    }
}

/// Includes native witness generation and randomized full-ZK proving.
pub fn prove(prepared: &Prepared) -> Proof {
    let artifacts = &prepared.circuit.artifacts;
    let (witness, public_inputs) = artifacts
        .generator
        .generate_witness(
            prepared.witness_input(),
            prepared.circuit.num_vars,
            prepared.circuit.num_io,
        )
        .expect("linked Circom witness generation failed");
    assert_eq!(public_inputs, prepared.expected_public_inputs);
    prepared
        .circuit
        .proving_key
        .prove(witness, public_inputs)
        .expect("Spartan-WHIR proving failed")
}

pub fn verify(prepared: &Prepared, proof: &Proof) {
    prepared
        .circuit
        .verifying_key
        .verify(&prepared.expected_public_inputs, proof)
        .expect("Spartan-WHIR verification failed");
}

pub fn proof_size(proof: &Proof) -> usize {
    bincode::serialized_size(proof).expect("cannot serialize the proof") as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use spartan_whir::validate_satisfaction;

    #[test]
    #[ignore = "requires the KoalaBear Circom compiler and native C++ headers"]
    fn hash_circuits_match_native_hashes() {
        for target in [Target::Sha256, Target::Keccak] {
            for size in utils::metadata::selected_byte_inputs() {
                for message in [
                    vec![0; size],
                    vec![255; size],
                    (0..size).map(|i| i as u8).collect(),
                ] {
                    let prepared = prepare_message(target, &message);
                    let artifacts = &prepared.circuit.artifacts;
                    let (witness, public_inputs) = artifacts
                        .generator
                        .generate_witness(
                            prepared.witness_input(),
                            prepared.circuit.num_vars,
                            prepared.circuit.num_io,
                        )
                        .unwrap();
                    assert_eq!(public_inputs, prepared.expected_public_inputs);
                    validate_satisfaction(&prepared.circuit.shape, &witness, &public_inputs)
                        .unwrap();
                    let mut incorrect_digest = public_inputs;
                    incorrect_digest[0] += F::ONE;
                    assert!(
                        validate_satisfaction(&prepared.circuit.shape, &witness, &incorrect_digest)
                            .is_err()
                    );
                }
            }
        }
    }

    #[test]
    #[ignore = "requires the KoalaBear Circom compiler and native C++ headers"]
    fn hash_proofs_verify_against_expected_digests() {
        for target in [Target::Sha256, Target::Keccak] {
            for size in utils::metadata::selected_byte_inputs() {
                let prepared = prepare(target, size);
                let proof = prove(&prepared);
                verify(&prepared, &proof);
                assert_eq!(
                    proof_size(&proof),
                    bincode::serialize(&proof).unwrap().len()
                );
                let mut incorrect_digest = prepared.expected_public_inputs.clone();
                incorrect_digest[0] += F::ONE;
                assert!(
                    prepared
                        .circuit
                        .verifying_key
                        .verify(&incorrect_digest, &proof)
                        .is_err()
                );
            }
        }
    }

    #[test]
    #[ignore = "requires the KoalaBear Circom compiler and native C++ headers"]
    fn poseidon_circuits_match_native_hashes_and_prove() {
        for size in utils::metadata::selected_field_element_inputs() {
            let prepared = prepare(Target::Poseidon, size);
            let artifacts = &prepared.circuit.artifacts;
            let (witness, public_inputs) = artifacts
                .generator
                .generate_witness(
                    prepared.witness_input(),
                    prepared.circuit.num_vars,
                    prepared.circuit.num_io,
                )
                .unwrap();
            assert_eq!(public_inputs, prepared.expected_public_inputs);
            validate_satisfaction(&prepared.circuit.shape, &witness, &public_inputs).unwrap();
            let proof = prove(&prepared);
            verify(&prepared, &proof);
            let mut incorrect_digest = public_inputs;
            incorrect_digest[0] += F::ONE;
            assert!(
                prepared
                    .circuit
                    .verifying_key
                    .verify(&incorrect_digest, &proof)
                    .is_err()
            );
        }
    }

    #[test]
    #[ignore = "requires the KoalaBear Circom compiler and native C++ headers"]
    fn ecdsa_proofs_bind_the_message_and_public_key() {
        for target in [Target::Ecdsa, Target::EcdsaP256] {
            let prepared = prepare(target, 32);
            let artifacts = &prepared.circuit.artifacts;
            let (witness, public_inputs) = artifacts
                .generator
                .generate_witness(
                    prepared.witness_input(),
                    prepared.circuit.num_vars,
                    prepared.circuit.num_io,
                )
                .unwrap();
            assert_eq!(public_inputs, prepared.expected_public_inputs);
            assert_eq!(public_inputs.len(), 96);
            validate_satisfaction(&prepared.circuit.shape, &witness, &public_inputs).unwrap();
            let proof = prove(&prepared);
            verify(&prepared, &proof);
            for changed_index in [0, 32, 64] {
                let mut incorrect_statement = public_inputs.clone();
                incorrect_statement[changed_index] += F::ONE;
                assert!(
                    prepared
                        .circuit
                        .verifying_key
                        .verify(&incorrect_statement, &proof)
                        .is_err()
                );
            }
        }
    }

    #[test]
    #[ignore = "requires the KoalaBear Circom compiler and native C++ headers"]
    fn ecdsa_auxiliary_witnesses_are_constrained() {
        for target in [Target::Ecdsa, Target::EcdsaP256] {
            let prepared = prepare(target, 32);
            let original = prepared.witness_input().into_owned();
            let fields: Vec<_> = original
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
                .collect();
            assert_eq!(fields.len(), 252);
            let mut mutations = vec![
                (160, fields[160] ^ 1),
                (182, fields[182] ^ 1),
                (160, 4096),
                (204, fields[204] ^ 1),
                (204, 4096),
                (248, 2),
            ];
            if target == Target::EcdsaP256 {
                mutations.extend([(214, 256), (226, 1), (250, 1)]);
            } else {
                mutations.extend([(209, 16), (210, 1)]);
            }
            let mut inputs = Vec::new();
            for (index, value) in mutations {
                let mut input = original.clone();
                input[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
                inputs.push(input);
            }
            let mut zero_denominator = original;
            zero_denominator[204 * 4..].fill(0);
            inputs.push(zero_denominator);
            for input in inputs {
                if let Ok((witness, public_inputs)) = prepared
                    .circuit
                    .artifacts
                    .generator
                    .generate_witness(&input, prepared.circuit.num_vars, prepared.circuit.num_io)
                {
                    assert!(
                        validate_satisfaction(&prepared.circuit.shape, &witness, &public_inputs)
                            .is_err(),
                        "an invalid ECDSA auxiliary witness satisfied the circuit"
                    );
                }
            }
        }
    }
}

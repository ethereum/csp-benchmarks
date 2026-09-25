pub mod ecdsa;
pub mod ecdsa_input;
pub mod ecdsa_p256;
pub mod ecdsa_p256_input;
pub mod keccak;
pub mod poseidon;
pub mod sha256;

use circom_prover::{
    CircomProver,
    prover::{CircomProof, ProofLib},
    witness::WitnessFn,
};
use num_bigint::BigUint;
use std::borrow::Cow;
use std::path::Path;
use utils::harness::{AuditStatus, BenchProperties};
use witnesscalc_adapter::parse_witness_to_bigints;

/// Stack for the witness thread. A default thread gets 2 MiB, which the ECDSA
/// witness generator overruns: the width-12 comb table alone holds 1.88 MB of
/// locals in a single frame, and the signature checks add another 1.1 MB on top.
const WITNESS_STACK: usize = 8 * 1024 * 1024;

/// Runs `f` on a thread with `WITNESS_STACK`, as `prove` runs the witness
/// generator. Tests that call an ECDSA generator directly would otherwise run it
/// on the 2 MiB test thread and abort the whole test binary.
#[cfg(test)]
pub(crate) fn on_witness_stack<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
    std::thread::Builder::new()
        .stack_size(WITNESS_STACK)
        .spawn(f)
        .expect("Failed to spawn the witness thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

pub const CIRCOM_BENCH_PROPERTIES: BenchProperties = BenchProperties {
    proving_system: Cow::Borrowed("Groth16"),
    field_curve: Cow::Borrowed("Bn254"),
    iop: Cow::Borrowed("Groth16"),
    pcs: None,
    arithm: Cow::Borrowed("R1CS"),
    is_zk: true,
    is_zkvm: false,
    security_bits: 100, // BN254 pairing security is about 100 bits after exTNFS estimates, see https://eips.ethereum.org/assets/eip-3068/2017-334.pdf and https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-12
    is_pq: false,
    is_maintained: true,
    is_audited: AuditStatus::PartiallyAudited, // e.g., https://veridise.com/wp-content/uploads/2023/02/VAR-circom-bigint.pdf
    isa: None,
};

pub fn sum_file_sizes_in_the_dir(file_path: &str) -> std::io::Result<usize> {
    let dir = Path::new(file_path)
        .parent()
        .expect("File should have a parent directory");

    let mut total_size: usize = 0;

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let metadata = entry.metadata()?;

        if metadata.is_file() {
            total_size += metadata.len() as usize;
        }
    }

    Ok(total_size)
}

pub fn prove(witness_fn: WitnessFn, input_str: String, zkey_path: String) -> CircomProof {
    // Spawn the witness thread here rather than letting `CircomProver::prove` do
    // it, so that it gets `WITNESS_STACK` instead of the default 2 MiB. The
    // prover takes the thread already running and joins it.
    let witnesses = std::thread::Builder::new()
        .stack_size(WITNESS_STACK)
        .spawn(move || {
            let witness = match witness_fn {
                WitnessFn::WitnessCalc(wit_fn) => wit_fn(input_str.as_str()).unwrap(),
                _ => panic!("Unsupported witness function"),
            };
            parse_witness_to_bigints(&witness)
                .unwrap()
                .into_iter()
                .map(|w| w.to_biguint().unwrap())
                .collect::<Vec<BigUint>>()
        })
        .expect("Failed to spawn the witness thread");

    // Generate proof
    circom_prover::prover::prove(
        ProofLib::Rapidsnark, // The rapidsnark prover
        zkey_path,
        witnesses,
    )
    .unwrap()
}

pub fn verify(proof: CircomProof, zkey_path: String) {
    // Verify proof
    let valid = CircomProver::verify(ProofLib::Rapidsnark, proof, zkey_path).unwrap();

    assert!(valid);
}

pub fn read_constraint_count(zkey_path: &str) -> usize {
    use ark_bn254::Bn254;
    use circom_prover::prover::ark_circom;
    use std::fs::File;
    use std::io::BufReader;

    let mut buffer = BufReader::new(File::open(zkey_path).expect("Unable to open zkey"));
    let (_, constraint_matrices) =
        ark_circom::read_zkey::<_, Bn254>(&mut buffer).expect("Unable to read zkey");
    constraint_matrices.num_constraints
}

pub fn proof_size(proof: &CircomProof) -> usize {
    serde_json::to_vec(proof)
        .expect("Failed to serialize proof")
        .len()
}

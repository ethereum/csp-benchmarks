use std::borrow::Cow;
use vega_prover::provider::T256HyraxEngine;

pub type E = T256HyraxEngine;
pub type Scalar = <E as vega_prover::traits::Engine>::Scalar;

pub mod circuits;

use circuits::sha256_circuit::Sha256Circuit;
use utils::generate_sha256_input;
use utils::harness::{AuditStatus, BenchProperties};
use vega_prover::{traits::snark::R1CSSNARKTrait, vega_sc_zkp::VegaZkSNARK};

pub const VEGA_BENCH_PROPERTIES: BenchProperties = BenchProperties {
    proving_system: Cow::Borrowed("Vega"),
    field_curve: Cow::Borrowed("T256"),
    iop: Cow::Borrowed("Spartan + Nova"),
    pcs: Some(Cow::Borrowed("Hyrax")),
    arithm: Cow::Borrowed("R1CS"),
    // This flow rerandomizes witness commitments and hides the verifier trace by
    // folding a random relaxed instance, then proving the folded instance.
    // https://github.com/microsoft/vega-prover/blob/c0ee259053cd12eaf43ed71b5cde375452b3ee4d/src/vega_sc_zkp.rs
    is_zk: true,
    is_zkvm: false,
    security_bits: 128,
    is_pq: false,
    is_maintained: true,
    is_audited: AuditStatus::NotAudited,
    isa: None,
};

/// Prepared context for SHA256 benchmark
pub struct PreparedSha256 {
    circuit: Sha256Circuit,
    digest: [u8; 32],
    pk: <VegaZkSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    vk: <VegaZkSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
}

/// Prepare SHA256 circuit for benchmarking
pub fn prepare_sha256(input_size: usize) -> PreparedSha256 {
    // Generate SHA256 inputs
    let (preimage, digest) = generate_sha256_input(input_size);
    let digest: [u8; 32] = digest
        .try_into()
        .expect("SHA-256 digest must have 32 bytes");

    // Create circuit
    let circuit = Sha256Circuit::new(preimage, digest);

    // Setup keys
    let (pk, vk) = VegaZkSNARK::<E>::setup(circuit.clone()).expect("setup failed");

    PreparedSha256 {
        circuit,
        digest,
        pk,
        vk,
    }
}

/// Generate proof for SHA256 circuit
pub fn prove_sha256(prepared: &PreparedSha256) -> VegaZkSNARK<E> {
    // Prepare the SNARK
    let prep_snark = VegaZkSNARK::<E>::prep_prove(&prepared.pk, prepared.circuit.clone(), true)
        .expect("prep_prove failed");

    // Generate proof
    // prep_prove includes witness generation and remains inside proving time.
    // Each benchmark iteration starts with fresh prep instead of reusing a
    // witness-dependent cache across proofs.
    VegaZkSNARK::<E>::prove(&prepared.pk, prepared.circuit.clone(), prep_snark, true)
        .expect("Failed to generate proof")
        .0
}

/// Verify proof for SHA256 circuit
pub fn verify_sha256(prepared: &PreparedSha256, proof: &VegaZkSNARK<E>) {
    assert!(
        verify_sha256_statement(prepared, proof, &prepared.digest),
        "Verification failed"
    );
}

/// Verify the proof and compare its authenticated output with the requested digest.
pub fn verify_sha256_statement(
    prepared: &PreparedSha256,
    proof: &VegaZkSNARK<E>,
    digest: &[u8; 32],
) -> bool {
    proof.verify(&prepared.vk).is_ok_and(|public_values| {
        public_values == circuits::sha256_circuit::digest_public_values(digest)
    })
}

/// Get number of constraints
pub fn num_constraints(prepared: &PreparedSha256) -> usize {
    // Get number of constraints from the proving key's sizes
    // sizes() returns [num_cons_unpadded, num_shared_unpadded, num_precommitted_unpadded, num_rest_unpadded,
    //                  num_cons, num_shared, num_precommitted, num_rest, num_public, num_challenges]
    let sizes = prepared.pk.sizes();
    sizes[4] // num_cons (padded)
}

/// Get preprocessing size (proving key size)
pub fn preprocessing_size(prepared: &PreparedSha256) -> usize {
    bincode::serialize(&prepared.pk)
        .map(|bytes| bytes.len())
        .unwrap_or(0)
}

/// Get proof size
pub fn proof_size(proof: &VegaZkSNARK<E>) -> usize {
    bincode::serialize(proof)
        .map(|bytes| bytes.len())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_wrapper_checks_the_requested_digest() {
        let prepared = prepare_sha256(1);
        let proof = prove_sha256(&prepared);
        assert!(verify_sha256_statement(&prepared, &proof, &prepared.digest));

        let mut wrong_digest = prepared.digest;
        wrong_digest[0] ^= 1;
        assert!(!verify_sha256_statement(&prepared, &proof, &wrong_digest));
    }
}

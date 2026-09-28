//! SHA256 benchmark using Rookie Numbers prover.
//!
//! The pinned verifier receives only values returned by `prove_sha256`; this benchmark does not
//! supply a public digest to the verifier.

use rookie_numbers::{
    secure_pcs_config, MAX_PREPROCESSED_LOG_SIZE, ROOKIE_NUMBERS_BENCH_PROPERTIES,
};
use sha256::{preprocess_sha256, prove_sha256, verify_sha256};
use utils::harness::ProvingSystem;

utils::define_benchmark_harness!(
    BenchTarget::Sha256,
    ProvingSystem::RookieNumbers,
    None,
    "sha256_mem_rookie_numbers",
    ROOKIE_NUMBERS_BENCH_PROPERTIES,
    |_| Some(utils::bench::Acceleration::Precompile),
    // Shared state: preprocess once with MAX_PREPROCESSED_LOG_SIZE
    { preprocess_sha256(MAX_PREPROCESSED_LOG_SIZE, secure_pcs_config()) },
    // prepare: |input_size, &preprocessed| -> PreparedContext
    |input_size, _preprocessed| utils::generate_sha256_input(input_size).0,
    // num_constraints: |ctx, &shared| -> usize
    |_words, _preprocessed| 1076, // components.n_constraints()
    // prove: |words, &shared| -> Proof
    |words, preprocessed| prove_sha256(words, secure_pcs_config(), preprocessed),
    // verify: |words, proof, &shared| -> ()
    |_words, proof, _preprocessed| verify_sha256(proof.0.clone(), proof.1, &proof.2)
        .expect("verify failed"),
    // preprocessing_size: |words, &shared| -> usize
    |_words, preprocessed| bincode::serialize(preprocessed)
        .map(|v| v.len())
        .unwrap_or(0),
    // proof_size: |proof, &shared| -> usize
    |proof, _preprocessed| bincode::serialize(proof).map(|v| v.len()).unwrap_or(0)
);

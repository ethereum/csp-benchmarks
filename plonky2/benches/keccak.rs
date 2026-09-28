use plonky2_circuits::PLONKY2_BENCH_PROPERTIES;
use plonky2_circuits::bench::{
    compute_proof_size, compute_u32_preprocessing_size, keccak256_prepare, prove, verify_proof,
};
use utils::harness::ProvingSystem;

utils::define_benchmark_harness!(
    BenchTarget::Keccak,
    ProvingSystem::Plonky2,
    None,
    "keccak_mem",
    PLONKY2_BENCH_PROPERTIES,
    |_| None,
    keccak256_prepare,
    |(_, _, n_gates, _)| *n_gates,
    |(circuit_data, pw, _, _)| { prove(circuit_data, pw.clone()) },
    verify_proof,
    |(circuit_data, _pw, _, _)| compute_u32_preprocessing_size(circuit_data),
    compute_proof_size
);

use plonky2_gpu_circuits::{
    BENCH_PROPERTIES, FEATURE, compute_proof_size, preprocessing_size, prove, sha256_prepare,
    verify_proof,
};
use utils::harness::ProvingSystem;

utils::define_benchmark_harness!(
    BenchTarget::Sha256,
    ProvingSystem::Plonky2Gpu,
    Some(FEATURE),
    "sha256_mem_plonky2_gpu",
    BENCH_PROPERTIES,
    |_| None,
    sha256_prepare,
    |(_, _, n_gates, _)| *n_gates,
    |(data, pw, _, _)| prove(data, pw.clone()),
    verify_proof,
    preprocessing_size,
    compute_proof_size
);

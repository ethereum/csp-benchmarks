use plonky2_gpu_circuits::{
    BENCH_PROPERTIES, FEATURE, compute_proof_size, poseidon_prepare, preprocessing_size, prove,
    verify_proof,
};
use utils::harness::ProvingSystem;

utils::define_benchmark_harness!(
    BenchTarget::Poseidon,
    ProvingSystem::Plonky2Gpu,
    Some(FEATURE),
    "poseidon_mem_plonky2_gpu",
    BENCH_PROPERTIES,
    |_| Some(utils::bench::Acceleration::Precompile),
    poseidon_prepare,
    |(_, _, n_gates, _)| *n_gates,
    |(data, pw, _, _)| prove(data, pw.clone()),
    verify_proof,
    preprocessing_size,
    compute_proof_size
);

use utils::harness::ProvingSystem;
use vega_bench::{
    num_constraints, prepare_sha256, preprocessing_size, proof_size, prove_sha256, verify_sha256,
    VEGA_BENCH_PROPERTIES,
};

utils::define_benchmark_harness!(
    BenchTarget::Sha256,
    ProvingSystem::Vega,
    None,
    "sha256_mem_vega",
    VEGA_BENCH_PROPERTIES,
    |_| None,
    |input_size| { prepare_sha256(input_size) },
    num_constraints,
    prove_sha256,
    verify_sha256,
    preprocessing_size,
    proof_size
);

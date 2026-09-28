use plonky2_circuits::{
    PLONKY2_BENCH_PROPERTIES,
    bench::compute_proof_size,
    ecdsa::{prepare, preprocessing_size, prove, verify},
};
use utils::harness::ProvingSystem;

utils::define_benchmark_harness!(
    BenchTarget::Ecdsa,
    ProvingSystem::Plonky2,
    Some("secp256k1"),
    "ecdsa_mem_plonky2",
    PLONKY2_BENCH_PROPERTIES,
    |_| None,
    prepare,
    |prepared| prepared.num_gates,
    prove,
    verify,
    preprocessing_size,
    compute_proof_size
);

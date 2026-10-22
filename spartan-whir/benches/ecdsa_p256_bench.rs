use spartan_whir_bench::{
    SPARTAN_WHIR_BENCH_PROPERTIES, Target, num_constraints, prepare, preprocessing_size,
    proof_size, prove, verify,
};
use utils::harness::ProvingSystem;

utils::define_benchmark_harness!(
    BenchTarget::Ecdsa,
    ProvingSystem::SpartanWhir,
    Some("secp256r1"),
    "ecdsa_p256_mem_spartan_whir",
    SPARTAN_WHIR_BENCH_PROPERTIES,
    |_| None,
    |size| prepare(Target::EcdsaP256, size),
    num_constraints,
    prove,
    verify,
    preprocessing_size,
    proof_size
);

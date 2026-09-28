use gkr_engine::MPIConfig;
use sha256_expander_benchmark::EXPANDER_BENCH_PROPERTIES;
use sha256_expander_benchmark::poseidon::{get_constraints, prepare, prove, verify};
use utils::harness::ProvingSystem;

utils::define_benchmark_harness!(
    BenchTarget::Poseidon,
    ProvingSystem::Expander,
    None,
    "poseidon_mem_expander",
    EXPANDER_BENCH_PROPERTIES,
    |_| None,
    {
        let universe = MPIConfig::init().expect("Failed to initialize MPI");
        let world = universe.world();
        (universe, world)
    },
    |size, _| prepare(size),
    |(circuit_bytes, witness_bytes), (universe, world)| get_constraints(
        circuit_bytes,
        witness_bytes,
        MPIConfig::prover_new(Some(universe), Some(world))
    ),
    |(circuit_bytes, witness_bytes), (universe, world)| {
        prove(
            circuit_bytes,
            witness_bytes,
            MPIConfig::prover_new(Some(universe), Some(world)),
        )
    },
    |(circuit_bytes, witness_bytes), (claimed, proof), (universe, world)| {
        verify(
            circuit_bytes,
            witness_bytes,
            proof,
            claimed,
            MPIConfig::prover_new(Some(universe), Some(world)),
        );
    },
    |(circuit_bytes, _), _| { circuit_bytes.len() },
    |(_, proof), _shared| proof.bytes.len()
);

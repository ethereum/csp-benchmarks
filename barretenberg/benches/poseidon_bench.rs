use barretenberg_bench::{Session, Target, properties};
use utils::{bench::Acceleration, harness::ProvingSystem};

utils::define_benchmark_harness!(
    BenchTarget::Poseidon,
    ProvingSystem::Barretenberg,
    None,
    "poseidon_mem_barretenberg",
    properties(),
    |_| Some(Acceleration::Precompile),
    { Session::new().expect("initialize Barretenberg") },
    |size, session| session
        .prepare(Target::Poseidon, size)
        .expect("prepare circuit"),
    |prepared, _| prepared.num_gates,
    |prepared, session| session.prove(&prepared.prover).expect("prove circuit"),
    |prepared, proof, session| {
        assert!(
            session
                .verify(&prepared.prover, proof)
                .expect("verify circuit")
        );
    },
    |prepared, _| prepared.preprocessing_size,
    |proof, _| proof.proof.iter().map(Vec::len).sum()
);

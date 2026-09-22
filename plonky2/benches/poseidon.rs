use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use plonky2_circuits::PLONKY2_BENCH_PROPERTIES;
use plonky2_circuits::bench::{compute_proof_size, poseidon_prepare, prove, verify_proof};
use utils::harness::ProvingSystem;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;

utils::define_benchmark_harness!(
    BenchTarget::Poseidon,
    ProvingSystem::Plonky2,
    None,
    "poseidon_mem_plonky2",
    PLONKY2_BENCH_PROPERTIES,
    |_| Some(utils::bench::Acceleration::Precompile),
    poseidon_prepare,
    |(_, _, n_gates, _)| *n_gates,
    |(circuit_data, pw, _, _)| { prove(circuit_data, pw.clone()) },
    verify_proof,
    |(circuit_data, _pw, _, _)| {
        let gate_serializer = DefaultGateSerializer;
        let common_data_size = circuit_data
            .common
            .to_bytes(&gate_serializer)
            .unwrap()
            .len();
        let generator_serializer = DefaultGeneratorSerializer::<C, D>::default();
        let prover_data_size = circuit_data
            .prover_only
            .to_bytes(&generator_serializer, &circuit_data.common)
            .unwrap()
            .len();
        prover_data_size + common_data_size
    },
    compute_proof_size
);

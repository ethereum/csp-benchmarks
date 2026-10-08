use provekit::{PROVEKIT_PROPS, prepare_poseidon2, preprocessing_size, prove, verify};
use utils::harness::ProvingSystem;

utils::define_benchmark_harness!(
    BenchTarget::Poseidon2,
    ProvingSystem::Provekit,
    None,
    "poseidon2_mem_provekit",
    PROVEKIT_PROPS,
    |input_size| (input_size == 4).then_some(utils::bench::Acceleration::Precompile),
    prepare_poseidon2,
    |(proof_scheme, _, _)| { proof_scheme.r1cs.num_constraints() },
    |(proof_scheme, toml_path, _)| { prove(proof_scheme, toml_path) },
    |(proof_scheme, _, _), proof| {
        verify(proof, proof_scheme).unwrap();
    },
    |(proof_scheme, _, _)| { preprocessing_size(proof_scheme) },
    |proof| { proof.whir_r1cs_proof.narg_string.len() + proof.whir_r1cs_proof.hints.len() }
);

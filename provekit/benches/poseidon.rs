use provekit::{PROVEKIT_PROPS, prepare_poseidon, preprocessing_size, prove, verify};
use utils::harness::ProvingSystem;

utils::define_benchmark_harness!(
    BenchTarget::Poseidon,
    ProvingSystem::Provekit,
    None,
    "poseidon_mem_provekit",
    PROVEKIT_PROPS,
    |_| None,
    prepare_poseidon,
    |(proof_scheme, _, _)| { proof_scheme.r1cs.num_constraints() },
    |(proof_scheme, toml_path, _)| { prove(proof_scheme, toml_path) },
    |(proof_scheme, _, _), proof| {
        verify(proof, proof_scheme).unwrap();
    },
    |(proof_scheme, _, _)| { preprocessing_size(proof_scheme) },
    |proof| { proof.whir_r1cs_proof.narg_string.len() + proof.whir_r1cs_proof.hints.len() }
);

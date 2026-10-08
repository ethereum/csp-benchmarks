use provekit::{PROVEKIT_PROPS, prepare_ecdsa, preprocessing_size, prove, verify};
use utils::harness::ProvingSystem;

utils::define_benchmark_harness!(
    BenchTarget::Ecdsa,
    ProvingSystem::Provekit,
    Some("secp256r1"),
    "ecdsa_mem_provekit",
    PROVEKIT_PROPS,
    |_| None,
    prepare_ecdsa,
    |(proof_scheme, _, _)| { proof_scheme.r1cs.num_constraints() },
    |(proof_scheme, toml_path, _)| { prove(proof_scheme, toml_path) },
    |(proof_scheme, _, _), proof| {
        verify(proof, proof_scheme).unwrap();
    },
    |(proof_scheme, _, _)| { preprocessing_size(proof_scheme) },
    |proof| { proof.whir_r1cs_proof.narg_string.len() + proof.whir_r1cs_proof.hints.len() }
);

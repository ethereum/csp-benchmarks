use plonky2_gpu_circuits::{
    Prepared, keccak_prepare, poseidon_prepare, preprocessing_size, prove, sha256_prepare,
    verify_proof,
};

#[test]
fn gpu_label_rejects_disabled_gpu() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_poseidon_mem_plonky2_gpu"))
        .args(["--input-size", "2"])
        .env("PLONKY2_GPU_ENABLED", "false")
        .output()
        .expect("run memory binary with GPU disabled");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("GPU benchmark cannot run with the GPU disabled")
    );
}

// This exercises the new adapter, its preprocessing accounting and digest
// checks. Upstream circuit/executor correctness tests live in those projects.
#[test]
#[ignore = "requires a hardware GPU; run explicitly with --include-ignored"]
fn hash_adapters_install_persisted_executors_and_verify() {
    for (prepare, size) in [
        (sha256_prepare as fn(usize) -> Prepared, 128),
        (keccak_prepare, 128),
        (poseidon_prepare, 2),
    ] {
        let prepared = prepare(size);
        assert!(prepared.0.has_witness_program());
        let encoded = prepared.0.witness_program().unwrap().to_bytes();
        assert!(preprocessing_size(&prepared) > encoded.len());
        let mut config = plonky2::plonk::witness_program::WitnessConfig::from_env().unwrap();
        config.fallback = plonky2::plonk::witness_program::WitnessFallback::Error;
        let loaded = prepared
            .0
            .witness_program_from_bytes_with_config(&encoded, config)
            .unwrap();
        prepared.0.install_witness_program(loaded).unwrap();
        let proof = prove(&prepared.0, prepared.1.clone());
        verify_proof(&prepared, &proof);
        // Same prepared circuit must also support subsequent proofs, including
        // fresh zero-knowledge randomness, without rebuilding its executor.
        let proof = prove(&prepared.0, prepared.1.clone());
        verify_proof(&prepared, &proof);
    }
}

use barretenberg_bench::{Session, Target};

fn byte_fields(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes
        .iter()
        .map(|&byte| {
            let mut field = vec![0; 32];
            field[31] = byte;
            field
        })
        .collect()
}

/// Checks generated circuits, benchmark inputs, and public outputs through the adapter.
/// Requires the pinned Nargo and BB executables plus their CRS cache.
#[test]
#[ignore = "requires Nargo and Barretenberg"]
fn generated_workloads_prove_with_expected_public_values() {
    let session = Session::new().unwrap();
    let mut workload_count = 0;
    for target in Target::ALL {
        for size in target.input_sizes() {
            eprintln!("Checking {}_{size}", target.name());
            let prepared = session.prepare(target, size).unwrap();
            let proof = session.prove(&prepared.prover).unwrap();
            assert!(prepared.num_gates > 0);
            assert!(prepared.preprocessing_size > 0);
            assert!(session.verify(&prepared.prover, &proof).unwrap());
            let expected = match target {
                Target::Sha256 => Some(byte_fields(&utils::generate_sha256_input(size).1)),
                Target::Blake3 => Some(byte_fields(&utils::generate_blake3_input(size).1)),
                Target::Keccak => Some(byte_fields(&utils::generate_keccak_input(size).1)),
                Target::Ecdsa => Some(byte_fields(&[1])),
                Target::Poseidon | Target::Poseidon2 => None,
            };
            if let Some(expected) = expected {
                assert_eq!(proof.public_inputs, expected);
            } else {
                assert_eq!(proof.public_inputs.len(), 1);
            }
            workload_count += 1;
        }
    }
    eprintln!("Checked {workload_count} generated workloads and their public values");
}

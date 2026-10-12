use ere_jolt::{EreJolt, compiler::RustRv64imacCustomized};
use ere_zkvm_interface::{Input, ProverResource};
use jolt_inlines_blake3 as _;
use serde::Serialize;
use std::env;
use utils::harness::{AuditStatus, BenchProperties};
use utils::zkvm::{CompiledProgram, PreparedBlake3, PreparedEcdsa, PreparedKeccak, PreparedSha256};

// SAFETY: called once before single-threaded JoltSdk construction
fn set_jolt_config(max_trace_length: u64, stack_size: u64, heap_size: u64) {
    unsafe {
        env::set_var("JOLT_MAX_TRACE_LENGTH", max_trace_length.to_string());
        env::set_var("JOLT_STACK_SIZE", stack_size.to_string());
        env::set_var("JOLT_HEAP_SIZE", heap_size.to_string());
        env::set_var("JOLT_MAX_INPUT_SIZE", "4096");
        env::set_var("JOLT_MAX_OUTPUT_SIZE", "4096");
    }
}

pub use utils::zkvm::{
    execution_cycles, preprocessing_size, proof_size, prove, prove_blake3, prove_ecdsa,
    prove_sha256, verify_blake3, verify_ecdsa, verify_keccak, verify_sha256,
};

pub fn jolt_bench_properties() -> BenchProperties {
    BenchProperties::new(
        "Jolt",
        "Bn254",
        "Twist & Shout",
        Some("Dory"),
        "Jolt",
        true,
        true,
        100, // BN254 pairing security is about 100 bits after exTNFS estimates, see https://eips.ethereum.org/assets/eip-3068/2017-334.pdf and https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-12
        false,
        true,
        AuditStatus::NotAudited,
        Some("RISC-V RV64IMAC"),
    )
}

fn build_framed_input(data: Vec<u8>) -> Input {
    let len = data.len() as u32;
    let mut framed = Vec::with_capacity(4 + data.len());
    framed.extend_from_slice(&len.to_le_bytes());
    framed.extend(data);
    Input::new().with_stdin(framed)
}

pub fn prepare_sha256(
    input_size: usize,
    program: &CompiledProgram<RustRv64imacCustomized>,
) -> PreparedSha256<EreJolt> {
    let max_trace_length = if input_size > 1024 { 131072 } else { 65536 };
    set_jolt_config(max_trace_length, 4096, 32768);
    let vm = EreJolt::new(program.program.clone(), ProverResource::Cpu)
        .expect("jolt prover build failed");

    let (message_bytes, digest) = utils::generate_sha256_input(input_size);
    let input = build_framed_input(message_bytes);

    PreparedSha256::with_expected_digest(vm, input, program.byte_size, digest)
}

pub fn prepare_blake3(
    input_size: usize,
    program: &CompiledProgram<RustRv64imacCustomized>,
) -> PreparedBlake3<EreJolt> {
    let max_trace_length = 131072;
    set_jolt_config(max_trace_length, 4096, 32768);
    let vm = EreJolt::new(program.program.clone(), ProverResource::Cpu)
        .expect("jolt prover build failed");

    let (message_bytes, digest) = utils::generate_blake3_input(input_size);
    let input = build_framed_input(message_bytes);

    PreparedBlake3::with_expected_digest(vm, input, program.byte_size, digest)
}

pub fn prepare_keccak(
    input_size: usize,
    program: &CompiledProgram<RustRv64imacCustomized>,
) -> PreparedKeccak<EreJolt> {
    set_jolt_config(65536, 4096, 32768);
    let vm = EreJolt::new(program.program.clone(), ProverResource::Cpu)
        .expect("jolt prover build failed");

    let (message_bytes, digest) = utils::generate_keccak_input(input_size);
    let input = build_framed_input(message_bytes);

    PreparedKeccak::with_expected_digest(vm, input, program.byte_size, digest)
}

pub fn prepare_ecdsa(
    _input_size: usize,
    program: &CompiledProgram<RustRv64imacCustomized>,
) -> PreparedEcdsa<EreJolt> {
    set_jolt_config(262144, 4096, 32768);
    let vm = EreJolt::new(program.program.clone(), ProverResource::Cpu)
        .expect("jolt prover build failed");

    let (digest, (pub_key_x, pub_key_y), signature) = utils::generate_ecdsa_k256_input();
    let input = build_ecdsa_jolt_input(&digest, &pub_key_x, &pub_key_y, &signature);

    PreparedEcdsa::new(vm, input, program.byte_size)
}

#[derive(Serialize)]
struct EcdsaInput {
    z: [u64; 4],
    r: [u64; 4],
    s: [u64; 4],
    q: [u64; 8],
}

fn bytes_be_to_u64_4(bytes: &[u8]) -> [u64; 4] {
    let mut result = [0u64; 4];

    for i in 0..4 {
        result[3 - i] = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }

    result
}

fn bytes_be_to_u64_8(x: &[u8], y: &[u8]) -> [u64; 8] {
    let mut result = [0u64; 8];

    for i in 0..4 {
        result[3 - i] = u64::from_be_bytes(x[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    for i in 0..4 {
        result[7 - i] = u64::from_be_bytes(y[i * 8..(i + 1) * 8].try_into().unwrap());
    }

    result
}

fn build_ecdsa_jolt_input(
    digest: &[u8],
    pub_key_x: &[u8],
    pub_key_y: &[u8],
    signature: &[u8],
) -> Input {
    let ecdsa_input = EcdsaInput {
        z: bytes_be_to_u64_4(digest),
        r: bytes_be_to_u64_4(&signature[..32]),
        s: bytes_be_to_u64_4(&signature[32..]),
        q: bytes_be_to_u64_8(pub_key_x, pub_key_y),
    };

    let serialized = postcard::to_allocvec(&ecdsa_input).expect("failed to serialize ECDSA input");
    build_framed_input(serialized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ere_zkvm_interface::zkVM;
    use utils::zkvm::helpers::load_or_compile_program;
    use utils::zkvm::{BLAKE3_BENCH, ECDSA_BENCH, KECCAK_BENCH, SHA256_BENCH};
    use utils::zkvm::{compile_guest_program, guest_dir};

    #[test]
    #[ignore = "compiles and executes the Jolt guest toolchain"]
    fn blake3_guest_matches_reference() {
        let program = load_or_compile_program(&RustRv64imacCustomized, BLAKE3_BENCH);

        for input_size in [128, 2048] {
            let prepared = prepare_blake3(input_size, &program);
            let (public_values, _) = prepared
                .vm()
                .execute(prepared.input())
                .expect("Jolt BLAKE3 guest execution must succeed");
            assert_eq!(
                public_values,
                prepared.expected_digest().expect("expected digest")
            );
        }

        let prepared = prepare_blake3(128, &program);
        let proof = prove_blake3(&prepared, &program);
        verify_blake3(&prepared, &proof, &(&program));
    }

    #[test]
    #[ignore = "proves the largest Jolt BLAKE3 benchmark input"]
    fn blake3_2048_proof_roundtrip() {
        let program = load_or_compile_program(&RustRv64imacCustomized, BLAKE3_BENCH);
        let prepared = prepare_blake3(2048, &program);
        let proof = prove_blake3(&prepared, &program);
        verify_blake3(&prepared, &proof, &(&program));
    }

    fn compile_fresh(benchmark: &str) -> CompiledProgram<RustRv64imacCustomized> {
        let original_dir = env::current_dir().unwrap();
        let program = compile_guest_program(&RustRv64imacCustomized, &guest_dir(benchmark));
        env::set_current_dir(original_dir).unwrap();
        program.expect("Jolt benchmark guest compilation must succeed")
    }

    #[test]
    #[ignore = "compiles and proves all Jolt benchmark guests"]
    fn benchmark_proof_roundtrips() {
        type PrepareHash =
            fn(usize, &CompiledProgram<RustRv64imacCustomized>) -> PreparedSha256<EreJolt>;
        for (benchmark, prepare) in [
            (SHA256_BENCH, prepare_sha256 as PrepareHash),
            (KECCAK_BENCH, prepare_keccak as PrepareHash),
            (BLAKE3_BENCH, prepare_blake3 as PrepareHash),
        ] {
            let program = compile_fresh(benchmark);
            let prepared = prepare(128, &program);
            let (output, _) = prepared.vm().execute(prepared.input()).unwrap();
            assert_eq!(output, prepared.expected_digest().unwrap());
            let proof = prepared.prove().unwrap();
            prepared.verify_with_digest(&proof).unwrap();

            let mut incorrect_digest = proof;
            incorrect_digest.public_values[0] ^= 1;
            assert!(prepared.verify_with_digest(&incorrect_digest).is_err());
        }

        let program = compile_fresh(ECDSA_BENCH);
        let prepared = prepare_ecdsa(32, &program);
        let (output, _) = prepared.vm().execute(prepared.input()).unwrap();
        assert_eq!(output, [1]);
        let proof = prove_ecdsa(&prepared, &program);
        verify_ecdsa(&prepared, &proof, &program);
    }
}

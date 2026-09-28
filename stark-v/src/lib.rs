//! Stark-V benchmark integration for csp-benchmarks.

use bincode::Options;
use ere_zkvm_interface::{zkVM, Compiler, Input, Proof, ProofKind};
use stark_v_sdk::{secure_pcs_config, StarkV, StarkVCompiler, StarkVProgram};
use std::fs;
use std::path::PathBuf;
use utils::harness::{AuditStatus, BenchProperties};

pub struct CompiledProgram {
    pub program: StarkVProgram,
    pub byte_size: usize,
}

pub struct PreparedBench {
    vm: StarkV,
    input: Input,
    compiled_size: usize,
    expected_digest: Vec<u8>,
}

pub struct ProofResult {
    pub public_values: Vec<u8>,
    pub proof: Proof,
}

pub fn stark_v_bench_properties() -> BenchProperties {
    BenchProperties::new(
        "Circle STARK",
        "M31",
        "Circle FRI", // https://eprint.iacr.org/2024/278.pdf
        Some("Circle-PCS"),
        "AIR",
        false,                   // Not ZK
        true,                    // zkVM
        94,   // Upstream secure_pcs_config() UDR/soundcalc batching cap for trace <= 2^20.
        true, // hash-based PCS
        true, // not actively maintained
        AuditStatus::NotAudited, // https://github.com/kkrt-labs/cairo-m/?tab=readme-ov-file#about
        Some("RISC-V RV32IM"),
    )
}

fn guest_dir(bench_name: &str) -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    PathBuf::from(manifest_dir).join("guest").join(bench_name)
}

fn compiled_path(bench_name: &str) -> PathBuf {
    guest_dir(bench_name)
        .join("target")
        .join(format!("{}.bin", bench_name))
}

pub fn load_or_compile(bench_name: &str) -> CompiledProgram {
    let path = compiled_path(bench_name);
    if path.exists() {
        return load_compiled(bench_name);
    }
    let compiler = StarkVCompiler::new();
    let program = compiler
        .compile(&guest_dir(bench_name))
        .expect("failed to compile guest program");
    let bytes = bincode::options()
        .serialize(&program)
        .expect("failed to serialize compiled program");
    fs::create_dir_all(path.parent().unwrap()).expect("failed to create directory");
    fs::write(&path, &bytes).expect("failed to write compiled program");
    CompiledProgram {
        program,
        byte_size: bytes.len(),
    }
}

pub fn load_compiled(bench_name: &str) -> CompiledProgram {
    let bytes = fs::read(compiled_path(bench_name))
        .expect("missing compiled guest; the harness should have compiled it already");
    let program: StarkVProgram = bincode::options()
        .deserialize(&bytes)
        .expect("failed to deserialize compiled program");
    CompiledProgram {
        program,
        byte_size: bytes.len(),
    }
}

pub fn prepare_sha256(input_size: usize, program: &CompiledProgram) -> PreparedBench {
    let vm = StarkV::new(program.program.clone(), secure_pcs_config());
    let (message_bytes, digest) = utils::generate_sha256_input(input_size);
    let input = build_prefixed_input(message_bytes);
    PreparedBench {
        vm,
        input,
        compiled_size: program.byte_size,
        expected_digest: digest,
    }
}

pub fn prepare_keccak(input_size: usize, program: &CompiledProgram) -> PreparedBench {
    let vm = StarkV::new(program.program.clone(), secure_pcs_config());
    let (message_bytes, digest) = utils::generate_keccak_input(input_size);
    let input = build_prefixed_input(message_bytes);
    PreparedBench {
        vm,
        input,
        compiled_size: program.byte_size,
        expected_digest: digest,
    }
}

pub fn prepare_blake3(input_size: usize, program: &CompiledProgram) -> PreparedBench {
    let vm = StarkV::new(program.program.clone(), secure_pcs_config());
    let (message_bytes, digest) = utils::generate_blake3_input(input_size);
    let input = build_prefixed_input(message_bytes);
    PreparedBench {
        vm,
        input,
        compiled_size: program.byte_size,
        expected_digest: digest,
    }
}

/// Build stark-v input with length-prefixed format.
///
/// The guest programs expect: [len: u32 LE][data: u8...]
fn build_prefixed_input(data: Vec<u8>) -> Input {
    Input::new().with_prefixed_stdin(data)
}

pub fn prove_bench(prepared: &PreparedBench, _: &CompiledProgram) -> ProofResult {
    let (public_values, proof, _) = prepared
        .vm
        .prove(&prepared.input, ProofKind::Compressed)
        .expect("prove failed");
    ProofResult {
        public_values,
        proof,
    }
}

pub fn verify_bench(prepared: &PreparedBench, proof: &ProofResult, _: &CompiledProgram) {
    let public_values = prepared.vm.verify(&proof.proof).expect("verify failed");
    assert_eq!(
        public_values, proof.public_values,
        "proof public values mismatch"
    );
    assert_eq!(
        public_values, prepared.expected_digest,
        "public values do not match expected digest"
    );
}

pub fn preprocessing_size(prepared: &PreparedBench, _: &CompiledProgram) -> usize {
    prepared.compiled_size
}

pub fn proof_size(proof: &ProofResult, _: &CompiledProgram) -> usize {
    match &proof.proof {
        Proof::Compressed(bytes) | Proof::Groth16(bytes) => bytes.len(),
    }
}

pub fn execution_cycles(prepared: &PreparedBench) -> u64 {
    let (_, report) = prepared
        .vm
        .execute(&prepared.input)
        .expect("execute failed");
    report.total_num_cycles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "compiles and executes the Stark-V guest toolchain"]
    fn blake3_guest_matches_reference() {
        let program = load_or_compile("blake3");

        for input_size in [128, 2048] {
            let prepared = prepare_blake3(input_size, &program);
            let (public_values, _) = prepared
                .vm
                .execute(&prepared.input)
                .expect("Stark-V BLAKE3 guest execution must succeed");
            assert_eq!(public_values, prepared.expected_digest);
        }

        let prepared = prepare_blake3(128, &program);
        let proof = prove_bench(&prepared, &program);
        verify_bench(&prepared, &proof, &program);
    }

    #[test]
    #[ignore = "proves the largest Stark-V BLAKE3 benchmark input"]
    fn blake3_2048_proof_roundtrip() {
        let program = load_or_compile("blake3");
        let prepared = prepare_blake3(2048, &program);
        let proof = prove_bench(&prepared, &program);
        verify_bench(&prepared, &proof, &program);
    }
}

use cairo_m_common::{InputValue, Program, PublicAddressRanges};
use cairo_m_compiler::{CompilerOptions, compile_cairo};
use cairo_m_prover::{
    Proof,
    adapter::{ProverInput, import_from_runner_output},
    prover::prove_cairo_m,
    prover_config::REGULAR_96_BITS,
    verifier::verify_cairo_m,
};
use cairo_m_runner::run_cairo_program;
use std::fs;
use stwo_prover::core::fields::{m31::M31, qm31::QM31};
use stwo_prover::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use utils::generate_sha256_input;

const INPUT_WORD_CAPACITY: usize = 528;
const ARGUMENT_SLOTS: u32 = 2;
const RETURN_SLOTS: u32 = 16;

pub struct PreparedBench {
    pub program: Program,
    entrypoint: &'static str,
    runner_inputs: Vec<InputValue>,
    public_ranges: PublicAddressRanges,
    public_program: Vec<QM31>,
    public_inputs: Vec<QM31>,
    public_digest: Vec<QM31>,
    initial_pc: u32,
    initial_fp: u32,
}

/// Compile the Cairo-M SHA256 program from source.
pub fn compile_program() -> Program {
    let source_path = "programs/sha256.cm".to_string();
    let source_text = fs::read_to_string(&source_path).expect("Failed to read sha256.cm");
    let options = CompilerOptions {
        verbose: false,
        optimization_level: Default::default(),
    };
    let output =
        compile_cairo(source_text, source_path, options).expect("Failed to compile sha256.cm");
    (*output.program).clone()
}

pub fn program_size(program: &Program) -> usize {
    bincode::serde::encode_to_vec(program, bincode::config::standard())
        .expect("failed to serialize Cairo-M program")
        .len()
}

/// Prepares a message for the Cairo-M SHA256 function by padding it and
/// converting it to u32 words.
fn prepare_sha256_input(msg: &[u8]) -> Vec<u32> {
    // Perform standard SHA-256 padding
    let mut padded_bytes = msg.to_vec();
    padded_bytes.push(0x80);

    // Pad to 56 bytes (448 bits) within the last chunk
    while padded_bytes.len() % 64 != 56 {
        padded_bytes.push(0x00);
    }

    // Append message length as 64-bit big-endian
    let bit_len = (msg.len() as u64) * 8;
    padded_bytes.extend_from_slice(&bit_len.to_be_bytes());

    // Convert bytes to u32 words (big-endian)
    padded_bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().expect("Chunk size mismatch")))
        .collect()
}

/// Prepare the input for the Cairo-M SHA256 program.
/// Takes a pre-compiled program and input size, returns inputs and the public statement.
pub fn prepare(input_size: usize, compiled_program: &Program) -> PreparedBench {
    let (input_bytes, digest) = generate_sha256_input(input_size);

    // Prepare the input with proper SHA-256 padding
    let mut padded_words = prepare_sha256_input(&input_bytes);
    let num_chunks = padded_words.len() / 16;
    assert!(
        padded_words.len() <= INPUT_WORD_CAPACITY,
        "input exceeds guest capacity"
    );
    padded_words.resize(INPUT_WORD_CAPACITY, 0);

    // Prepare the entry point and input params based on input_size
    let entrypoint = "sha256_hash";
    let input_values: Vec<InputValue> = padded_words
        .iter()
        .map(|&word| InputValue::Number(word as i64))
        .collect();
    let runner_inputs = vec![
        InputValue::List(input_values),
        InputValue::Number(num_chunks as i64),
    ];

    let public_program: Vec<QM31> = compiled_program
        .data
        .iter()
        .flat_map(|item| item.to_qm31_vec())
        .collect();
    let program_end = public_program.len() as u32;
    // The runner materializes the fixed input array before the argument and return slots.
    // Each u32 occupies two M31 cells. The digest tuple occupies sixteen return slots.
    let input_start = program_end + (INPUT_WORD_CAPACITY * 2) as u32;
    let output_start = input_start + ARGUMENT_SLOTS;
    let output_end = output_start + RETURN_SLOTS;
    let public_digest = digest
        .chunks_exact(4)
        .flat_map(|bytes| {
            let word = u32::from_be_bytes(bytes.try_into().expect("digest word"));
            [
                QM31::from(M31::from(word & 0xffff)),
                QM31::from(M31::from(word >> 16)),
            ]
        })
        .collect();

    PreparedBench {
        program: compiled_program.clone(),
        entrypoint,
        runner_inputs,
        public_ranges: PublicAddressRanges {
            program: 0..program_end,
            input: input_start..output_start,
            output: output_start..output_end,
        },
        public_program,
        public_inputs: vec![
            M31::from(program_end).into(),
            M31::from(num_chunks as u32).into(),
        ],
        public_digest,
        initial_pc: compiled_program.entrypoints[entrypoint].pc as u32,
        initial_fp: output_end + 2,
    }
}

pub fn prover_input(prepared: &PreparedBench) -> ProverInput {
    let runner_output = run_cairo_program(
        &prepared.program,
        prepared.entrypoint,
        &prepared.runner_inputs,
        Default::default(),
    )
    .expect("failed to run cairo program");

    let segment = runner_output
        .vm
        .segments
        .clone()
        .into_iter()
        .next()
        .unwrap();

    import_from_runner_output(segment, prepared.public_ranges.clone())
        .expect("Failed to import runner output for proof generation")
}

pub fn prove(prepared: &PreparedBench) -> Proof<Blake2sMerkleHasher> {
    let mut prover_input = prover_input(prepared);

    let pcs_config = REGULAR_96_BITS;

    prove_cairo_m::<Blake2sMerkleChannel>(&mut prover_input, Some(pcs_config))
        .expect("failed to generate proof")
}

pub fn verify(prepared: &PreparedBench, proof: &Proof<Blake2sMerkleHasher>) {
    let pcs_config = REGULAR_96_BITS;

    verify_cairo_m::<Blake2sMerkleChannel>(proof.clone(), Some(pcs_config))
        .expect("failed to verify proof");

    assert_eq!(
        proof.public_data.initial_registers.pc.0, prepared.initial_pc,
        "entrypoint mismatch"
    );
    assert_eq!(
        proof.public_data.initial_registers.fp.0, prepared.initial_fp,
        "initial frame mismatch"
    );
    check_public_entries(
        &proof.public_data.public_memory.program,
        0,
        &prepared.public_program,
    );
    check_public_entries(
        &proof.public_data.public_memory.input,
        prepared.public_ranges.input.start,
        &prepared.public_inputs,
    );
    check_public_entries(
        &proof.public_data.public_memory.output,
        prepared.public_ranges.output.start,
        &prepared.public_digest,
    );
}

fn check_public_entries(entries: &[Option<(M31, QM31, M31)>], start: u32, expected: &[QM31]) {
    assert_eq!(
        entries.len(),
        expected.len(),
        "public memory length mismatch"
    );
    for (offset, (entry, expected_value)) in entries.iter().zip(expected).enumerate() {
        let (address, value, _) = entry.expect("missing public memory entry");
        assert_eq!(
            address.0,
            start + offset as u32,
            "public memory address mismatch"
        );
        assert_eq!(value, *expected_value, "public memory value mismatch");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "compiles and proves the Cairo-M benchmark guest"]
    fn sha256_benchmark_statement_roundtrip() {
        let program = compile_program();
        for input_size in [128, 256] {
            let prepared = prepare(input_size, &program);
            let proof = prove(&prepared);
            verify(&prepared, &proof);

            let mut wrong_digest = prepare(input_size, &program);
            wrong_digest.public_digest[0].0.0.0 ^= 1;
            assert!(std::panic::catch_unwind(|| verify(&wrong_digest, &proof)).is_err());

            let mut wrong_program = prepare(input_size, &program);
            wrong_program.public_program[0].0.0.0 ^= 1;
            assert!(std::panic::catch_unwind(|| verify(&wrong_program, &proof)).is_err());
        }
    }
}

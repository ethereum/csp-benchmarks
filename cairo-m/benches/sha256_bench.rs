use cairo_m::{PreparedBench, compile_program, prepare, program_size, prove, prover_input, verify};
use cairo_m_common::Program;
use cairo_m_prover::public_data::PublicData;
use utils::harness::{AuditStatus, BenchProperties, ProvingSystem};

utils::define_benchmark_harness!(
    BenchTarget::Sha256,
    ProvingSystem::CairoM,
    None,
    "sha256_mem_cairo_m",
    BenchProperties::new(
        "Circle STARK", // https://github.com/kkrt-labs/cairo-m/?tab=readme-ov-file#welcome-to-cairo-m
        "M31", // https://github.com/kkrt-labs/cairo-m/?tab=readme-ov-file#welcome-to-cairo-m
        "Circle FRI", // https://eprint.iacr.org/2024/278.pdf
        Some("Circle-PCS"), // https://eprint.iacr.org/2024/278.pdf
        "AIR",
        false,
        true,                    // zkVM
        88, // Crites-Stewart re-estimate of REGULAR_96_BITS; see results/stark_fri_security_report.md
        true, // hash-based PCS
        false, // not actively maintained
        AuditStatus::NotAudited, // https://github.com/kkrt-labs/cairo-m/?tab=readme-ov-file#about
        Some("Cairo ISA"), // https://github.com/kkrt-labs/cairo-m/blob/main/docs/design.md
    ),
    |_| Some(utils::bench::Acceleration::Precompile),
    { compile_program() },
    |input_size, program: &Program| { prepare(input_size, program) },
    |_, _| 0,
    |prepared, _| { prove(prepared) },
    |prepared, proof, _| { verify(prepared, proof) },
    |prepared: &PreparedBench, _| { program_size(&prepared.program) },
    |proof, _| proof.stark_proof.size_estimate(),
    |prepared: &PreparedBench| {
        let prover_input = prover_input(prepared);
        PublicData::new(&prover_input).clock.0 as u64
    }
);

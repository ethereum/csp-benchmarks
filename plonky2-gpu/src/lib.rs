#![recursion_limit = "256"]

use plonky2::plonk::witness_program::{WitnessConfig, WitnessFallback};
use std::{borrow::Cow, sync::OnceLock};
use utils::harness::{AuditStatus, BenchProperties};

#[path = "../../plonky2/src/keccak256/mod.rs"]
pub mod keccak256;
#[path = "../../plonky2/src/sha256/mod.rs"]
pub mod sha256;
#[path = "../../plonky2/src/bench.rs"]
mod stock_bench;

pub use stock_bench::{Prepared, compute_proof_size, prove, verify_proof};

pub const FEATURE: &str = "gpu_executor";

// Same protocol/configuration as the stock adapter; the fork's implementation
// changes have not been audited. Upstream audits do not cover this code path.
pub const BENCH_PROPERTIES: BenchProperties = BenchProperties {
    proving_system: Cow::Borrowed("Plonky2 GPU"),
    field_curve: Cow::Borrowed("Goldilocks"),
    iop: Cow::Borrowed("FRI"),
    pcs: Some(Cow::Borrowed("FRI")),
    arithm: Cow::Borrowed("Plonkish"),
    is_zk: true,
    is_zkvm: false,
    security_bits: 97,
    is_pq: true,
    is_maintained: true,
    is_audited: AuditStatus::NotAudited,
    isa: None,
};

fn require_gpu() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let config = plonky2::gpu::GpuConfig::from_env().expect("invalid GPU configuration");
        assert!(
            config.enabled,
            "GPU benchmark cannot run with the GPU disabled"
        );
        assert!(
            !config.allow_software,
            "GPU benchmark requires a hardware adapter"
        );
        plonky2::gpu::configure(config).expect("configure GPU before circuit preparation");
        plonky2::gpu::context().expect("GPU benchmark requires an available hardware adapter");
    });
}

fn prepare(input_size: usize, build: fn(usize) -> Prepared) -> Prepared {
    require_gpu();
    let prepared = build(input_size);
    let mut config = WitnessConfig::from_env().expect("invalid executor configuration");
    config.fallback = WitnessFallback::Error;
    let inputs = prepared.1.target_values.keys().copied().collect::<Vec<_>>();
    let program = prepared
        .0
        .compile_witness_program_with_config(&inputs, config)
        .expect("all witness generators must support the compiled executor");
    prepared
        .0
        .install_witness_program(program)
        .expect("install compiled witness executor");
    prepared
}

pub fn sha256_prepare(input_size: usize) -> Prepared {
    prepare(input_size, stock_bench::sha256_prepare)
}

pub fn keccak_prepare(input_size: usize) -> Prepared {
    prepare(input_size, stock_bench::keccak256_prepare)
}

pub fn poseidon_prepare(input_size: usize) -> Prepared {
    prepare(input_size, stock_bench::poseidon_prepare)
}

pub fn preprocessing_size((data, _, _, _): &Prepared) -> usize {
    // ProverOnlyCircuitData serialization intentionally omits the executor.
    // A reusable prover persists both the circuit data and the compiled program.
    stock_bench::compute_u32_preprocessing_size(data)
        + data
            .witness_program()
            .expect("executor must be installed")
            .to_bytes()
            .len()
}

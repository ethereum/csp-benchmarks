use std::borrow::Cow;
use std::str::FromStr;

use crate::bench::{
    Acceleration, Metrics, compile_binary, run_measure_mem_script, write_json_metrics,
};
use crate::metadata::{selected_byte_inputs, selected_field_element_inputs};
use criterion::{BatchSize, Criterion};

const SAMPLE_SIZE: usize = 10;

#[derive(Clone, Copy, Debug)]
pub enum BenchTarget {
    Sha256,
    Blake3,
    Ecdsa,
    Keccak,
    Poseidon,
    Poseidon2,
}

impl BenchTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            BenchTarget::Sha256 => "sha256",
            BenchTarget::Blake3 => "blake3",
            BenchTarget::Ecdsa => "ecdsa",
            BenchTarget::Keccak => "keccak",
            BenchTarget::Poseidon => "poseidon",
            BenchTarget::Poseidon2 => "poseidon2",
        }
    }
}

impl FromStr for BenchTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<BenchTarget, String> {
        match s {
            "sha256" => Ok(BenchTarget::Sha256),
            "blake3" => Ok(BenchTarget::Blake3),
            "ecdsa" => Ok(BenchTarget::Ecdsa),
            "keccak" => Ok(BenchTarget::Keccak),
            "poseidon" => Ok(BenchTarget::Poseidon),
            "poseidon2" => Ok(BenchTarget::Poseidon2),
            _ => Err(format!("Invalid benchmark target: {}", s)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ProvingSystem {
    Binius64,
    Expander,
    Plonky2,
    Provekit,
    ProvekitGroth16,
    Circom,
    Risc0,
    Jolt,
    Miden,
    CairoM,
    Vega,
    RookieNumbers,
    StarkV,
    Flock,
    Halo2,
    // Extend as needed
}

impl ProvingSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProvingSystem::Binius64 => "binius64",
            ProvingSystem::Expander => "expander",
            ProvingSystem::Plonky2 => "plonky2",
            ProvingSystem::Provekit => "provekit",
            ProvingSystem::ProvekitGroth16 => "provekit-groth16",
            ProvingSystem::Circom => "circom",
            ProvingSystem::Risc0 => "risc0",
            ProvingSystem::Jolt => "jolt",
            ProvingSystem::Miden => "miden",
            ProvingSystem::CairoM => "cairo-m",
            ProvingSystem::Vega => "vega",
            ProvingSystem::RookieNumbers => "rookie-numbers",
            ProvingSystem::StarkV => "stark-v",
            ProvingSystem::Flock => "flock",
            ProvingSystem::Halo2 => "halo2",
        }
    }
}

#[derive(Clone, Debug)]
pub struct BenchHarnessConfig<'a> {
    pub target: BenchTarget,
    pub system: ProvingSystem,
    pub feature: Option<&'a str>,
    pub mem_binary_name: &'a str,
}

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditStatus {
    #[serde(rename = "audited")]
    Audited,
    #[serde(rename = "not_audited")]
    NotAudited,
    #[serde(rename = "partially_audited")]
    PartiallyAudited,
}

impl FromStr for AuditStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<AuditStatus, String> {
        match s {
            "audited" => Ok(AuditStatus::Audited),
            "not_audited" => Ok(AuditStatus::NotAudited),
            "partially_audited" => Ok(AuditStatus::PartiallyAudited),
            _ => Err(format!("Invalid audit status: {}", s)),
        }
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BenchProperties {
    // Classification
    pub proving_system: Cow<'static, str>,
    pub field_curve: Cow<'static, str>,
    pub iop: Cow<'static, str>,
    pub pcs: Option<Cow<'static, str>>,
    pub arithm: Cow<'static, str>,
    /// Whether the exact proof mode benchmarked in this repository is implemented
    /// as zero-knowledge across the complete proving and verification flow.
    ///
    /// Public documentation or source must cover the exact benchmarked path and
    /// show that its required blinding or masking is enabled throughout that flow.
    /// A formal security argument strengthens that evidence but is not required.
    /// Modes with known leakage or an applicable unresolved upstream privacy caveat
    /// are `false`.
    pub is_zk: bool,
    /// True if the proving system is a zkVM (executes guest programs rather than fixed circuits); defaults to false when omitted.
    #[serde(default)]
    pub is_zkvm: bool,

    // Security
    pub security_bits: u64,
    pub is_pq: bool,

    // Maintenance / audit / zk
    pub is_maintained: bool,
    pub is_audited: AuditStatus,

    // zkVM specifics
    pub isa: Option<Cow<'static, str>>,
}

impl BenchProperties {
    #[allow(clippy::too_many_arguments)]
    /// Create a new BenchProperties struct.
    /// # Arguments
    /// * `proving_system` - The proving system name.
    /// * `field_curve` - The finite field or curve used by the system.
    /// * `iop` - The IOP used by the system.
    /// * `pcs` - The PCS used by the system (if applicable).
    /// * `arithm` - The arithmetization used by the system.
    /// * `is_zk` - Whether the exact proof mode benchmarked here is implemented
    ///   as zero-knowledge across the complete proving and verification flow
    ///   under the repository's `is_zk` policy.
    /// * `is_zkvm` - Whether the system executes guest programs as a zkVM (set to false for circuit-only proof systems).
    /// * `security_bits` - The security (soundness) parameter of the system.
    /// * `is_pq` - Whether the system is post-quantum-sound.
    /// * `is_maintained` - Whether the system codebase is maintained.
    /// * `is_audited` - The audit status of the system.
    /// * `isa` - The instruction set architecture of the system (for zkVMs).
    pub fn new(
        proving_system: &'static str,
        field_curve: &'static str,
        iop: &'static str,
        pcs: Option<&'static str>,
        arithm: &'static str,
        is_zk: bool,
        is_zkvm: bool,
        security_bits: u64,
        is_pq: bool,
        is_maintained: bool,
        is_audited: AuditStatus,
        isa: Option<&'static str>,
    ) -> Self {
        // Serde deserialization default implementation does not allow static strings, so we need to convert them to Cow::Borrowed.
        Self {
            proving_system: Cow::Borrowed(proving_system),
            field_curve: Cow::Borrowed(field_curve),
            iop: Cow::Borrowed(iop),
            pcs: pcs.map(Cow::Borrowed),
            arithm: Cow::Borrowed(arithm),
            is_zk,
            is_zkvm,
            security_bits,
            is_pq,
            is_maintained,
            is_audited,
            isa: isa.map(Cow::Borrowed),
        }
    }
}

impl Default for BenchProperties {
    fn default() -> Self {
        Self {
            proving_system: Cow::Borrowed(""),
            field_curve: Cow::Borrowed(""),
            iop: Cow::Borrowed(""),
            pcs: None,
            arithm: Cow::Borrowed(""),
            is_zk: false,
            is_zkvm: false,
            security_bits: 0,
            is_pq: false,
            is_maintained: false,
            is_audited: AuditStatus::NotAudited,
            isa: None,
        }
    }
}

fn feat_suffix(feat: Option<&str>) -> String {
    match feat {
        Some(f) if !f.is_empty() => format!("_{}", f),
        _ => String::new(),
    }
}

fn group_id(target: &str, size: usize, system: &str, feat: Option<&str>) -> String {
    format!("{}_{}_{}{}", target, size, system, feat_suffix(feat))
}

fn bench_id(target: &str, size: usize, system: &str, feat: Option<&str>, which: &str) -> String {
    format!(
        "{}_{}_{}{}_{}",
        target,
        size,
        system,
        feat_suffix(feat),
        which
    )
}

fn mem_report_filename(target: &str, size: usize, system: &str, feat: Option<&str>) -> String {
    match feat {
        Some(f) if !f.is_empty() => format!("{}_{}_{}_{}_mem_report.json", target, size, system, f),
        _ => format!("{}_{}_{}_mem_report.json", target, size, system),
    }
}

fn input_sizes_for(target: BenchTarget) -> Vec<usize> {
    match target {
        BenchTarget::Sha256 | BenchTarget::Keccak | BenchTarget::Blake3 => selected_byte_inputs(),
        BenchTarget::Ecdsa => vec![32],
        BenchTarget::Poseidon | BenchTarget::Poseidon2 => selected_field_element_inputs(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_benchmarks_fn<
    PreparedContext,
    Proof,
    PrepareFn,
    NumConstraintsFn,
    ProveFn,
    VerifyFn,
    PrepSizeFn,
    ProofSizeFn,
    AccelerationFn,
    ExecutionCyclesFn: Fn(&PreparedContext) -> u64,
>(
    c: &mut Criterion,
    cfg: BenchHarnessConfig<'_>,
    properties: BenchProperties,
    acceleration: AccelerationFn,
    mut prepare: PrepareFn,
    mut num_constraints: NumConstraintsFn,
    mut prove: ProveFn,
    mut verify: VerifyFn,
    mut preprocessing_size: PrepSizeFn,
    mut proof_size: ProofSizeFn,
    execution_cycles: Option<ExecutionCyclesFn>,
) where
    PrepareFn: FnMut(usize) -> PreparedContext + Copy,
    ProveFn: FnMut(&PreparedContext) -> Proof + Copy,
    NumConstraintsFn: FnMut(&PreparedContext) -> usize,
    VerifyFn: FnMut(&PreparedContext, &Proof),
    PrepSizeFn: FnMut(&PreparedContext) -> usize,
    ProofSizeFn: FnMut(&Proof) -> usize,
    AccelerationFn: Fn(usize) -> Option<Acceleration>,
{
    let target_str = cfg.target.as_str();
    let system_str = cfg.system.as_str();

    for size in input_sizes_for(cfg.target) {
        let prepared_context = prepare(size);

        let mut metrics = init_metrics(
            &cfg,
            target_str,
            system_str,
            size,
            &properties,
            acceleration(size),
        );
        metrics.preprocessing_size = preprocessing_size(&prepared_context);
        metrics.num_constraints = num_constraints(&prepared_context);
        let proof = prove(&prepared_context);
        metrics.proof_size = proof_size(&proof);

        if let Some(ref cycles_fn) = execution_cycles {
            let c = cycles_fn(&prepared_context);
            metrics.cycles = if c == 0 { None } else { Some(c) };
        }

        write_json_metrics(target_str, size, system_str, cfg.feature, &metrics);

        measure_ram(&cfg, target_str, system_str, cfg.mem_binary_name, size);

        let mut group = init_bench_group(c, &cfg, target_str, system_str, size);

        let prove_id = bench_id(target_str, size, system_str, cfg.feature, "prove");
        group.bench_function(prove_id, move |bench| {
            bench.iter_batched(
                || prepare(size),
                |prepared| {
                    let _ = (prove)(&prepared);
                },
                BatchSize::SmallInput,
            );
        });

        let verify_id = bench_id(target_str, size, system_str, cfg.feature, "verify");
        group.bench_function(verify_id, |bench| {
            bench.iter_batched(
                || {
                    let prepared = prepare(size);
                    let proof_local = (prove)(&prepared);
                    (prepared, proof_local)
                },
                |(prepared, proof_local)| {
                    (verify)(&prepared, &proof_local);
                },
                BatchSize::SmallInput,
            );
        });

        group.finish();
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_benchmarks_with_state_fn<
    SharedState: Copy,
    PreparedContext,
    Proof,
    PrepareFn,
    NumConstraintsFn,
    ProveFn,
    VerifyFn,
    PrepSizeFn,
    ProofSizeFn,
    AccelerationFn,
    ExecutionCyclesFn: Fn(&PreparedContext) -> u64,
>(
    c: &mut Criterion,
    cfg: BenchHarnessConfig<'_>,
    properties: BenchProperties,
    acceleration: AccelerationFn,
    shared: SharedState,
    mut prepare: PrepareFn,
    mut num_constraints: NumConstraintsFn,
    mut prove: ProveFn,
    mut verify: VerifyFn,
    mut preprocessing_size: PrepSizeFn,
    mut proof_size: ProofSizeFn,
    execution_cycles: Option<ExecutionCyclesFn>,
) where
    PrepareFn: FnMut(usize, SharedState) -> PreparedContext + Copy,
    NumConstraintsFn: FnMut(&PreparedContext, &SharedState) -> usize,
    ProveFn: FnMut(&PreparedContext, &SharedState) -> Proof + Copy,
    VerifyFn: FnMut(&PreparedContext, &Proof, &SharedState),
    PrepSizeFn: FnMut(&PreparedContext, &SharedState) -> usize,
    ProofSizeFn: FnMut(&Proof, &SharedState) -> usize,
    AccelerationFn: Fn(usize) -> Option<Acceleration>,
{
    let target_str = cfg.target.as_str();
    let system_str = cfg.system.as_str();

    for size in input_sizes_for(cfg.target) {
        let prepared_context = prepare(size, shared);

        let mut metrics = init_metrics(
            &cfg,
            target_str,
            system_str,
            size,
            &properties,
            acceleration(size),
        );
        metrics.preprocessing_size = preprocessing_size(&prepared_context, &shared);
        metrics.num_constraints = num_constraints(&prepared_context, &shared);
        let proof = prove(&prepared_context, &shared);
        metrics.proof_size = proof_size(&proof, &shared);

        if let Some(ref cycles_fn) = execution_cycles {
            let c = cycles_fn(&prepared_context);
            metrics.cycles = if c == 0 { None } else { Some(c) };
        }

        write_json_metrics(target_str, size, system_str, cfg.feature, &metrics);

        measure_ram(&cfg, target_str, system_str, cfg.mem_binary_name, size);

        let mut group = init_bench_group(c, &cfg, target_str, system_str, size);

        let prove_id = bench_id(target_str, size, system_str, cfg.feature, "prove");
        group.bench_function(prove_id, move |bench| {
            bench.iter_batched(
                move || prepare(size, shared),
                move |prepared| {
                    let _ = (prove)(&prepared, &shared);
                },
                BatchSize::SmallInput,
            );
        });

        let verify_id = bench_id(target_str, size, system_str, cfg.feature, "verify");
        group.bench_function(verify_id, |bench| {
            bench.iter_batched(
                || {
                    let prepared = prepare(size, shared);
                    let proof_local = (prove)(&prepared, &shared);
                    (prepared, proof_local)
                },
                |(prepared, proof_local)| {
                    (verify)(&prepared, &proof_local, &shared);
                },
                BatchSize::SmallInput,
            );
        });

        group.finish();
    }
}

fn init_bench_group<'a>(
    c: &'a mut Criterion,
    cfg: &BenchHarnessConfig<'a>,
    target_str: &'static str,
    system_str: &'static str,
    size: usize,
) -> criterion::BenchmarkGroup<'a, criterion::measurement::WallTime> {
    let gid = group_id(target_str, size, system_str, cfg.feature);
    let mut group = c.benchmark_group(gid);
    group.sample_size(SAMPLE_SIZE);
    group
}

fn init_metrics(
    cfg: &BenchHarnessConfig<'_>,
    target_str: &'static str,
    system_str: &'static str,
    size: usize,
    properties: &BenchProperties,
    acceleration: Option<Acceleration>,
) -> Metrics {
    let mut metrics = Metrics::new(
        system_str.to_string(),
        match cfg.feature {
            Some(f) if !f.is_empty() => Some(f.to_string()),
            _ => None,
        },
        target_str.to_string(),
        size,
        properties.clone(),
    );
    metrics.acceleration = acceleration;
    metrics
}

fn measure_ram(
    cfg: &BenchHarnessConfig<'_>,
    target_str: &'static str,
    system_str: &'static str,
    mem_bin_name_ref: &str,
    size: usize,
) {
    compile_binary(mem_bin_name_ref);
    let bin_path = format!("../target/release/{}", mem_bin_name_ref);
    let mem_json = mem_report_filename(target_str, size, system_str, cfg.feature);
    run_measure_mem_script(&mem_json, &bin_path, size);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_metrics_uses_input_size_dependent_acceleration() {
        let cfg = BenchHarnessConfig {
            target: BenchTarget::Poseidon2,
            system: ProvingSystem::Provekit,
            feature: None,
            mem_binary_name: "unused",
        };
        let properties = BenchProperties::default();
        let acceleration = |input_size| (input_size == 4).then_some(Acceleration::Precompile);

        let metrics_for_2 = init_metrics(
            &cfg,
            "poseidon2",
            "provekit",
            2,
            &properties,
            acceleration(2),
        );
        let metrics_for_4 = init_metrics(
            &cfg,
            "poseidon2",
            "provekit",
            4,
            &properties,
            acceleration(4),
        );

        assert_eq!(metrics_for_2.acceleration, None);
        assert_eq!(metrics_for_4.acceleration, Some(Acceleration::Precompile));
    }
}

#[macro_export]
macro_rules! __define_benchmark_harness {
    // With shared state
    ($public_group_ident:ident, $target:expr, $system:expr, $feature:expr, $mem_binary_name:expr, $properties:expr, $acceleration:expr, { $($shared_init:tt)* },
        $prepare:expr, $num_constraints:expr, $prove:expr, $verify:expr, $prep_size:expr, $proof_size:expr
    ) => {
        fn criterion_benchmarks(c: &mut ::criterion::Criterion) {
            let system = $system;
            let cfg = ::utils::harness::BenchHarnessConfig {
                target: $target,
                system,
                feature: $feature,
                mem_binary_name: $mem_binary_name,
            };
            ::utils::harness::run_benchmarks_with_state_fn(
                c,
                cfg,
                $properties,
                $acceleration,
                &{ $($shared_init)* },
                $prepare,
                $num_constraints,
                $prove,
                $verify,
                $prep_size,
                $proof_size,
                None::<fn(&_) -> u64>,
            );
        }
        ::criterion::criterion_group!($public_group_ident, criterion_benchmarks);
        ::criterion::criterion_main!($public_group_ident);
    };
    // No shared state, with execution_cycles
    ($public_group_ident:ident, $target:expr, $system:expr, $feature:expr, $mem_binary_name:expr, $properties:expr, $acceleration:expr,
        $prepare:expr, $num_constraints:expr, $prove:expr, $verify:expr, $prep_size:expr, $proof_size:expr, $execution_cycles:expr
    ) => {
        fn criterion_benchmarks(c: &mut ::criterion::Criterion) {
            let system = $system;
            let cfg = ::utils::harness::BenchHarnessConfig {
                target: $target,
                system,
                feature: $feature,
                mem_binary_name: $mem_binary_name,
            };
            ::utils::harness::run_benchmarks_fn(
                c,
                cfg,
                $properties,
                $acceleration,
                $prepare,
                $num_constraints,
                $prove,
                $verify,
                $prep_size,
                $proof_size,
                Some($execution_cycles),
            );
        }
        ::criterion::criterion_group!($public_group_ident, criterion_benchmarks);
        ::criterion::criterion_main!($public_group_ident);
    };
    // With shared state and execution_cycles
    ($public_group_ident:ident, $target:expr, $system:expr, $feature:expr, $mem_binary_name:expr, $properties:expr, $acceleration:expr, { $($shared_init:tt)* },
        $prepare:expr, $num_constraints:expr, $prove:expr, $verify:expr, $prep_size:expr, $proof_size:expr, $execution_cycles:expr
    ) => {
        fn criterion_benchmarks(c: &mut ::criterion::Criterion) {
            let system = $system;
            let cfg = ::utils::harness::BenchHarnessConfig {
                target: $target,
                system,
                feature: $feature,
                mem_binary_name: $mem_binary_name,
            };
            ::utils::harness::run_benchmarks_with_state_fn(
                c,
                cfg,
                $properties,
                $acceleration,
                &{ $($shared_init)* },
                $prepare,
                $num_constraints,
                $prove,
                $verify,
                $prep_size,
                $proof_size,
                Some($execution_cycles),
            );
        }
        ::criterion::criterion_group!($public_group_ident, criterion_benchmarks);
        ::criterion::criterion_main!($public_group_ident);
    };
    // No shared state, no execution_cycles
    ($public_group_ident:ident, $target:expr, $system:expr, $feature:expr, $mem_binary_name:expr, $properties:expr, $acceleration:expr,
        $prepare:expr, $num_constraints:expr, $prove:expr, $verify:expr, $prep_size:expr, $proof_size:expr
    ) => {
        fn criterion_benchmarks(c: &mut ::criterion::Criterion) {
            let system = $system;
            let cfg = ::utils::harness::BenchHarnessConfig {
                target: $target,
                system,
                feature: $feature,
                mem_binary_name: $mem_binary_name,
            };
            ::utils::harness::run_benchmarks_fn(
                c,
                cfg,
                $properties,
                $acceleration,
                $prepare,
                $num_constraints,
                $prove,
                $verify,
                $prep_size,
                $proof_size,
                None::<fn(&_) -> u64>,
            );
        }
        ::criterion::criterion_group!($public_group_ident, criterion_benchmarks);
        ::criterion::criterion_main!($public_group_ident);
    };
}

#[macro_export]
macro_rules! define_benchmark_harness {
    (BenchTarget::Sha256, $($rest:tt)*) => {
        $crate::__define_benchmark_harness!(sha256, $crate::harness::BenchTarget::Sha256, $($rest)*);
    };
    (BenchTarget::Blake3, $($rest:tt)*) => {
        $crate::__define_benchmark_harness!(blake3, $crate::harness::BenchTarget::Blake3, $($rest)*);
    };
    (BenchTarget::Ecdsa, $($rest:tt)*) => {
        $crate::__define_benchmark_harness!(ecdsa, $crate::harness::BenchTarget::Ecdsa, $($rest)*);
    };
    (BenchTarget::Keccak, $($rest:tt)*) => {
        $crate::__define_benchmark_harness!(keccak, $crate::harness::BenchTarget::Keccak, $($rest)*);
    };
    (BenchTarget::Poseidon, $($rest:tt)*) => {
        $crate::__define_benchmark_harness!(poseidon, $crate::harness::BenchTarget::Poseidon, $($rest)*);
    };
    (BenchTarget::Poseidon2, $($rest:tt)*) => {
        $crate::__define_benchmark_harness!(poseidon2, $crate::harness::BenchTarget::Poseidon2, $($rest)*);
    };
}

use crate::harness::BenchProperties;
use human_repr::{HumanCount, HumanDuration};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use serde_with::{DurationNanoSeconds, serde_as};
use std::{
    fmt::Display,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tabled::{Table, Tabled, settings::Style};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Acceleration {
    Precompile,
    Inline,
}

impl Display for Acceleration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Precompile => f.write_str("precompile"),
            Self::Inline => f.write_str("inline"),
        }
    }
}

fn get_current_memory_usage() -> Result<usize, std::io::Error> {
    unsafe {
        let mut self_usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut self_usage);

        let mut child_usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_CHILDREN, &mut child_usage);

        let total_maxrss = self_usage.ru_maxrss + child_usage.ru_maxrss;

        #[cfg(target_os = "linux")]
        {
            Ok(total_maxrss as usize * 1024)
        }
        #[cfg(target_os = "macos")]
        {
            Ok(total_maxrss as usize)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            compile_error!("This crate only supports Linux and macOS for memory measurement");
        }
    }
}

pub fn measure_peak_memory<R, F: FnOnce() -> R>(func: F) -> (R, usize) {
    let peak = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    let peak_clone = Arc::clone(&peak);
    let stop_clone = Arc::clone(&stop);
    let monitor = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            if let Ok(mem) = get_current_memory_usage() {
                peak_clone.fetch_max(mem, Ordering::Relaxed);
            }
            thread::sleep(Duration::from_millis(10));
        }
    });

    let result = func();

    stop.store(true, Ordering::Relaxed);
    monitor.join().unwrap();

    (result, peak.load(Ordering::Relaxed))
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Tabled, Clone)]
pub struct Metrics {
    pub name: String,
    #[tabled(display_with = "display_string")]
    pub feat: Option<String>,
    pub target: String,
    #[tabled(display_with = "display_bytes")]
    pub input_size: usize,
    #[serde_as(as = "DurationNanoSeconds")]
    #[tabled(display_with = "display_duration")]
    pub proof_duration: Duration,
    #[serde_as(as = "DurationNanoSeconds")]
    #[tabled(display_with = "display_duration")]
    pub verify_duration: Duration,
    #[tabled(display_with = "display_cycles")]
    pub cycles: Option<u64>,
    #[tabled(display_with = "display_bytes")]
    pub proof_size: usize,
    #[tabled(display_with = "display_bytes")]
    pub preprocessing_size: usize,
    pub num_constraints: usize,
    #[tabled(display_with = "display_bytes")]
    pub peak_memory: usize,
    #[tabled(display_with = "display_acceleration")]
    pub acceleration: Option<Acceleration>,
    #[serde(flatten)]
    #[tabled(skip)]
    pub bench_properties: BenchProperties,
}

fn display_bytes(bytes: &usize) -> String {
    bytes.human_count_bytes().to_string()
}

fn display_duration(duration: &Duration) -> String {
    duration.human_duration().to_string()
}

fn display_string(s: &Option<String>) -> String {
    match s {
        Some(v) if !v.is_empty() => v.clone(),
        _ => "-".to_string(),
    }
}

fn display_cycles(cycles: &Option<u64>) -> String {
    match cycles {
        Some(v) => v.human_count_bare().to_string(),
        None => "-".to_string(),
    }
}

fn display_acceleration(acceleration: &Option<Acceleration>) -> String {
    acceleration
        .map(|acceleration| acceleration.to_string())
        .unwrap_or_else(|| "-".to_string())
}

impl Metrics {
    pub fn new(
        name: String,
        feat: Option<String>,
        target: String,
        size: usize,
        bench_properties: BenchProperties,
    ) -> Self {
        Metrics {
            name,
            feat,
            target,
            input_size: size,
            proof_duration: Duration::default(),
            verify_duration: Duration::default(),
            cycles: None,
            proof_size: 0,
            preprocessing_size: 0,
            num_constraints: 0,
            peak_memory: 0,
            acceleration: None,
            bench_properties,
        }
    }
}

pub fn benchmark<T: Display + Clone, F>(func: F, inputs: &[T], file: &str)
where
    F: Fn(T) -> Metrics,
{
    let mut results = Vec::new();
    for input in inputs {
        let (mut metrics, peak_memory) = measure_peak_memory(|| func(input.clone()));
        metrics.peak_memory = peak_memory;
        results.push(metrics);
    }

    write_csv(file, &results);
}

pub fn write_csv(out_path: &str, results: &[Metrics]) {
    let mut out = csv::WriterBuilder::new().from_path(out_path).unwrap();

    let mut all_metrics = Vec::new();

    for metric in results {
        out.serialize(metric).expect("Could not serialize");
        out.flush().expect("Could not flush");
        all_metrics.push(metric);
    }

    out.flush().expect("Could not flush");

    let mut table = Table::new(&all_metrics);
    table.with(Style::modern());
    println!("{table}");
}

pub fn metrics_filename(target: &str, size: usize, system: &str, feat: Option<&str>) -> String {
    match feat {
        Some(f) if !f.is_empty() => format!("{}_{}_{}_{}_metrics.json", target, size, system, f),
        _ => format!("{}_{}_{}_metrics.json", target, size, system),
    }
}

pub fn write_json_metrics(
    target_str: &'static str,
    size: usize,
    system_str: &'static str,
    feature: Option<&str>,
    metrics: &Metrics,
) {
    let metrics_file = metrics_filename(target_str, size, system_str, feature);

    write_json_metrics_file(&metrics_file, metrics);
}

pub fn write_json_metrics_file(output_path: &str, metrics: &Metrics) {
    let json = serde_json::to_string_pretty(metrics).unwrap();
    std::fs::write(output_path, json).unwrap();
}

pub fn compile_binary(binary_name: &str) -> std::path::PathBuf {
    let compile_output = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("--bin")
        .arg(binary_name)
        .output()
        .expect("failed to compile");

    assert!(
        compile_output.status.success(),
        "failed to compile memory binary '{}'\nstdout:\n{}\nstderr:\n{}",
        binary_name,
        String::from_utf8_lossy(&compile_output.stdout),
        String::from_utf8_lossy(&compile_output.stderr)
    );

    // Excluded workspaces and CARGO_TARGET_DIR can place binaries elsewhere.
    // Ask Cargo for the effective path rather than assuming ../target.
    let metadata = Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .output()
        .expect("failed to locate compiled memory binary");
    assert!(
        metadata.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&metadata.stdout).expect("invalid cargo metadata");
    std::path::PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .expect("cargo metadata must include target_directory"),
    )
    .join("release")
    .join(format!("{binary_name}{}", std::env::consts::EXE_SUFFIX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_without_acceleration_deserialize_as_none() {
        let json = r#"{
            "name": "example",
            "target": "sha256",
            "input_size": 128,
            "proof_duration": 0,
            "verify_duration": 0,
            "proof_size": 0,
            "preprocessing_size": 0,
            "num_constraints": 0,
            "peak_memory": 0,
            "proving_system": "Example",
            "field_curve": "ExampleField",
            "iop": "ExampleIOP",
            "arithm": "ExampleArithm",
            "is_zk": false,
            "is_zkvm": false,
            "security_bits": 96,
            "is_pq": true,
            "is_maintained": true,
            "is_audited": "not_audited"
        }"#;

        let metrics: Metrics = serde_json::from_str(json).unwrap();

        assert_eq!(metrics.acceleration, None);
    }

    #[test]
    fn acceleration_variants_serialize_as_json_enum_values() {
        assert_eq!(
            serde_json::to_string(&Acceleration::Precompile).unwrap(),
            r#""precompile""#
        );
        assert_eq!(Acceleration::Precompile.to_string(), "precompile");
        assert_eq!(
            serde_json::to_string(&Acceleration::Inline).unwrap(),
            r#""inline""#
        );
        assert_eq!(Acceleration::Inline.to_string(), "inline");
    }
}

pub fn run_measure_mem_script(json_file: &str, binary_path: &str, input_size: usize) {
    let script = "../measure_mem_avg.sh";

    let output = Command::new("bash")
        .arg(script)
        .arg("--json")
        .arg(json_file)
        .arg("--")
        .arg(binary_path)
        .arg("--input-size")
        .arg(input_size.to_string())
        .output()
        .expect("failed to execute script");

    println!("{}", String::from_utf8_lossy(&output.stdout));

    if !output.stderr.is_empty() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }

    assert!(
        output.status.success(),
        "measure_mem_avg.sh failed with status {:?} for '{}' (input_size={})",
        output.status.code(),
        binary_path,
        input_size
    );
}

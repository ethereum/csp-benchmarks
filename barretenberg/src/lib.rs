use std::{
    cell::RefCell,
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    rc::Rc,
};

use anyhow::{Context, Result, bail, ensure};
use barretenberg_rs::{
    BarretenbergApi,
    backends::PipeBackend,
    generated_types::{CircuitInput, CircuitInputNoVK, CircuitProveResponse, ProofSystemSettings},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Parser;
use utils::harness::BenchProperties;

const BB_VERSION: &str = "5.2.1";
const NARGO_VERSION: &str = "1.0.0-beta.25";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Target {
    Sha256,
    Blake3,
    Keccak,
    Ecdsa,
    Poseidon,
    Poseidon2,
}

impl Target {
    pub const ALL: [Self; 6] = [
        Self::Sha256,
        Self::Blake3,
        Self::Keccak,
        Self::Ecdsa,
        Self::Poseidon,
        Self::Poseidon2,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Blake3 => "blake3",
            Self::Keccak => "keccak",
            Self::Ecdsa => "ecdsa",
            Self::Poseidon => "poseidon",
            Self::Poseidon2 => "poseidon2",
        }
    }

    pub fn input_sizes(self) -> Vec<usize> {
        match self {
            Self::Ecdsa => vec![32],
            Self::Poseidon | Self::Poseidon2 => utils::metadata::selected_field_element_inputs(),
            _ => utils::metadata::selected_byte_inputs()
                .into_iter()
                .filter(|&size| self != Self::Blake3 || size <= 1024)
                .collect(),
        }
    }

    fn source_directory(self) -> &'static str {
        match self {
            Self::Sha256 => "hash/sha256",
            Self::Blake3 => "hash/blake3",
            Self::Keccak => "hash/keccak256",
            Self::Ecdsa => "ecdsa",
            Self::Poseidon => "hash/poseidon",
            Self::Poseidon2 => "hash/poseidon2",
        }
    }

    fn source(self, size: usize) -> Result<String> {
        ensure!(size > 0, "input size must be positive");
        ensure!(
            self != Self::Blake3 || size <= 1024,
            "native BLAKE3 supports at most 1024 bytes"
        );
        ensure!(self != Self::Ecdsa || size == 32, "ECDSA input size is 32");
        let path = source_root()
            .join(self.source_directory())
            .join("src/main.nr");
        let source = fs::read_to_string(path)?;
        let replacements = match self {
            Self::Sha256 => vec![(
                "input: [u8; 2048]".to_string(),
                format!("input: [u8; {size}]"),
            )],
            Self::Blake3 => vec![(
                "input: [u8; 1024]".to_string(),
                format!("input: [u8; {size}]"),
            )],
            Self::Keccak => vec![
                (
                    "input: [u8; 2048]".to_string(),
                    format!("input: [u8; {size}]"),
                ),
                (
                    "keccak256::<2048>".to_string(),
                    format!("keccak256::<{size}>"),
                ),
            ],
            Self::Poseidon => vec![
                ("[Field; 2]".to_string(), format!("[Field; {size}]")),
                ("hash_2".to_string(), format!("hash_{size}")),
            ],
            Self::Poseidon2 => vec![
                ("[Field; 2]".to_string(), format!("[Field; {size}]")),
                (
                    "Poseidon2::hash(inputs, 2)".to_string(),
                    format!("Poseidon2::hash(inputs, {size})"),
                ),
            ],
            Self::Ecdsa => vec![],
        };
        let mut result = source;
        for (from, to) in replacements {
            ensure!(
                result.contains(&from),
                "{} circuit template is missing {from:?}",
                self.name()
            );
            result = result.replace(&from, &to);
        }
        Ok(result)
    }

    fn inputs(self, size: usize) -> String {
        match self {
            Self::Sha256 => format!(
                "input = {:?}\ninput_len = {size}\n",
                utils::generate_sha256_input(size).0
            ),
            Self::Blake3 => format!("input = {:?}\n", utils::generate_blake3_input(size).0),
            Self::Keccak => format!(
                "input = {:?}\nmessage_size = {size}\n",
                utils::generate_keccak_input(size).0
            ),
            Self::Poseidon | Self::Poseidon2 => format!(
                "inputs = {:?}\n",
                utils::generate_poseidon_input_strings(size)
            ),
            Self::Ecdsa => {
                let (digest, (x, y), signature) = utils::generate_ecdsa_input();
                format!(
                    "public_key_x = {x:?}\npublic_key_y = {y:?}\nsignature = {signature:?}\nmessage_hash = {digest:?}\n"
                )
            }
        }
    }
}

pub fn properties() -> BenchProperties {
    serde_json::from_str(include_str!("../bench_props.json"))
        .expect("Barretenberg benchmark metadata")
}

fn source_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("circuits")
}

fn project_path(target: Target, size: usize) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/noir")
        .join(format!("{}_{size}", target.name()))
}

fn settings() -> ProofSystemSettings {
    // Zero-knowledge UltraHonk with the Poseidon2 transcript.
    ProofSystemSettings {
        ipa_accumulation: false,
        oracle_hash_type: "poseidon2".into(),
        disable_zk: false,
        optimized_solidity_verifier: false,
    }
}

fn decompress(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decompressed = Vec::new();
    flate2::read::GzDecoder::new(bytes).read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

fn run(command: &mut Command) -> Result<Vec<u8>> {
    let output = command
        .output()
        .with_context(|| format!("run {command:?}"))?;
    ensure!(
        output.status.success(),
        "{command:?} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

fn nargo() -> Command {
    Command::new(std::env::var_os("NARGO_BIN").unwrap_or_else(|| "nargo".into()))
}

fn load_bytecode(project: &Path, target: Target) -> Result<(Vec<u8>, usize)> {
    let artifact = fs::read(
        project
            .join("target")
            .join(format!("{}.json", target.name())),
    )?;
    let json: serde_json::Value = serde_json::from_slice(&artifact)?;
    let encoded = json["bytecode"]
        .as_str()
        .context("artifact bytecode is missing")?;
    Ok((decompress(&STANDARD.decode(encoded)?)?, artifact.len()))
}

pub struct Prover {
    circuit: CircuitInput,
    project: PathBuf,
}

pub struct Prepared {
    pub prover: Prover,
    pub num_gates: usize,
    pub preprocessing_size: usize,
}

/// Reuses a BB child process and its SRS cache across benchmark iterations.
/// The harness creates the session before timing proving and verification.
pub struct Session {
    api: RefCell<BarretenbergApi<PipeBackend>>,
    prepared: RefCell<HashMap<(Target, usize), Rc<Prepared>>>,
}

impl Session {
    pub fn new() -> Result<Self> {
        let bb = std::env::var_os("BB_BIN").unwrap_or_else(|| "bb".into());
        let version = run(Command::new(&bb).arg("--version"))?;
        ensure!(
            String::from_utf8_lossy(&version).trim() == BB_VERSION,
            "expected Barretenberg {BB_VERSION}, got {}",
            String::from_utf8_lossy(&version)
        );
        let version = run(nargo().arg("--version"))?;
        let version = String::from_utf8_lossy(&version);
        ensure!(
            version
                .lines()
                .any(|line| line.trim() == format!("nargo version = {NARGO_VERSION}")),
            "expected Nargo {NARGO_VERSION}, got {version}"
        );
        Ok(Self {
            api: RefCell::new(BarretenbergApi::new(PipeBackend::new(bb, None)?)),
            prepared: RefCell::new(HashMap::new()),
        })
    }

    /// Compile and cache each circuit size and verification key before timing.
    /// Generated Noir projects live under `target/noir/<target>_<size>`.
    pub fn prepare(&self, target: Target, size: usize) -> Result<Rc<Prepared>> {
        if let Some(prepared) = self.prepared.borrow().get(&(target, size)) {
            return Ok(Rc::clone(prepared));
        }
        let source = target.source(size)?;
        let project = project_path(target, size);
        fs::create_dir_all(project.join("src"))?;
        fs::write(project.join("src/main.nr"), source)?;
        fs::copy(
            source_root()
                .join(target.source_directory())
                .join("Nargo.toml"),
            project.join("Nargo.toml"),
        )?;
        fs::write(project.join("Prover.toml"), target.inputs(size))?;
        run(nargo().current_dir(&project).args([
            "compile",
            "--silence-warnings",
            "--skip-brillig-constraints-check",
        ]))?;
        let (bytecode, preprocessing_size) = load_bytecode(&project, target)?;
        let mut circuit = CircuitInput {
            name: target.name().into(),
            bytecode,
            verification_key: vec![],
        };
        let mut api = self.api.borrow_mut();
        let num_gates = api
            .circuit_stats(circuit.clone(), false, settings())?
            .num_gates as usize;
        circuit.verification_key = api
            .circuit_compute_vk(
                CircuitInputNoVK {
                    name: circuit.name.clone(),
                    bytecode: circuit.bytecode.clone(),
                },
                settings(),
            )?
            .bytes;
        fs::write(project.join("target/vk"), &circuit.verification_key)?;
        let prepared = Rc::new(Prepared {
            prover: Prover { circuit, project },
            num_gates,
            preprocessing_size,
        });
        self.prepared
            .borrow_mut()
            .insert((target, size), Rc::clone(&prepared));
        Ok(prepared)
    }

    /// Proving includes witness generation and construction of the UltraHonk prover instance.
    pub fn prove(&self, prover: &Prover) -> Result<CircuitProveResponse> {
        run(nargo().current_dir(&prover.project).args([
            "execute",
            "--silence-warnings",
            "witness",
        ]))?;
        let witness = decompress(&fs::read(prover.project.join("target/witness.gz"))?)?;
        Ok(self
            .api
            .borrow_mut()
            .circuit_prove(prover.circuit.clone(), &witness, settings())?)
    }

    pub fn verify(&self, prover: &Prover, proof: &CircuitProveResponse) -> Result<bool> {
        Ok(self
            .api
            .borrow_mut()
            .circuit_verify(
                &prover.circuit.verification_key,
                proof.public_inputs.clone(),
                proof.proof.clone(),
                settings(),
            )?
            .verified)
    }
}

#[derive(Parser)]
struct MemoryArgs {
    #[arg(long, env = "INPUT_SIZE")]
    input_size: usize,
}

pub fn measure_memory(target: Target) -> Result<()> {
    let size = MemoryArgs::parse().input_size;
    let project = project_path(target, size);
    if !project.join("target/vk").is_file() {
        bail!(
            "prepare {}_{size} with the benchmark harness before measuring memory",
            target.name()
        );
    }
    // The harness prepares the bytecode and verification key before RAM measurement.
    let (bytecode, _) = load_bytecode(&project, target)?;
    let verification_key = fs::read(project.join("target/vk"))?;
    let prover = Prover {
        circuit: CircuitInput {
            name: target.name().into(),
            bytecode,
            verification_key,
        },
        project,
    };
    let session = Session::new()?;
    let _proof = session.prove(&prover)?;
    // Reap BB before exit so /usr/bin/time includes its peak RSS.
    drop(session);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_preserve_public_outputs_and_size_parameters() {
        for target in Target::ALL {
            for size in target.input_sizes() {
                let source = target.source(size).unwrap();
                assert!(source.contains("-> pub "));
                if target != Target::Ecdsa {
                    assert!(source.contains(&format!("; {size}]")));
                }
                match target {
                    Target::Keccak => {
                        assert!(source.contains(&format!("keccak256::<{size}>")));
                    }
                    Target::Poseidon => {
                        assert!(
                            source
                                .contains(&format!("use poseidon::poseidon::bn254::hash_{size};"))
                        );
                        assert!(source.contains(&format!("hash_{size}(inputs)")));
                    }
                    Target::Poseidon2 => {
                        assert!(source.contains(&format!("Poseidon2::hash(inputs, {size})")));
                    }
                    _ => {}
                }
            }
        }
        assert!(Target::Blake3.source(2048).is_err());
    }
}

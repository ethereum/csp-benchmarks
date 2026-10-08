use provekit_common::{NoirProof, NoirProofScheme, Prover, Verifier, file::serialize};
use provekit_prover::Prove;
use provekit_r1cs_compiler::NoirProofSchemeBuilder;
use provekit_verifier::Verify;
use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use utils::generate_ecdsa_input;
use utils::harness::{AuditStatus, BenchProperties};

const NOIR_VERSION: &str = "1.0.0-beta.26";

pub const PROVEKIT_PROPS: BenchProperties = BenchProperties {
    proving_system: Cow::Borrowed("Spartan+WHIR"), // https://github.com/worldfnd/provekit
    field_curve: Cow::Borrowed("Bn254"),           // https://github.com/worldfnd/provekit
    iop: Cow::Borrowed("Spartan"),                 // https://github.com/worldfnd/provekit
    pcs: Some(Cow::Borrowed("WHIR")),              // https://github.com/worldfnd/provekit
    arithm: Cow::Borrowed("R1CS"),                 // https://github.com/worldfnd/provekit
    is_zk: true, // https://github.com/worldfnd/provekit/blob/c87957a02a2618a0932abd85726040139e49091c/provekit/prover/src/whir_r1cs.rs
    is_zkvm: false,
    security_bits: 128, // https://github.com/worldfnd/provekit/blob/c87957a02a2618a0932abd85726040139e49091c/provekit/r1cs-compiler/src/whir_r1cs.rs#L75
    is_pq: true,        // hash-based PCS
    is_maintained: true, // https://github.com/worldfnd/provekit
    is_audited: AuditStatus::NotAudited,
    isa: None,
};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("circuits")
}

fn compile_package(package: &str) -> (NoirProofScheme, PathBuf) {
    let workspace_root = workspace_root();
    let nargo = std::env::var_os("PROVEKIT_NARGO")
        .or_else(|| std::env::var_os("NARGO_BIN"))
        .unwrap_or_else(|| "nargo".into());
    let version = Command::new(&nargo)
        .arg("--version")
        .output()
        .expect("Failed to run nargo --version");
    assert!(
        version.status.success()
            && String::from_utf8_lossy(&version.stdout)
                .lines()
                .any(|line| line.trim() == format!("nargo version = {NOIR_VERSION}")),
        "ProveKit WHIR requires nargo {NOIR_VERSION}; select it with PROVEKIT_NARGO"
    );
    let output = Command::new(&nargo)
        .args([
            "compile",
            "--package",
            package,
            "--silence-warnings",
            "--skip-brillig-constraints-check",
        ])
        .current_dir(&workspace_root)
        .output()
        .expect("Failed to run nargo compile");
    if !output.status.success() {
        panic!(
            "Compilation failed for {package}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let circuit_path = workspace_root
        .join("target")
        .join(format!("{package}.json"));
    let proof_scheme = NoirProofScheme::from_file(&circuit_path)
        .unwrap_or_else(|e| panic!("Failed to load proof scheme for {package}: {e}"));
    (proof_scheme, circuit_path)
}

fn write_prover_toml(package: &str, content: &str) -> PathBuf {
    let dir = workspace_root().join("target").join("inputs");
    fs::create_dir_all(&dir).expect("Failed to create circuit dir");
    let toml_path = dir.join(format!("{package}.toml"));
    fs::write(&toml_path, content).expect("Failed to write Prover.toml");
    toml_path
}

fn join_u8(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn join_field_strings(fields: &[String]) -> String {
    fields
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn prepare_sha256(input_size: usize) -> (NoirProofScheme, PathBuf, PathBuf) {
    let package = format!("csp_sha256_{input_size}");
    let (proof_scheme, circuit_path) = compile_package(&package);

    let (data, _digest) = utils::generate_sha256_input(input_size);
    let toml = format!("input = [{}]\ninput_len = {input_size}", join_u8(&data),);
    let toml_path = write_prover_toml(&package, &toml);
    (proof_scheme, toml_path, circuit_path)
}

pub fn prepare_keccak(input_size: usize) -> (NoirProofScheme, PathBuf, PathBuf) {
    let package = format!("csp_keccak_{input_size}");
    let (proof_scheme, circuit_path) = compile_package(&package);

    let (data, digest) = utils::generate_keccak_input(input_size);
    let toml = format!(
        "msg = [{}]\nmessage_size = {input_size}\nresult = [{}]",
        join_u8(&data),
        join_u8(&digest),
    );
    let toml_path = write_prover_toml(&package, &toml);
    (proof_scheme, toml_path, circuit_path)
}

pub fn prepare_poseidon(input_size: usize) -> (NoirProofScheme, PathBuf, PathBuf) {
    let package = format!("csp_poseidon_{input_size}");
    let (proof_scheme, circuit_path) = compile_package(&package);

    let fields = utils::generate_poseidon_input_strings(input_size);
    let toml = format!("inputs = [{}]", join_field_strings(&fields));
    let toml_path = write_prover_toml(&package, &toml);
    (proof_scheme, toml_path, circuit_path)
}

pub fn prepare_poseidon2(input_size: usize) -> (NoirProofScheme, PathBuf, PathBuf) {
    let package = format!("csp_poseidon2_{input_size}");
    let (proof_scheme, circuit_path) = compile_package(&package);

    let fields = utils::generate_poseidon_input_strings(input_size);
    let toml = format!("inputs = [{}]", join_field_strings(&fields));
    let toml_path = write_prover_toml(&package, &toml);
    (proof_scheme, toml_path, circuit_path)
}

pub fn prepare_ecdsa(_: usize) -> (NoirProofScheme, PathBuf, PathBuf) {
    let package = "csp_ecdsa_p256";
    let (proof_scheme, circuit_path) = compile_package(package);

    let (digest, (pub_key_x, pub_key_y), signature) = generate_ecdsa_input();
    let toml = format!(
        "hashed_message = [{}]\npub_key_x = [{}]\npub_key_y = [{}]\nsignature = [{}]",
        join_u8(&digest),
        join_u8(&pub_key_x),
        join_u8(&pub_key_y),
        join_u8(&signature),
    );
    let toml_path = write_prover_toml(package, &toml);
    (proof_scheme, toml_path, circuit_path)
}

pub fn prove(proof_scheme: &NoirProofScheme, toml_path: &Path) -> NoirProof {
    let prover = Prover::from_noir_proof_scheme(proof_scheme.clone());
    prover
        .prove_with_toml(toml_path)
        .expect("Proof generation failed")
}

/// Verify a proof with the given scheme
pub fn verify(proof: &NoirProof, proof_scheme: &NoirProofScheme) -> Result<(), &'static str> {
    let mut verifier = Verifier::from_noir_proof_scheme(proof_scheme.clone());
    verifier.verify(proof).map_err(|_| "Proof is not valid")
}

pub fn preprocessing_size(proof_scheme: &NoirProofScheme) -> usize {
    let prover = Prover::from_noir_proof_scheme(proof_scheme.clone());
    serialize(&prover)
        .expect("serialize Prover to .pkp bytes")
        .len()
}

#[cfg(test)]
mod tests {
    use super::compile_package;

    #[test]
    fn ecdsa_circuit_exposes_digest_and_key() {
        let (scheme, _) = compile_package("csp_ecdsa_p256");
        let abi = scheme.witness_generator.abi();
        for name in ["hashed_message", "pub_key_x", "pub_key_y"] {
            assert!(
                abi.parameters
                    .iter()
                    .find(|p| p.name == name)
                    .unwrap()
                    .is_public()
            );
        }
        assert!(
            !abi.parameters
                .iter()
                .find(|p| p.name == "signature")
                .unwrap()
                .is_public()
        );
    }
}

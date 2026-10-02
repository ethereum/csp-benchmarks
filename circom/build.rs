use std::{
    fs,
    path::{Path, PathBuf},
};

fn emit_rpath(path: &Path) {
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", path.display());
}

fn find_rapidsnark_dirs(out_dir: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let out_path = Path::new(out_dir);
    let build_root = out_path.parent().and_then(|p| p.parent());
    let target = std::env::var("TARGET").ok();

    if let Some(build_root) = build_root
        && let Ok(entries) = fs::read_dir(build_root)
    {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with("rust-rapidsnark-") {
                continue;
            }
            let base = path.join("out").join("rapidsnark");
            let mut candidates = Vec::new();
            if let Some(ref triple) = target {
                candidates.push(base.join(triple));
            }
            candidates.push(base.join("aarch64-apple-darwin"));
            candidates.push(base.join("x86_64-apple-darwin"));
            for candidate in candidates {
                if candidate.join("librapidsnark.dylib").exists() {
                    dirs.push(candidate);
                }
            }
        }
    }

    dirs
}

const CIRCUIT_DIR: &str = "./circuits/ecdsa";
const CIRCOMLIB_DIR: &str = "./circomlib/circuits";
const CACHE_HIT_ENV: &str = "CIRCOM_ECDSA_WITNESS_CACHE_HIT";
const CIRCOM_OPTIMIZATION: &str = "--O2";

fn collect_circom_sources(dir: &Path, sources: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_circom_sources(&path, sources);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "circom")
        {
            sources.push(path);
        }
    }
}

fn generator_inputs() -> Vec<PathBuf> {
    let mut inputs = vec![PathBuf::from("./build.rs")];
    for dir in [CIRCUIT_DIR, CIRCOMLIB_DIR] {
        collect_circom_sources(Path::new(dir), &mut inputs);
    }
    inputs.sort();
    inputs
}

fn is_nonempty_file(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0)
}

/// CI sets this only after an exact cache hit whose key covers the circuit
/// sources, circomlib sources, compiler version, platform, and generation code.
/// Trusting that key preserves the generated files' mtimes for the native build
/// cache while the size checks reject incomplete cache entries.
fn exact_ci_cache_hit(cpp: &Path, dat: &Path) -> bool {
    std::env::var(CACHE_HIT_ENV).is_ok_and(|value| value == "1")
        && is_nonempty_file(cpp)
        && is_nonempty_file(dat)
}

/// Local builds use mtimes to decide whether the generated files still match
/// the current generator inputs.
fn is_current(cpp: &Path, dat: &Path, inputs: &[PathBuf]) -> bool {
    if inputs.is_empty() || !is_nonempty_file(cpp) || !is_nonempty_file(dat) {
        return false;
    }
    let Ok(built) = cpp.metadata().and_then(|m| m.modified()) else {
        return false;
    };
    inputs.iter().all(|input| {
        input
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|changed| changed <= built)
    })
}

/// The ECDSA witness generators are the artifacts not tracked in the repo: at
/// tens of MiB of generated C++ each, because the width-12 comb table is
/// inlined in the circuit. They are compiled from `<name>.circom` on demand,
/// which needs `circom` on PATH. Every other circuit still ships its `.cpp` and
/// `.dat` in tree.
fn generate_witness_generator(name: &str) {
    let circuit = format!("{name}.circom");

    // Watch the generation code and every circuit in the directory, not just
    // the main file: that file is a `main` component over the includes that
    // hold the circuit itself. The directory is not watched as a whole because
    // the generated files live in it.
    let inputs = generator_inputs();
    for input in &inputs {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    println!("cargo:rerun-if-env-changed={CACHE_HIT_ENV}");

    let dest = Path::new(CIRCUIT_DIR).join(name);
    let cpp = dest.join(format!("{name}.cpp"));
    let dat = dest.join(format!("{name}.dat"));
    if exact_ci_cache_hit(&cpp, &dat) || is_current(&cpp, &dat, &inputs) {
        return;
    }

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is set for build scripts");
    let staging = Path::new(&out_dir).join(format!("{name}_circom"));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).expect("cannot create the circom output directory");

    // Generate the optimized witness calculator without an `.r1cs`, which is not
    // needed here and costs over 100 MB. circom emits into `<out>/<name>_cpp/`.
    let status = std::process::Command::new("circom")
        .current_dir(CIRCUIT_DIR)
        .arg(&circuit)
        .arg("--c")
        .arg(CIRCOM_OPTIMIZATION)
        .arg("-o")
        .arg(&staging)
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "could not run `circom`, which builds the ECDSA witness generators \
                 (the circuit artifacts not stored in the repo): {e}. \
                 Install circom 2.2.3 and put it on PATH."
            )
        });
    assert!(status.success(), "circom failed to compile {circuit}");

    let emitted = staging.join(format!("{name}_cpp"));
    fs::create_dir_all(&dest).expect("cannot create the circuit directory");
    for file in [format!("{name}.cpp"), format!("{name}.dat")] {
        fs::copy(emitted.join(&file), dest.join(&file))
            .unwrap_or_else(|e| panic!("circom did not emit {file}: {e}"));
    }
}

fn main() {
    generate_witness_generator("ecdsa_32");
    generate_witness_generator("ecdsa_p256_32");

    // SHA256 circuits
    witnesscalc_adapter::build_and_link("./circuits/sha256/sha256_128");
    witnesscalc_adapter::build_and_link("./circuits/sha256/sha256_256");
    witnesscalc_adapter::build_and_link("./circuits/sha256/sha256_512");
    witnesscalc_adapter::build_and_link("./circuits/sha256/sha256_1024");
    witnesscalc_adapter::build_and_link("./circuits/sha256/sha256_2048");

    // ECDSA circuit (secp256k1, fake-GLV + width-12 comb)
    witnesscalc_adapter::build_and_link("./circuits/ecdsa/ecdsa_32");

    // ECDSA circuit (secp256r1, 2-dimensional fake-GLV + width-12 comb)
    witnesscalc_adapter::build_and_link("./circuits/ecdsa/ecdsa_p256_32");

    // Keccak circuits
    witnesscalc_adapter::build_and_link("./circuits/keccak/keccak_128");
    witnesscalc_adapter::build_and_link("./circuits/keccak/keccak_256");
    witnesscalc_adapter::build_and_link("./circuits/keccak/keccak_512");
    witnesscalc_adapter::build_and_link("./circuits/keccak/keccak_1024");
    witnesscalc_adapter::build_and_link("./circuits/keccak/keccak_2048");

    // Poseidon circuits
    witnesscalc_adapter::build_and_link("./circuits/poseidon/poseidon_2");
    witnesscalc_adapter::build_and_link("./circuits/poseidon/poseidon_4");
    witnesscalc_adapter::build_and_link("./circuits/poseidon/poseidon_8");
    witnesscalc_adapter::build_and_link("./circuits/poseidon/poseidon_12");
    witnesscalc_adapter::build_and_link("./circuits/poseidon/poseidon_16");

    if let Ok(out_dir) = std::env::var("OUT_DIR") {
        let lib_dir = Path::new(&out_dir)
            .join("witnesscalc")
            .join("package")
            .join("lib");
        if lib_dir.exists() {
            emit_rpath(&lib_dir);
        }

        let mut rapidsnark_dirs = if let Ok(paths) = std::env::var("DEP_RUST_RAPIDSNARK_NATIVE") {
            std::env::split_paths(std::ffi::OsStr::new(&paths))
                .filter(|p| p.exists())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        if rapidsnark_dirs.is_empty() {
            rapidsnark_dirs.extend(find_rapidsnark_dirs(&out_dir));
        }

        for dir in rapidsnark_dirs {
            emit_rpath(&dir);
        }
    }
}

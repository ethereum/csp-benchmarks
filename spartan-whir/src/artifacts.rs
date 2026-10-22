use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use spartan_whir::{PoseidonWitnessGenerator, R1csShape, engine::F, import_r1cs_path};

const CIRCOM_FLAGS: &[&str] = &["--prime", "koalabear", "--r1cs", "--c"];
const CXX_FLAGS: &[&str] = &[
    "-std=c++11",
    "-O3",
    "-fPIC",
    "-fvisibility=hidden",
    "-UNDEBUG",
    "-DCIRCOM_LINKED_WITNESS_ONLY",
];
const INCLUDE_DIRS: &[&str] = &["/opt/homebrew/include", "/usr/local/include"];
const LIBRARY_DIRS: &[&str] = &["/opt/homebrew/lib", "/usr/local/lib"];

pub struct Artifacts {
    pub shape: R1csShape<F>,
    pub witness: WitnessArtifacts,
}

pub struct WitnessArtifacts {
    pub generator: PoseidonWitnessGenerator,
    pub witness_artifact_size: usize,
}

pub fn load(target: &str, input_size: usize) -> Result<Artifacts> {
    if !matches!(
        target,
        "sha256" | "keccak" | "poseidon" | "ecdsa" | "ecdsa_p256"
    ) {
        bail!("unsupported Spartan-WHIR target {target}");
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let stem = format!("{target}_{input_size}");
    let source = root
        .join("circuits")
        .join(if target == "ecdsa_p256" {
            "ecdsa"
        } else {
            target
        })
        .join(format!("{stem}.circom"));
    if !source.is_file() {
        bail!("missing Spartan-WHIR circuit {}", source.display());
    }
    let circom = resolve_program(
        env::var_os("SPARTAN_WHIR_CIRCOM").unwrap_or_else(|| OsString::from("circom")),
    )?;
    let cxx = resolve_program(env::var_os("CXX").unwrap_or_else(|| OsString::from("c++")))?;
    let fingerprint = fingerprint(root, &source, &circom, &cxx)?;
    let cache_root = root.join("target/circuits");
    fs::create_dir_all(&cache_root)
        .with_context(|| format!("create circuit cache {}", cache_root.display()))?;
    let cache = cache_root.join(format!("{stem}-{fingerprint}"));
    if !cache.is_dir() {
        let build = tempfile::Builder::new()
            .prefix(".build-")
            .tempdir_in(&cache_root)
            .context("create temporary circuit build directory")?;
        compile(&source, &stem, build.path(), &circom, &cxx)?;
        if !complete(build.path(), &stem) {
            bail!("compiler did not produce all artifacts for {stem}");
        }
        // A complete directory becomes visible atomically. Another process may
        // have finished the same build while this process was compiling.
        if let Err(error) = fs::rename(build.path(), &cache)
            && !complete(&cache, &stem)
        {
            return Err(error).context("publish completed circuit build");
        }
    }
    if !complete(&cache, &stem) {
        bail!("incomplete circuit cache {}", cache.display());
    }
    load_compiled(&cache, &stem)
}

fn resolve_program(program: OsString) -> Result<PathBuf> {
    let path = PathBuf::from(&program);
    if path.components().count() > 1 || path.is_absolute() {
        if !path.is_file() {
            bail!("compiler {} does not exist", path.display());
        }
        return absolute(path);
    }
    if let Some(paths) = env::var_os("PATH") {
        for directory in env::split_paths(&paths) {
            let candidate = directory.join(&path);
            if candidate.is_file() {
                return absolute(candidate);
            }
        }
    }
    bail!(
        "compiler {} was not found; set SPARTAN_WHIR_CIRCOM to the KoalaBear Circom executable and CXX to a C++ compiler",
        path.display()
    )
}

fn absolute(path: PathBuf) -> Result<PathBuf> {
    // Preserve the executable name: clang++ and clang can be symlinks to the
    // same binary, while the driver name selects C++ runtime linking.
    Ok(if path.is_absolute() {
        path
    } else {
        env::current_dir()?.join(path)
    })
}

fn fingerprint(root: &Path, entry: &Path, circom: &Path, cxx: &Path) -> Result<String> {
    let mut hash = Sha256::new();
    update(&mut hash, b"spartan-whir-circuit-cache-v1");
    update(&mut hash, env::consts::OS.as_bytes());
    update(&mut hash, env::consts::ARCH.as_bytes());
    for flag in CIRCOM_FLAGS {
        update(&mut hash, flag.as_bytes());
    }
    let stem = entry
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("");
    update(&mut hash, optimization(stem).as_bytes());
    if stem.starts_with("ecdsa") {
        update(&mut hash, include_bytes!("comb_witness.rs"));
        update(&mut hash, b"-lgmp");
        for directory in LIBRARY_DIRS {
            if Path::new(directory).is_dir() {
                update(&mut hash, directory.as_bytes());
            }
        }
    }
    for flag in CXX_FLAGS {
        update(&mut hash, flag.as_bytes());
    }
    for directory in INCLUDE_DIRS {
        let directory = Path::new(directory);
        if directory.is_dir() {
            update(&mut hash, directory.as_os_str().as_encoded_bytes());
        }
    }
    let mut sources = BTreeSet::new();
    collect_sources(entry, &mut sources)?;
    for source in sources {
        update(
            &mut hash,
            source
                .strip_prefix(root)
                .unwrap_or(&source)
                .as_os_str()
                .as_encoded_bytes(),
        );
        hash_file(&mut hash, &source)?;
    }
    for compiler in [circom, cxx] {
        update(&mut hash, compiler.as_os_str().as_encoded_bytes());
        hash_file(&mut hash, compiler)?;
        let output = Command::new(compiler)
            .arg("--version")
            .output()
            .with_context(|| format!("read compiler version {}", compiler.display()))?;
        if !output.status.success() {
            bail!(
                "compiler {} --version failed: {}",
                compiler.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        update(&mut hash, &output.stdout);
        update(&mut hash, &output.stderr);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn collect_sources(source: &Path, sources: &mut BTreeSet<PathBuf>) -> Result<()> {
    let source = fs::canonicalize(source)
        .with_context(|| format!("resolve circuit source {}", source.display()))?;
    if !sources.insert(source.clone()) {
        return Ok(());
    }
    let text = fs::read_to_string(&source)
        .with_context(|| format!("read circuit source {}", source.display()))?;
    for line in text.lines() {
        if let Some(include) = line.trim_start().strip_prefix("include") {
            let include = include.trim_start();
            if let Some(quoted) = include.strip_prefix('"') {
                let (path, _) = quoted
                    .split_once('"')
                    .with_context(|| format!("invalid include in {}", source.display()))?;
                collect_sources(&source.parent().unwrap().join(path), sources)?;
            }
        }
    }
    Ok(())
}

fn update(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

fn hash_file(hash: &mut Sha256, path: &Path) -> Result<()> {
    let mut file = File::open(path).with_context(|| format!("read {}", path.display()))?;
    hash.update(file.metadata()?.len().to_le_bytes());
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            return Ok(());
        }
        hash.update(&buffer[..length]);
    }
}

fn compile(source: &Path, stem: &str, output: &Path, circom: &Path, cxx: &Path) -> Result<()> {
    let mut command = Command::new(circom);
    command
        .arg(source)
        .args(CIRCOM_FLAGS)
        .arg(optimization(stem))
        .arg("-o")
        .arg(output);
    run(command, "compile KoalaBear circuit")?;

    let cpp = output.join(format!("{stem}_cpp"));
    if stem.starts_with("ecdsa") {
        crate::comb_witness::compact(&cpp.join(format!("{stem}.cpp")))
            .context("compact the native comb table initialization")?;
    }
    let library = output.join(library_name(stem));
    let mut command = Command::new(cxx);
    command.args(CXX_FLAGS).arg("-I").arg(&cpp);
    for directory in INCLUDE_DIRS {
        if Path::new(directory).is_dir() {
            command.arg("-I").arg(directory);
        }
    }
    command
        .arg(cpp.join("calcwit.cpp"))
        .arg(cpp.join("fr.cpp"))
        .arg(cpp.join("main.cpp"))
        .arg(cpp.join(format!("{stem}.cpp")));
    if stem.starts_with("ecdsa") {
        for directory in LIBRARY_DIRS {
            if Path::new(directory).is_dir() {
                command.arg("-L").arg(directory);
            }
        }
        command.arg("-lgmp");
    }
    if cfg!(target_os = "macos") {
        command
            .arg("-dynamiclib")
            .arg(format!("-Wl,-install_name,@rpath/{}", library_name(stem)));
    } else {
        command.arg("-shared");
    }
    command.arg("-o").arg(library);
    run(command, "compile native witness generator")
}

fn optimization(stem: &str) -> &'static str {
    if stem.starts_with("ecdsa") {
        "--O1"
    } else {
        "--O2"
    }
}

fn run(mut command: Command, operation: &str) -> Result<()> {
    let output = command
        .output()
        .with_context(|| format!("{operation}: {command:?}"))?;
    if !output.status.success() {
        bail!(
            "{operation} failed ({})\ncommand: {command:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn library_name(stem: &str) -> String {
    format!(
        "{}{stem}_witness.{}",
        env::consts::DLL_PREFIX,
        env::consts::DLL_EXTENSION
    )
}

fn complete(cache: &Path, stem: &str) -> bool {
    cache.join(format!("{stem}.r1cs")).is_file()
        && cache.join(library_name(stem)).is_file()
        && cache.join(format!("{stem}_cpp/{stem}.dat")).is_file()
}

fn load_compiled(cache: &Path, stem: &str) -> Result<Artifacts> {
    let path = cache.join(format!("{stem}.r1cs"));
    let shape = import_r1cs_path(path)?.shape;
    let library_path = cache.join(library_name(stem));
    let circuit_data = fs::read(cache.join(format!("{stem}_cpp/{stem}.dat")))?;
    // SAFETY: the library is generated by the pinned KoalaBear Circom compiler
    // and implements the documented witness ABI. The generator owns its library.
    let generator = unsafe {
        PoseidonWitnessGenerator::load_library("csp-benchmarks", &library_path, stem, &circuit_data)
    }
    .with_context(|| format!("load native witness library {}", library_path.display()))?;
    let witness_artifact_size = usize::try_from(fs::metadata(&library_path)?.len())?
        .checked_add(circuit_data.len())
        .context("native witness artifact size overflow")?;
    Ok(Artifacts {
        shape,
        witness: WitnessArtifacts {
            generator,
            witness_artifact_size,
        },
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn compiler(path: &Path, suffix: &str) {
        fs::write(path, format!("#!/bin/sh\necho test-compiler\n# {suffix}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn cache_tracks_included_sources_and_compilers() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let entry = root.join("main.circom");
        let included = root.join("shared.circom");
        fs::write(&entry, "include \"shared.circom\";\n").unwrap();
        fs::write(&included, "// shared source\n").unwrap();
        let circom = root.join("circom");
        let cxx = root.join("c++");
        compiler(&circom, "circom");
        compiler(&cxx, "cxx");
        let initial = fingerprint(root, &entry, &circom, &cxx).unwrap();

        fs::write(root.join("unrelated.circom"), "// unrelated source\n").unwrap();
        assert_eq!(initial, fingerprint(root, &entry, &circom, &cxx).unwrap());

        fs::write(&included, "// revised shared source\n").unwrap();
        let changed_source = fingerprint(root, &entry, &circom, &cxx).unwrap();
        assert_ne!(initial, changed_source);

        compiler(&cxx, "changed executable, identical version output");
        assert_ne!(
            changed_source,
            fingerprint(root, &entry, &circom, &cxx).unwrap()
        );
    }
}

//! Apply the benchmark's native table representation to a standalone probe.

#[path = "../src/comb_witness.rs"]
mod comb_witness;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let source = args.next().ok_or_else(|| {
        anyhow::anyhow!("usage: compact_comb_witness <fresh-generated-circuit.cpp>")
    })?;
    anyhow::ensure!(args.next().is_none(), "expected one C++ source path");
    comb_witness::compact(std::path::Path::new(&source))
}

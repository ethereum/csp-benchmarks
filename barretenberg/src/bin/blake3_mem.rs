fn main() -> anyhow::Result<()> {
    barretenberg_bench::measure_memory(barretenberg_bench::Target::Blake3)
}

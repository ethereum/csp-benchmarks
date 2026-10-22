use clap::Parser;
use spartan_whir_bench::{Target, prepare, prove};

#[derive(Parser)]
struct Args {
    #[arg(long, env = "INPUT_SIZE")]
    input_size: usize,
}

fn main() {
    let args = Args::parse();
    let prepared = prepare(Target::Sha256, args.input_size);
    let _ = prove(&prepared);
}

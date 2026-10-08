use clap::Parser;
use vega_bench::{prepare_sha256, prove_sha256};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    input_size: Option<usize>,
}

fn main() {
    let args = Args::parse();
    let input_size = args.input_size.unwrap_or(128);
    let prepared = prepare_sha256(input_size);
    let _proof = prove_sha256(&prepared);
}

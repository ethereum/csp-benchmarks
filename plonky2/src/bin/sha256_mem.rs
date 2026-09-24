use clap::Parser;
use plonky2_circuits::bench::{prove, sha256_prepare};

#[derive(Parser, Debug)]
struct Args {
    /// Input size parameter
    #[arg(long)]
    input_size: usize,
}

fn main() {
    let args = Args::parse();

    sha256_mem(args.input_size);
}

fn sha256_mem(input_size: usize) {
    let (data, pw, _, _) = sha256_prepare(input_size);
    let _proof = prove(&data, pw);
}

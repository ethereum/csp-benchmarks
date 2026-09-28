use clap::Parser;
use plonky2_circuits::bench::{keccak256_prepare, prove};

#[derive(Parser, Debug)]
struct Args {
    /// Input size parameter
    #[arg(long)]
    input_size: usize,
}

fn main() {
    let args = Args::parse();

    keccak_mem(args.input_size);
}

fn keccak_mem(input_size: usize) {
    let (data, pw, _, _) = keccak256_prepare(input_size);
    let _proof = prove(&data, pw);
}

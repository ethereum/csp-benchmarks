use circom::ecdsa_p256::{prepare, prove};
use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    /// Input size parameter
    #[arg(long)]
    input_size: usize,
}

fn main() {
    let args = Args::parse();

    ecdsa_p256_mem(args.input_size);
}

fn ecdsa_p256_mem(input_size: usize) {
    let (witness_fn, input_str, zkey_path) = prepare(input_size);
    let _ = prove(witness_fn, input_str, zkey_path);
}

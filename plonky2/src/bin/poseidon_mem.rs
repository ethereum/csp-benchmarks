use clap::Parser;
use plonky2_circuits::bench::{poseidon_prepare, prove};

#[derive(Parser, Debug)]
struct Args {
    /// Number of field elements to hash
    #[arg(long)]
    input_size: usize,
}

fn main() {
    let args = Args::parse();

    let (circuit_data, pw, _, _) = poseidon_prepare(args.input_size);
    let _ = prove(&circuit_data, pw);
}

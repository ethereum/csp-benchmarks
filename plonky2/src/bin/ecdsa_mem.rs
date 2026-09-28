use clap::Parser;
use plonky2_circuits::ecdsa::{prepare, prove};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    input_size: usize,
}

fn main() {
    let prepared = prepare(Args::parse().input_size);
    let _proof = prove(&prepared);
}

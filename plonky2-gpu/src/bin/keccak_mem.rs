use clap::Parser;
use plonky2_gpu_circuits::{keccak_prepare, prove};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    input_size: usize,
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    let (data, pw, _, _) = keccak_prepare(args.input_size);
    let _proof = prove(&data, pw);
}

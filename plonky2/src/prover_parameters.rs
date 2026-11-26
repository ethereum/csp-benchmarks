//! Prover configurations selected for the CPU benchmark inputs.
//!
//! We screened wire layouts and FRI fold schedules by padded row count with
//! zero knowledge enabled, then benchmarked the shortlisted configurations.
//! These settings come from the measured proving time and peak RAM Pareto
//! frontiers. See the chart linked from `plonky2/README.md`.

use plonky2::{
    fri::reduction_strategies::FriReductionStrategy, plonk::circuit_data::CircuitConfig,
};

use crate::bench::{self, Prepared};

pub fn sha256_prepare(input_size: usize) -> Prepared {
    let (wires, routed_wires, arity_bits) = match input_size {
        128 => (135, 112, vec![1; 13]),
        256 => (216, 216, quaternary_then_binary(9)),
        512 => (168, 168, vec![1; 14]),
        1024 => (152, 144, vec![1; 15]),
        2048 => (140, 140, quaternary_then_binary(12)),
        _ => return bench::sha256_prepare(input_size),
    };
    bench::sha256_prepare_with_config(input_size, config(wires, routed_wires, arity_bits))
}

pub fn keccak256_prepare(input_size: usize) -> Prepared {
    let (wires, routed_wires, arity_bits) = match input_size {
        128 => (196, 196, vec![1; 12]),
        256 => (160, 160, vec![1; 13]),
        512 => (320, 320, vec![1; 13]),
        1024 => (296, 296, quaternary_then_binary(10)),
        2048 => (140, 140, quaternary_then_binary(12)),
        _ => return bench::keccak256_prepare(input_size),
    };
    bench::keccak256_prepare_with_config(input_size, config(wires, routed_wires, arity_bits))
}

pub fn poseidon_prepare(input_size: usize) -> Prepared {
    if matches!(input_size, 2 | 4 | 8 | 12 | 16) {
        return bench::poseidon_prepare_with_config(
            input_size,
            config(135, 80, quaternary_then_binary(7)),
        );
    }
    bench::poseidon_prepare(input_size)
}

fn quaternary_then_binary(binary_folds: usize) -> Vec<usize> {
    let mut arity_bits = vec![2, 2];
    arity_bits.resize(2 + binary_folds, 1);
    arity_bits
}

fn config(wires: usize, routed_wires: usize, arity_bits: Vec<usize>) -> CircuitConfig {
    let mut config = CircuitConfig::standard_recursion_zk_config();
    config.num_wires = wires;
    config.num_routed_wires = routed_wires;
    config.max_quotient_degree_factor = 8;
    config.fri_config.reduction_strategy = FriReductionStrategy::Fixed(arity_bits);
    config
}

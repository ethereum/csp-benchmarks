// Copyright 2025 Irreducible Inc.
// Reference https://github.com/binius-zk/binius64/blob/main/crates/examples/src/circuits/keccak.rs
use anyhow::Result;
use binius_circuits::{
    fixed_byte_vec::ByteVec,
    keccak::{N_WORDS_PER_DIGEST, keccak256_varlen},
};
use binius_core::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};
use clap::Args;

use crate::circuit_utils::{
    CircuitTrait, DEFAULT_HASH_MESSAGE_BYTES, determine_hash_max_bytes_from_args,
};
use utils::generate_keccak_input;

pub type KeccakParams = <KeccakCircuit as CircuitTrait>::Params;
pub type KeccakInstance = <KeccakCircuit as CircuitTrait>::Instance;

/// Keccak-256 hash circuit example
pub struct KeccakCircuit {
    message: ByteVec,
    digest: [Wire; N_WORDS_PER_DIGEST],
    max_len_bytes: usize,
}

#[derive(Args, Debug, Clone)]
pub struct Params {
    /// Maximum message length in bytes that the circuit can handle
    #[arg(long)]
    pub max_len_bytes: Option<usize>,
}

impl CircuitTrait for KeccakCircuit {
    type Params = Params;
    type Instance = usize;

    fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
        let max_len_bytes = determine_hash_max_bytes_from_args(params.max_len_bytes)?;

        let digest: [Wire; N_WORDS_PER_DIGEST] = std::array::from_fn(|_| builder.add_inout());
        let n_words = max_len_bytes.div_ceil(8);
        let message = ByteVec::new_witness(builder, n_words);
        let computed_digest = keccak256_varlen(builder, &message);
        for index in 0..digest.len() {
            builder.assert_eq(
                format!("keccak_digest[{index}]"),
                computed_digest[index],
                digest[index],
            );
        }

        Ok(Self {
            message,
            digest,
            max_len_bytes,
        })
    }

    fn populate_witness(&self, message_len_bytes: usize, w: &mut WitnessFiller) -> Result<()> {
        let (message_bytes, digest_bytes) = generate_keccak_input(message_len_bytes);
        assert!(message_len_bytes <= self.max_len_bytes);
        self.message.populate_data(w, &message_bytes);
        self.message.populate_len_bytes(w, message_len_bytes);
        for (wire, bytes) in self.digest.iter().zip(digest_bytes.chunks_exact(8)) {
            w[*wire] = Word(u64::from_le_bytes(bytes.try_into().unwrap()));
        }

        Ok(())
    }

    fn param_summary(params: &Self::Params) -> Option<String> {
        Some(format!(
            "{}b",
            params.max_len_bytes.unwrap_or(DEFAULT_HASH_MESSAGE_BYTES)
        ))
    }
}

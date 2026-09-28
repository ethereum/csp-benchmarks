// Copyright 2025 Irreducible Inc.
// Reference: https://github.com/IrreducibleOSS/binius64/blob/main/prover/examples/src/circuits/sha256.rs
use anyhow::Result;
use binius_circuits::{
    fixed_byte_vec::ByteVec,
    sha256::{sha256_fixed, sha256_varlen},
};
use binius_core::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};
use clap::Args;

use std::array;

use crate::circuit_utils::{
    CircuitTrait, DEFAULT_HASH_MESSAGE_BYTES, determine_hash_max_bytes_from_args,
};
use utils::generate_sha256_input;

pub type Sha256Params = <Sha256Circuit as CircuitTrait>::Params;
pub type Sha256Instance = <Sha256Circuit as CircuitTrait>::Instance;

pub struct Sha256Circuit {
    circuit: Sha256Mode,
}

enum Sha256Mode {
    Fixed {
        message: Vec<Wire>,
        digest: [Wire; 8],
        len_bytes: usize,
    },
    Variable {
        message: ByteVec,
        digest: [Wire; 4],
    },
}

impl CircuitTrait for Sha256Circuit {
    type Params = Params;
    type Instance = usize;

    fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
        let max_len_bytes = determine_hash_max_bytes_from_args(params.max_len_bytes)?;
        let circuit = if params.exact_len {
            let message: Vec<Wire> = (0..max_len_bytes.div_ceil(4))
                .map(|_| builder.add_witness())
                .collect();
            let computed_digest = sha256_fixed(builder, &message, max_len_bytes);
            let digest: [Wire; 8] = array::from_fn(|_| builder.add_inout());
            for index in 0..digest.len() {
                builder.assert_eq(
                    format!("sha256_digest[{index}]"),
                    computed_digest[index],
                    digest[index],
                );
            }
            Sha256Mode::Fixed {
                message,
                digest,
                len_bytes: max_len_bytes,
            }
        } else {
            let message = ByteVec::new_witness(builder, max_len_bytes.div_ceil(8));
            let computed_digest = sha256_varlen(builder, &message);
            let digest: [Wire; 4] = array::from_fn(|_| builder.add_inout());
            for index in 0..digest.len() {
                builder.assert_eq(
                    format!("sha256_digest[{index}]"),
                    computed_digest[index],
                    digest[index],
                );
            }
            Sha256Mode::Variable { message, digest }
        };

        Ok(Self { circuit })
    }

    fn populate_witness(&self, message_len_bytes: usize, w: &mut WitnessFiller) -> Result<()> {
        let (message_bytes, digest_bytes) = generate_sha256_input(message_len_bytes);
        match &self.circuit {
            Sha256Mode::Fixed {
                message,
                digest,
                len_bytes,
            } => {
                assert_eq!(message_len_bytes, *len_bytes);
                for (wire, bytes) in message.iter().zip(message_bytes.chunks(4)) {
                    let mut word = [0u8; 4];
                    word[..bytes.len()].copy_from_slice(bytes);
                    w[*wire] = Word(u32::from_be_bytes(word) as u64);
                }
                for (wire, bytes) in digest.iter().zip(digest_bytes.chunks_exact(4)) {
                    w[*wire] = Word(u32::from_be_bytes(bytes.try_into().unwrap()) as u64);
                }
            }
            Sha256Mode::Variable { message, digest } => {
                message.populate_data(w, &message_bytes);
                message.populate_len_bytes(w, message_len_bytes);
                for (wire, bytes) in digest.iter().zip(digest_bytes.chunks_exact(8)) {
                    w[*wire] = Word(u64::from_be_bytes(bytes.try_into().unwrap()));
                }
            }
        }

        Ok(())
    }

    fn param_summary(params: &Self::Params) -> Option<String> {
        let base = format!(
            "{}b",
            params.max_len_bytes.unwrap_or(DEFAULT_HASH_MESSAGE_BYTES)
        );
        if params.exact_len {
            Some(format!("{}-exact", base))
        } else {
            Some(base)
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct Params {
    /// Maximum message length in bytes that the circuit can handle.
    #[arg(long)]
    pub max_len_bytes: Option<usize>,

    /// Build circuit for exact message length (makes length a compile-time constant instead of
    /// runtime witness).
    #[arg(long, default_value_t = false)]
    pub exact_len: bool,
}

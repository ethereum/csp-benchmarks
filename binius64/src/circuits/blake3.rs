use std::array;

use anyhow::Result;
use binius_circuits::blake3::blake3_fixed;
use binius_core::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};
use clap::Args;

use crate::circuit_utils::{
    CircuitTrait, DEFAULT_HASH_MESSAGE_BYTES, determine_hash_max_bytes_from_args,
};
use utils::generate_blake3_input;

pub type Blake3Params = <Blake3Circuit as CircuitTrait>::Params;
pub type Blake3Instance = <Blake3Circuit as CircuitTrait>::Instance;

/// Fixed-length BLAKE3 circuit backed by Binius64's complete chunk/tree gadget.
pub struct Blake3Circuit {
    message: Vec<Wire>,
    digest: [Wire; 8],
    len_bytes: usize,
}

impl CircuitTrait for Blake3Circuit {
    type Params = Params;
    type Instance = usize;

    fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
        let len_bytes = determine_hash_max_bytes_from_args(params.max_len_bytes)?;
        let message: Vec<Wire> = (0..len_bytes.div_ceil(4))
            .map(|_| builder.add_witness())
            .collect();
        let computed_digest = blake3_fixed(builder, &message, len_bytes);
        let digest: [Wire; 8] = array::from_fn(|_| builder.add_inout());
        for index in 0..digest.len() {
            builder.assert_eq(
                format!("blake3_digest[{index}]"),
                computed_digest[index],
                digest[index],
            );
        }

        Ok(Self {
            message,
            digest,
            len_bytes,
        })
    }

    fn populate_witness(&self, message_len_bytes: usize, w: &mut WitnessFiller) -> Result<()> {
        assert_eq!(message_len_bytes, self.len_bytes);
        let (message_bytes, digest_bytes) = generate_blake3_input(message_len_bytes);

        for (wire, bytes) in self.message.iter().zip(message_bytes.chunks(4)) {
            let mut word = [0u8; 4];
            word[..bytes.len()].copy_from_slice(bytes);
            w[*wire] = Word(u32::from_le_bytes(word) as u64);
        }
        for (wire, bytes) in self.digest.iter().zip(digest_bytes.chunks_exact(4)) {
            w[*wire] = Word(u32::from_le_bytes(bytes.try_into().unwrap()) as u64);
        }

        Ok(())
    }

    fn param_summary(params: &Self::Params) -> Option<String> {
        Some(format!(
            "{}b-exact",
            params.max_len_bytes.unwrap_or(DEFAULT_HASH_MESSAGE_BYTES)
        ))
    }
}

#[derive(Args, Debug, Clone)]
pub struct Params {
    /// Exact message length in bytes.
    #[arg(long)]
    pub max_len_bytes: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{prepare, prove, verify};

    #[test]
    #[ignore = "covers BLAKE3 circuit setup and proving"]
    fn blake3_roundtrip_at_sweep_boundaries() {
        for input_size in [128, 2048] {
            let (verifier, prover, _cs, circuit, compiled_circuit, instance) =
                prepare::<Blake3Circuit>(
                    input_size,
                    Params {
                        max_len_bytes: Some(input_size),
                    },
                )
                .expect("prepare BLAKE3 circuit");
            let (proof, public_witness) =
                prove::<Blake3Circuit>(&prover, &compiled_circuit, &circuit, instance)
                    .expect("prove BLAKE3 circuit");
            verify(&verifier, &public_witness, &proof).expect("verify BLAKE3 circuit");
        }
    }
}

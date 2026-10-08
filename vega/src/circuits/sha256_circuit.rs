// MIT License

// Copyright (c) Microsoft Corporation.

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE

use crate::{Scalar, E};
use bellpepper::gadgets::sha256::sha256;
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};
use ff::Field;
use sha2::{Digest, Sha256};
use vega_prover::traits::circuit::VegaCircuit;

#[derive(Clone, Debug)]
pub struct Sha256Circuit {
    preimage: Vec<u8>,
    digest: [u8; 32],
}

impl Sha256Circuit {
    pub fn new(preimage: Vec<u8>, digest: [u8; 32]) -> Self {
        Self { preimage, digest }
    }
}

pub(crate) fn digest_public_values(digest: &[u8; 32]) -> Vec<Scalar> {
    digest
        .iter()
        .flat_map(|&byte| {
            (0..8).rev().map(move |i| {
                if (byte >> i) & 1 == 1 {
                    Scalar::ONE
                } else {
                    Scalar::ZERO
                }
            })
        })
        .collect()
}

impl VegaCircuit<E> for Sha256Circuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(digest_public_values(&self.digest))
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // No shared variables in this circuit
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>], // shared variables, if any
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // 1. Preimage bits
        let bit_values: Vec<_> = self
            .preimage
            .clone()
            .into_iter()
            .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
            .map(Some)
            .collect();
        assert_eq!(bit_values.len(), self.preimage.len() * 8);

        let preimage_bits = bit_values
            .into_iter()
            .enumerate()
            .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {i}")), b))
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()?;

        // 2. SHA-256 gadget
        let hash_bits = sha256(cs.namespace(|| "sha256"), &preimage_bits)?;

        // 3. Sanity-check against Rust SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&self.preimage);
        let expected = hasher.finalize();

        let mut expected_bits = expected
            .iter()
            .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1));

        for b in &hash_bits {
            match b {
                Boolean::Is(bit) => {
                    assert_eq!(expected_bits.next().unwrap(), bit.get_value().unwrap())
                }
                Boolean::Not(bit) => {
                    assert_ne!(expected_bits.next().unwrap(), bit.get_value().unwrap())
                }
                Boolean::Constant(_) => unreachable!(),
            }
        }

        let mut digest_nums = Vec::with_capacity(hash_bits.len());
        for (i, bit) in hash_bits.iter().enumerate() {
            // Carry the computed digest across Vega's precommitted and rest phases.
            let n = AllocatedNum::alloc(cs.namespace(|| format!("digest num {i}")), || {
                Ok(
                    if bit.get_value().ok_or(SynthesisError::AssignmentMissing)? {
                        Scalar::ONE
                    } else {
                        Scalar::ZERO
                    },
                )
            })?;

            // Single equality constraint is enough
            cs.enforce(
                || format!("bit == num {i}"),
                |_| bit.lc(CS::one(), Scalar::ONE),
                |lc| lc + CS::one(),
                |lc| lc + n.get_variable(),
            );
            digest_nums.push(n);
        }

        Ok(digest_nums)
    }

    fn num_challenges(&self) -> usize {
        // SHA-256 circuit does not expect any challenges
        0
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        precommitted: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        // Vega resets public assignments before this phase, so input allocation
        // must happen here, after the precommitted witness has been generated.
        for (i, (computed, expected)) in precommitted
            .iter()
            .zip(digest_public_values(&self.digest))
            .enumerate()
        {
            let public = AllocatedNum::alloc_input(
                cs.namespace(|| format!("public digest bit {i}")),
                || Ok(expected),
            )?;
            cs.enforce(
                || format!("computed == public digest bit {i}"),
                |lc| lc + computed.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + public.get_variable(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;

    #[test]
    fn sha256_constraints_reject_an_incorrect_public_digest() {
        let preimage = vec![7u8];
        let digest: [u8; 32] = Sha256::digest(&preimage).into();
        for valid in [true, false] {
            let mut expected = digest;
            if !valid {
                expected[0] ^= 1;
            }
            let circuit = Sha256Circuit::new(preimage.clone(), expected);
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let shared = circuit.shared(&mut cs).unwrap();
            let precommitted = circuit.precommitted(&mut cs, &shared).unwrap();
            circuit
                .synthesize(&mut cs, &shared, &precommitted, Some(&[]))
                .unwrap();
            assert_eq!(cs.is_satisfied(), valid);
        }
    }
}

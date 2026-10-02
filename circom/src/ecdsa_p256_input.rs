//! Building the circuit input for one secp256r1 (P-256) signature.
//!
//! Same layout as the secp256k1 input: the public part of a signature, each
//! value in four 64-bit limbs. The circuit derives every witness value itself.

use p256::elliptic_curve::PrimeField;
use p256::{FieldBytes, Scalar};
use std::collections::HashMap;

use crate::ecdsa_input::limbs_json;

/// `r`, `s`, `msghash` and the public key, which is everything the circuit
/// reads.
pub fn build_circuit_input(
    digest: &[u8],
    pub_key_x: &[u8],
    pub_key_y: &[u8],
    signature: &[u8],
) -> HashMap<String, serde_json::Value> {
    let (r_bytes, s_bytes) = signature.split_at(32);
    let r = scalar_from_bytes(r_bytes);
    let s = scalar_from_bytes(s_bytes);

    HashMap::from([
        ("r".to_string(), limbs_json(&r.to_bytes())),
        ("s".to_string(), limbs_json(&s.to_bytes())),
        // Keep the original prehash public. The circuit reduces it modulo the
        // group order when it computes u1.
        ("msghash".to_string(), limbs_json(digest)),
        (
            "pubkey".to_string(),
            serde_json::json!([limbs_json(pub_key_x), limbs_json(pub_key_y)]),
        ),
    ])
}

fn scalar_from_bytes(bytes: &[u8]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_repr(*FieldBytes::from_slice(bytes)))
        .expect("scalar below the group order")
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::EncodedPoint;
    use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};

    fn limbs_to_bytes(value: &serde_json::Value) -> Vec<u8> {
        let limbs: Vec<u64> = value
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap().parse().unwrap())
            .collect();
        limbs.iter().rev().flat_map(|l| l.to_be_bytes()).collect()
    }

    #[test]
    fn input_carries_only_the_public_part() {
        let (digest, (x, y), signature) = utils::generate_ecdsa_input();
        let inputs = build_circuit_input(&digest, &x, &y, &signature);
        let mut keys: Vec<_> = inputs.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["msghash", "pubkey", "r", "s"]);
    }

    #[test]
    fn benchmark_signature_verifies_and_round_trips() {
        let (digest, (x, y), signature) = utils::generate_ecdsa_input();
        let point = EncodedPoint::from_affine_coordinates(
            FieldBytes::from_slice(&x),
            FieldBytes::from_slice(&y),
            false,
        );
        let key = VerifyingKey::from_encoded_point(&point).unwrap();
        let sig = Signature::from_slice(&signature).unwrap();
        key.verify_prehash(&digest, &sig).unwrap();

        let inputs = build_circuit_input(&digest, &x, &y, &signature);
        assert_eq!(limbs_to_bytes(&inputs["r"]), signature[..32]);
        assert_eq!(limbs_to_bytes(&inputs["s"]), signature[32..]);
        assert_eq!(limbs_to_bytes(&inputs["msghash"]), digest);
        let pubkey = inputs["pubkey"].as_array().unwrap();
        assert_eq!(limbs_to_bytes(&pubkey[0]), x);
        assert_eq!(limbs_to_bytes(&pubkey[1]), y);
    }
}

//! Building the circuit input for one secp256k1 signature.
//!
//! This module contains the public half of a signature re-encoded into the
//! circuit's limb layout. It does not depend on the prover or generated witness
//! bindings.
//!
//! The circuit derives its own witness values — the inverse of `s`, the point
//! `R`, and the lattice hint — so nothing here has to agree with them. The
//! fake-GLV addition checks and the hint's 64-bit bound are the remaining
//! completeness limits.

use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, Scalar, U256};
use std::collections::HashMap;

/// Number of 64-bit limbs a 256-bit value is split into for the circuit.
pub const LIMBS: usize = 4;

/// Everything the circuit reads, which after the witness values moved into the
/// circuit is exactly the public part of a signature: `r`, `s`, `msghash` and
/// the public key.
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

/// Big-endian 32 bytes to the circuit's four 64-bit limbs, least significant
/// first, as decimal strings — the encoding `circom-ecdsa` uses.
fn to_limbs(bytes: &[u8]) -> Vec<String> {
    let words = U256::from_be_slice(bytes).to_words();
    debug_assert_eq!(words.len(), LIMBS);
    words.iter().map(|w| w.to_string()).collect()
}

pub(crate) fn limbs_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::json!(to_limbs(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::point::AffineCoordinates;
    use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use k256::{AffinePoint, EncodedPoint, ProjectivePoint};
    use num_bigint::BigInt;

    /// Recompute the ECDSA witness values used by the reference vectors.
    struct ReferenceValues {
        sinv: Vec<String>,
        r_y: Vec<String>,
    }

    fn reference_values(
        digest: &[u8],
        pub_key_x: &[u8],
        pub_key_y: &[u8],
        signature: &[u8],
    ) -> ReferenceValues {
        let (r_bytes, s_bytes) = signature.split_at(32);
        let s = scalar_from_bytes(s_bytes);
        let h = <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(digest));

        let pubkey = affine_from_coordinates(pub_key_x, pub_key_y);

        let sinv = Option::<Scalar>::from(s.invert()).expect("s is non-zero for a valid signature");
        let u1 = h * sinv;
        let u2 = scalar_from_bytes(r_bytes) * sinv;

        // R is recomputed rather than recovered. The circuit witnesses the same
        // point, checks it on-curve, and constrains R.x mod n to public r.
        let big_r =
            (ProjectivePoint::GENERATOR * u1 + ProjectivePoint::from(pubkey) * u2).to_affine();
        assert_ne!(big_r, AffinePoint::IDENTITY, "R must not be the identity");
        let encoded_r = big_r.to_encoded_point(false);
        let r_y = encoded_r.y().expect("R is not the identity").to_vec();
        let reduced_r_x =
            <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(big_r.x().as_slice()));
        assert_eq!(
            reduced_r_x.to_bytes().as_slice(),
            r_bytes,
            "R.x mod n must equal r"
        );

        ReferenceValues {
            sinv: to_limbs(&sinv.to_bytes()),
            r_y: to_limbs(&r_y),
        }
    }

    fn affine_from_coordinates(x: &[u8], y: &[u8]) -> AffinePoint {
        let encoded = EncodedPoint::from_affine_coordinates(
            FieldBytes::from_slice(x),
            FieldBytes::from_slice(y),
            false,
        );
        Option::from(AffinePoint::from_encoded_point(&encoded)).expect("public key is on the curve")
    }

    /// Case 0 from the phase-3 reference vectors, produced by the JavaScript
    /// reference implementation. The derived values must match these constants.
    const R: &str = "96791156512790716983420836554981361349633210393766748359174448225512580277889";
    const S: &str = "33203354763501292305393002586333292996477110501749449198087039140030956875352";
    const MSGHASH: &str =
        "115036409922160129120102340064964763318413243106689753485336434403599877394652";
    const PUBKEY_X: &str =
        "63737832037230298197813806405409247279633802592228276503012513604051759695990";
    const PUBKEY_Y: &str =
        "7071887374780549439636777590279604435986066643851367285439908248767331831345";
    const EXPECTED_SINV: [&str; 4] = [
        "17727830181370692433",
        "13971681926046695686",
        "418281532449457824",
        "14210140541796473370",
    ];
    const EXPECTED_RY: [&str; 4] = [
        "1365492518906797085",
        "12802732031621248931",
        "11291563637012021028",
        "9388996153046433210",
    ];
    fn be_bytes(decimal: &str) -> Vec<u8> {
        let value = BigInt::parse_bytes(decimal.as_bytes(), 10).unwrap();
        let (_, mut bytes) = value.to_bytes_be();
        while bytes.len() < 32 {
            bytes.insert(0, 0);
        }
        bytes
    }

    fn field(inputs: &HashMap<String, serde_json::Value>, key: &str) -> Vec<String> {
        serde_json::from_value(inputs[key].clone()).unwrap()
    }

    fn reference_signature() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut signature = be_bytes(R);
        signature.extend(be_bytes(S));
        (
            be_bytes(MSGHASH),
            be_bytes(PUBKEY_X),
            be_bytes(PUBKEY_Y),
            signature,
        )
    }

    #[test]
    fn input_carries_only_the_public_part() {
        let (digest, x, y, signature) = reference_signature();
        let inputs = build_circuit_input(&digest, &x, &y, &signature);

        let mut keys: Vec<&String> = inputs.keys().collect();
        keys.sort();
        assert_eq!(keys, ["msghash", "pubkey", "r", "s"]);
    }

    #[test]
    fn input_preserves_the_full_prehash() {
        let (_, x, y, signature) = reference_signature();
        let inputs = build_circuit_input(&[0xff; 32], &x, &y, &signature);

        assert_eq!(field(&inputs, "msghash"), vec![u64::MAX.to_string(); 4]);
    }

    #[test]
    fn matches_the_javascript_witness() {
        let (digest, x, y, signature) = reference_signature();
        let values = reference_values(&digest, &x, &y, &signature);

        assert_eq!(values.sinv, EXPECTED_SINV);
        assert_eq!(values.r_y, EXPECTED_RY);
    }

    #[test]
    fn limbs_are_little_endian() {
        // 2^64 + 5 -> [5, 1, 0, 0]
        let mut bytes = vec![0u8; 32];
        bytes[31] = 5;
        bytes[23] = 1;
        assert_eq!(to_limbs(&bytes), vec!["5", "1", "0", "0"]);
    }

    /// Check the shared benchmark input against the reference ECDSA relation.
    /// This does not run the generated witness calculator, so it does not cover
    /// the Circom Eisenstein search or the fake-GLV loop's exceptional additions.
    #[test]
    fn benchmark_input_matches_reference_relation() {
        let (digest, (x, y), signature) = utils::generate_ecdsa_k256_input();
        reference_values(&digest, &x, &y, &signature);

        let inputs = build_circuit_input(&digest, &x, &y, &signature);
        for key in ["r", "s", "msghash"] {
            assert_eq!(field(&inputs, key).len(), LIMBS, "{key}");
        }
    }
}

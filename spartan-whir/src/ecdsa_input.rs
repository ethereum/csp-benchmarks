use p3_field::PrimeCharacteristicRing;
use spartan_whir::engine::F;

/// Encodes the shared ECDSA workload: public prehash and public key, followed by
/// the private signature. Every 256-bit integer uses little-endian byte limbs.
pub fn input(p256: bool) -> (Vec<u8>, Vec<F>) {
    let (digest, (x, y), signature) = if p256 {
        utils::generate_ecdsa_input()
    } else {
        utils::generate_ecdsa_k256_input()
    };
    encode(&digest, &x, &y, &signature)
}

pub fn encode(digest: &[u8], x: &[u8], y: &[u8], signature: &[u8]) -> (Vec<u8>, Vec<F>) {
    assert_eq!(digest.len(), 32);
    assert_eq!(x.len(), 32);
    assert_eq!(y.len(), 32);
    assert_eq!(signature.len(), 64);
    let public: Vec<u8> = digest
        .iter()
        .rev()
        .chain(x.iter().rev())
        .chain(y.iter().rev())
        .copied()
        .collect();
    let public_inputs = public.iter().map(|&byte| F::from_u8(byte)).collect();
    let raw = public
        .into_iter()
        .chain(signature[..32].iter().rev().copied())
        .chain(signature[32..].iter().rev().copied())
        .flat_map(|byte| u32::from(byte).to_le_bytes())
        .collect();
    (raw, public_inputs)
}

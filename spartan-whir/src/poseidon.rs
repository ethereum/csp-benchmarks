use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::default_koalabear_poseidon1_16;
use p3_symmetric::{CryptographicHasher, Increment, Pad10Sponge};
use spartan_whir::engine::F;

/// KoalaBear Poseidon1 uses a width-16 state with eight-element rate,
/// capacity, and digest. Pad10Sponge applies its native field-element padding.
pub fn input(input_size: usize) -> (Vec<u8>, Vec<F>) {
    assert!(
        [2, 4, 8, 12, 16].contains(&input_size),
        "unsupported Poseidon input size: {input_size}"
    );
    let message = utils::generate_poseidon_input(input_size)
        .iter()
        .map(|bytes| {
            bytes.iter().rev().fold(F::ZERO, |value, &byte| {
                value * F::from_u32(256) + F::from_u8(byte)
            })
        })
        .collect::<Vec<_>>();
    let sponge = Pad10Sponge::<F, _, _, 16, 8, 8>::new(
        default_koalabear_poseidon1_16(),
        Increment::new(F::ONE),
    );
    let digest = sponge.hash_iter(message.iter().copied()).to_vec();
    // The linked generator reads public digest fields before private inputs.
    let binary = digest
        .iter()
        .chain(&message)
        .flat_map(|value| value.as_canonical_u32().to_le_bytes())
        .collect();
    (binary, digest)
}

//! Fixed-size secp256k1 ECDSA benchmark circuit.

use num::{BigUint, One};
use plonky2::{
    field::{secp256k1_base::Secp256K1Base, secp256k1_scalar::Secp256K1Scalar, types::PrimeField},
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use plonky2_ecdsa::{
    curve::secp256k1::Secp256K1,
    gadgets::{
        biguint::{BigUintTarget, CircuitBuilderBiguint, WitnessBigUint},
        curve::CircuitBuilderCurve,
        ecdsa::{ECDSAPublicKeyTarget, ECDSASignatureTarget, verify_message_circuit},
        nonnative::CircuitBuilderNonNative,
    },
    serialization::{EcdsaGateSerializer, EcdsaGeneratorSerializer},
};
use plonky2_u32::gadgets::range_check::range_check_u32_circuit;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub struct PreparedEcdsa {
    pub data: CircuitData<F, C, D>,
    pub witness: PartialWitness<F>,
    pub num_gates: usize,
    #[cfg(test)]
    targets: EcdsaTargets,
}

#[cfg(test)]
struct EcdsaTargets {
    digest: BigUintTarget,
    public_key_x: BigUintTarget,
    public_key_y: BigUintTarget,
    r: BigUintTarget,
    s: BigUintTarget,
}

pub fn prepare(input_size: usize) -> PreparedEcdsa {
    assert_eq!(input_size, 32, "ECDSA uses a 32-byte prehash");
    let (digest, (public_key_x, public_key_y), signature) = utils::generate_ecdsa_k256_input();

    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true;
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut witness = PartialWitness::new();

    let digest_target = builder.add_virtual_biguint_target(8);
    constrain_u256(&mut builder, &digest_target);
    register_public(&mut builder, &digest_target);
    witness.set_biguint_target(&digest_target, &BigUint::from_bytes_be(&digest));
    let message = builder.reduce::<Secp256K1Scalar>(&digest_target);

    let public_key = builder.add_virtual_affine_point_target::<Secp256K1>();
    let public_key_x_target = builder.nonnative_to_canonical_biguint(&public_key.x);
    let public_key_y_target = builder.nonnative_to_canonical_biguint(&public_key.y);
    constrain_canonical::<Secp256K1Base>(&mut builder, &public_key_x_target);
    constrain_canonical::<Secp256K1Base>(&mut builder, &public_key_y_target);
    register_public(&mut builder, &public_key_x_target);
    register_public(&mut builder, &public_key_y_target);
    witness.set_biguint_target(&public_key_x_target, &BigUint::from_bytes_be(&public_key_x));
    witness.set_biguint_target(&public_key_y_target, &BigUint::from_bytes_be(&public_key_y));

    let r = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
    let s = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
    let r_target = builder.nonnative_to_canonical_biguint(&r);
    let s_target = builder.nonnative_to_canonical_biguint(&s);
    constrain_canonical::<Secp256K1Scalar>(&mut builder, &r_target);
    constrain_canonical::<Secp256K1Scalar>(&mut builder, &s_target);
    constrain_nonzero(&mut builder, &r_target);
    constrain_nonzero(&mut builder, &s_target);
    witness.set_biguint_target(&r_target, &BigUint::from_bytes_be(&signature[..32]));
    witness.set_biguint_target(&s_target, &BigUint::from_bytes_be(&signature[32..]));

    verify_message_circuit(
        &mut builder,
        message,
        ECDSASignatureTarget { r, s },
        ECDSAPublicKeyTarget(public_key),
    );

    let num_gates = builder.num_gates();
    PreparedEcdsa {
        data: builder.build::<C>(),
        witness,
        num_gates,
        #[cfg(test)]
        targets: EcdsaTargets {
            digest: digest_target,
            public_key_x: public_key_x_target,
            public_key_y: public_key_y_target,
            r: r_target,
            s: s_target,
        },
    }
}

fn constrain_u256(builder: &mut CircuitBuilder<F, D>, value: &BigUintTarget) {
    range_check_u32_circuit(builder, value.limbs.clone());
}

fn constrain_canonical<FF: PrimeField>(builder: &mut CircuitBuilder<F, D>, value: &BigUintTarget) {
    constrain_u256(builder, value);
    let max = builder.constant_biguint(&(FF::order() - BigUint::one()));
    let is_canonical = builder.cmp_biguint(value, &max);
    builder.assert_one(is_canonical.target);
}

fn constrain_nonzero(builder: &mut CircuitBuilder<F, D>, value: &BigUintTarget) {
    let one = builder.constant_biguint(&BigUint::one());
    let is_nonzero = builder.cmp_biguint(&one, value);
    builder.assert_one(is_nonzero.target);
}

fn register_public(builder: &mut CircuitBuilder<F, D>, value: &BigUintTarget) {
    builder.register_public_inputs(&value.limbs.iter().map(|limb| limb.0).collect::<Vec<_>>());
}

pub fn prove(prepared: &PreparedEcdsa) -> plonky2::plonk::proof::ProofWithPublicInputs<F, C, D> {
    prepared.data.prove(prepared.witness.clone()).unwrap()
}

pub fn verify(
    prepared: &PreparedEcdsa,
    proof: &plonky2::plonk::proof::ProofWithPublicInputs<F, C, D>,
) {
    prepared.data.verify(proof.clone()).unwrap();
}

pub fn preprocessing_size(prepared: &PreparedEcdsa) -> usize {
    let gates = EcdsaGateSerializer;
    let generators = EcdsaGeneratorSerializer::<C, D>::default();
    prepared.data.common.to_bytes(&gates).unwrap().len()
        + prepared
            .data
            .prover_only
            .to_bytes(&generators, &prepared.data.common)
            .unwrap()
            .len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

    fn fixture_witness(targets: &EcdsaTargets, digest: &[u8]) -> PartialWitness<F> {
        let (_, (public_key_x, public_key_y), signature) = utils::generate_ecdsa_k256_input();
        let mut witness = PartialWitness::new();
        witness.set_biguint_target(&targets.digest, &BigUint::from_bytes_be(digest));
        witness.set_biguint_target(
            &targets.public_key_x,
            &BigUint::from_bytes_be(&public_key_x),
        );
        witness.set_biguint_target(
            &targets.public_key_y,
            &BigUint::from_bytes_be(&public_key_y),
        );
        witness.set_biguint_target(&targets.r, &BigUint::from_bytes_be(&signature[..32]));
        witness.set_biguint_target(&targets.s, &BigUint::from_bytes_be(&signature[32..]));
        witness
    }

    #[test]
    fn ecdsa_circuit_serialization_round_trip() {
        let PreparedEcdsa { data, .. } = prepare(32);
        let gates = EcdsaGateSerializer;
        let generators = EcdsaGeneratorSerializer::<C, D>::default();
        assert_eq!(data.common.num_public_inputs, 24);
        let bytes = data.to_bytes(&gates, &generators).unwrap();
        drop(data);
        let restored =
            CircuitData::<GoldilocksField, C, D>::from_bytes(&bytes, &gates, &generators).unwrap();
        assert_eq!(restored.to_bytes(&gates, &generators).unwrap(), bytes);
    }

    #[test]
    #[ignore = "requires benchmark-class memory"]
    fn ecdsa_circuit_proves_and_rejects_invalid_inputs() {
        let PreparedEcdsa {
            data,
            witness,
            targets,
            ..
        } = prepare(32);

        let proof = data.prove(witness.clone()).unwrap();
        data.verify(proof.clone()).unwrap();

        let mut altered = proof;
        altered.public_inputs[0] += GoldilocksField::ONE;
        assert!(data.verify(altered).is_err());

        let (mut invalid_digest, _, _) = utils::generate_ecdsa_k256_input();
        invalid_digest[0] ^= 1;
        if let Ok(invalid_proof) = data.prove(fixture_witness(&targets, &invalid_digest)) {
            assert!(data.verify(invalid_proof).is_err());
        }
    }
}

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    field::types::Field,
    hash::poseidon::PoseidonHash,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
    util::serialization::Write,
};

use crate::keccak256::circuit::{array_to_bits_lsb, keccak256_circuit};
use crate::sha256::circuit::{array_to_bits, make_circuits};
use plonky2_u32::gates::arithmetic_u32::{U32GateSerializer, U32GeneratorSerializer};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
pub type Prepared = (CircuitData<F, C, D>, PartialWitness<F>, usize, Vec<F>);

pub fn verify(data: &VerifierCircuitData<F, C, D>, proof: ProofWithPublicInputs<F, C, D>) {
    data.verify(proof).unwrap()
}

pub fn prove(
    data: &CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    pw: PartialWitness<F>,
) -> ProofWithPublicInputs<GoldilocksField, C, D> {
    data.prove(pw).unwrap()
}

pub fn sha256_prepare(input_size: usize) -> Prepared {
    let (msg, hash) = utils::generate_sha256_input(input_size);

    let msg_bits = array_to_bits(&msg);
    let len = msg.len() * 8;
    println!("block count: {}", (len + 65).div_ceil(512));
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
    let targets = make_circuits(&mut builder, len as u64);
    let mut pw = PartialWitness::new();

    for (i, msg_bit) in msg_bits.iter().enumerate().take(len) {
        pw.set_bool_target(targets.message[i], *msg_bit).unwrap();
    }

    let expected_res = array_to_bits(hash.as_slice());
    let digest_targets: Vec<_> = targets.digest.iter().map(|bit| bit.target).collect();
    builder.register_public_inputs(&digest_targets);
    let expected_public_inputs = expected_res
        .iter()
        .map(|bit| F::from_canonical_u64(u64::from(*bit)))
        .collect::<Vec<_>>();

    let n_gates = builder.num_gates();
    let circuit_data = builder.build::<C>();
    assert_eq!(
        circuit_data.common.num_public_inputs,
        expected_public_inputs.len()
    );
    (circuit_data, pw, n_gates, expected_public_inputs)
}

pub fn poseidon_prepare(input_size: usize) -> Prepared {
    let inputs = utils::generate_poseidon_input_goldilocks(input_size);
    let input_fields: Vec<_> = inputs
        .iter()
        .map(|input| F::from_canonical_u64(*input))
        .collect();
    let expected_public_inputs = PoseidonHash::hash_no_pad(&input_fields).to_vec();
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());

    let input_targets: Vec<_> = (0..input_size)
        .map(|_| builder.add_virtual_target())
        .collect();

    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input_targets.clone());
    builder.register_public_inputs(&hash_out.elements);

    let mut pw = PartialWitness::new();
    for (i, target) in input_targets.iter().enumerate() {
        pw.set_target(*target, input_fields[i]).unwrap();
    }

    let n_gates = builder.num_gates();
    let circuit_data = builder.build::<C>();
    assert_eq!(
        circuit_data.common.num_public_inputs,
        expected_public_inputs.len()
    );
    (circuit_data, pw, n_gates, expected_public_inputs)
}

pub fn keccak256_prepare(input_size: usize) -> Prepared {
    let (msg, hash) = utils::generate_keccak_input(input_size);

    let msg_bits = array_to_bits_lsb(&msg);
    let len = msg.len() * 8;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());

    let mut input_targets = vec![];
    for _ in 0..len {
        input_targets.push(builder.add_virtual_bool_target_safe());
    }

    let targets = keccak256_circuit(input_targets.clone(), &mut builder);
    let mut pw = PartialWitness::new();

    for (i, msg_bit) in msg_bits.iter().enumerate().take(len) {
        pw.set_bool_target(input_targets[i], *msg_bit).unwrap();
    }

    let expected_res = array_to_bits_lsb(hash.as_slice());
    let digest_targets: Vec<_> = targets.iter().map(|bit| bit.target).collect();
    builder.register_public_inputs(&digest_targets);
    let expected_public_inputs = expected_res
        .iter()
        .map(|bit| F::from_canonical_u64(u64::from(*bit)))
        .collect::<Vec<_>>();

    let n_gates = builder.num_gates();
    let circuit_data = builder.build::<C>();
    assert_eq!(
        circuit_data.common.num_public_inputs,
        expected_public_inputs.len()
    );
    (circuit_data, pw, n_gates, expected_public_inputs)
}

pub fn compute_u32_preprocessing_size(circuit_data: &CircuitData<F, C, D>) -> usize {
    let gate_serializer = U32GateSerializer;
    let common_data_size = circuit_data
        .common
        .to_bytes(&gate_serializer)
        .unwrap()
        .len();
    let generator_serializer = U32GeneratorSerializer::<C, D>::default();
    let prover_data_size = circuit_data
        .prover_only
        .to_bytes(&generator_serializer, &circuit_data.common)
        .unwrap()
        .len();
    prover_data_size + common_data_size
}

pub fn verify_proof(
    (circuit_data, _pw, _, expected_public_inputs): &Prepared,
    proof: &ProofWithPublicInputs<GoldilocksField, C, D>,
) {
    assert_eq!(
        proof.public_inputs, *expected_public_inputs,
        "digest mismatch"
    );
    let verifier_data = circuit_data.verifier_data();
    verify(&verifier_data, proof.clone());
}

pub fn compute_proof_size(proof: &ProofWithPublicInputs<GoldilocksField, C, D>) -> usize {
    let mut buffer = Vec::new();
    buffer.write_proof(&proof.proof).unwrap();
    buffer.len()
}

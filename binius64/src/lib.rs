use std::borrow::Cow;

use anyhow::Result;
use binius_core::{Word, constraint_system::ConstraintSystem};
use binius_frontend::{Circuit, CircuitBuilder};
use binius_hash::StdHashSuite;
use binius_prover::zk_config::ZKProver;
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{config::StdChallenger, zk_config::ZKVerifier};
use utils::harness::{AuditStatus, BenchProperties};

use crate::circuit_utils::{CircuitTrait, StdProver, StdVerifier};

pub mod circuit_utils;
pub mod circuits;

pub const BINIUS64_BENCH_PROPERTIES: BenchProperties = BenchProperties {
    proving_system: Cow::Borrowed("Binius64"),
    field_curve: Cow::Borrowed("F2^128"),
    iop: Cow::Borrowed("Binius64 + Spartan"),
    pcs: Some(Cow::Borrowed("BaseFold")),
    arithm: Cow::Borrowed("Binius64"),
    is_zk: true, // Exact benchmark path uses upstream ZKProver/ZKVerifier.
    is_zkvm: false,
    // Upstream Binius and Spartan ZK verifier paths both set SECURITY_BITS = 96.
    security_bits: 96,
    is_pq: true, // BaseFold with hash-based Merkle commitments.
    is_maintained: true,
    is_audited: AuditStatus::NotAudited,
    isa: None,
};

/// Setup the ZK prover and verifier and use SHA256 for Merkle tree compression.
fn setup(cs: ConstraintSystem, log_inv_rate: usize) -> Result<(StdVerifier, StdProver)> {
    let verifier = ZKVerifier::<StdHashSuite>::setup(cs, log_inv_rate)?;
    let prover = ZKProver::setup(&verifier)?;
    Ok((verifier, prover))
}

// Use the default configs/params
pub fn prepare<CT: CircuitTrait>(
    input_size: usize,
    params: CT::Params,
) -> Result<(StdVerifier, StdProver, ConstraintSystem, CT, Circuit, usize)> {
    // Extract common arguments
    let log_inv_rate = 1;

    // Build the circuit
    let mut builder = CircuitBuilder::new();

    let circuit = CT::build(params, &mut builder)?;
    let compiled_circuit = builder.build();

    // Set up prover and verifier
    let cs = compiled_circuit.constraint_system().clone();

    // Using SHA256 compression for Merkle tree
    let (verifier, prover) = setup(cs.clone(), log_inv_rate as usize)?;
    Ok((verifier, prover, cs, circuit, compiled_circuit, input_size))
}

pub fn prove<CT: CircuitTrait>(
    prover: &StdProver,
    compiled_circuit: &Circuit,
    circuit: &CT,
    instance: CT::Instance,
) -> Result<(Vec<u8>, Vec<Word>)> {
    // Population of the input to the witness and then evaluating the circuit.
    let mut filler = compiled_circuit.new_witness_filler();
    circuit.populate_witness(instance, &mut filler)?; // input population
    compiled_circuit.populate_wire_witness(&mut filler)?; // circuit evaluation
    let witness = filler.into_value_vec();

    let pub_witness = witness.inout().to_vec();

    // Prove
    let challenger = StdChallenger::default();
    let mut prover_transcript = ProverTranscript::new(challenger);
    let mut rng = rand::rng();
    prover.prove(&witness, &mut rng, &mut prover_transcript)?;

    let proof = prover_transcript.finalize();

    Ok((proof, pub_witness))
}

pub fn verify(verifier: &StdVerifier, pub_witness: &[Word], proof: &[u8]) -> Result<()> {
    let challenger = StdChallenger::default();
    let mut verifier_transcript = VerifierTranscript::new(challenger, proof.to_vec());
    verifier.verify(pub_witness, &mut verifier_transcript)?;
    verifier_transcript.finalize()?;

    Ok(())
}

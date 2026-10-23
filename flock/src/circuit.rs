use std::any::Any;

use flock_hash::HashKind;
use flock_prover::challenger::FsChallenger;
use flock_prover::circuit::builder::{CircuitShape, CircuitWitness, GateType, SlotId};
use flock_prover::field::F128;
use flock_prover::lincheck::LincheckCircuit;
use flock_prover::pcs::{
    Commitment, PcsParams,
    ligerito::{LigeritoProfile, embedded_initial_k},
};
use flock_prover::prover::UnionSlotProverInput;
use flock_prover::r1cs::{BlockR1cs, SparseBinaryMatrix, WitnessLayout};
use flock_prover::union::UnionInstance;
use flock_prover::verifier::FlockVerifyError;
use serde::Serialize;

#[cfg(not(target_arch = "aarch64"))]
use flock_prover::{
    proof::R1csProofCircuitMerged as BackendProof,
    prover::prove_fast_ligerito_union_circuit as prove_circuit,
    verifier::verify_ligerito_union_circuit as verify_circuit,
};
#[cfg(target_arch = "aarch64")]
use flock_prover::{
    proof::R1csProofCircuitMergedAg as BackendProof,
    prover::prove_fast_ligerito_union_circuit_ag as prove_circuit,
    verifier::verify_ligerito_union_circuit_ag as verify_circuit,
};

pub(crate) type WitnessBuffers = (Vec<F128>, Vec<F128>, Vec<F128>, Vec<u8>);

pub(crate) struct CircuitSetup<G: GateType> {
    pub(crate) shape: CircuitShape,
    pub(crate) slots: Vec<(SlotId, BlockR1cs)>,
    pub(crate) nu: usize,
    pub(crate) inputs: Vec<F128>,
    pub(crate) hints: Vec<G::Hint>,
    pub(crate) public: Vec<F128>,
    generate: fn(&[G::Row], usize) -> WitnessBuffers,
    pcs_params: PcsParams,
}

#[derive(Clone, Serialize)]
pub(crate) struct CircuitProof {
    pub(crate) proof: BackendProof,
    pub(crate) commitment: Commitment,
}

impl<G> CircuitSetup<G>
where
    G: GateType + 'static,
    G::Row: 'static,
    G::Hint: Any + Sync,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        shape: CircuitShape,
        mut slots: Vec<(SlotId, BlockR1cs)>,
        nu: usize,
        inputs: Vec<F128>,
        hints: Vec<G::Hint>,
        public: Vec<F128>,
        generate: fn(&[G::Row], usize) -> WitnessBuffers,
    ) -> Self {
        assert!(shape.circuit.check_public(&public));
        assert!(public.len() >= 2);
        slots.sort_by_key(|(slot, _)| shape.registry_slot(*slot));
        for (_, r1cs) in &mut slots {
            r1cs.layout = WitnessLayout::BatchMajor;
            r1cs.csc_lincheck_circuit();
        }

        let union = UnionInstance::new(&shape.registry, shape.counts.clone());
        let profile = LigeritoProfile::Fast;
        let m = union.dense_m();
        let log_batch_size = embedded_initial_k(m, profile)
            .expect("Flock hash circuit must fit a published Ligerito configuration");
        let pcs_params = PcsParams {
            m,
            log_inv_rate: profile.log_inv_rate(),
            log_batch_size,
            profile,
            num_lanes: union.commit_lanes(log_batch_size),
            merkle_hash: HashKind::Blake3,
        };
        pcs_params
            .ligerito_prover_config()
            .expect("Flock proving parameters must match the published profile");
        pcs_params
            .ligerito_verifier_config()
            .expect("Flock verification parameters must match the published profile");
        // These are circuit-specific public preprocessing, excluded from proving.
        shape.registry.digest();
        shape.circuit.digest();

        Self {
            shape,
            slots,
            nu,
            inputs,
            hints,
            public,
            generate,
            pcs_params,
        }
    }

    fn witness(&self) -> CircuitWitness {
        let hints: Vec<&(dyn Any + Sync)> = self
            .hints
            .iter()
            .map(|hint| hint as &(dyn Any + Sync))
            .collect();
        self.shape.run(&self.inputs, &hints)
    }

    pub(crate) fn prove(&self, domain: &[u8]) -> CircuitProof {
        let witness = self.witness();
        assert_eq!(witness.public, self.public, "unexpected full-hash digest");
        let union = UnionInstance::new(&self.shape.registry, self.shape.counts.clone());
        let slots = self
            .slots
            .iter()
            .map(|(slot, r1cs)| {
                UnionSlotProverInput::new(
                    (self.generate)(witness.rows::<G>(*slot), self.nu),
                    r1cs.csc_lincheck_circuit(),
                )
            })
            .collect();
        let mut challenger = FsChallenger::with_hash(domain, HashKind::Blake3);
        let (proof, commitment, _) = prove_circuit(
            &union,
            &self.shape.circuit,
            &self.public,
            &self.pcs_params,
            slots,
            Vec::new(),
            &mut challenger,
        );
        CircuitProof { proof, commitment }
    }

    pub(crate) fn verify(
        &self,
        proof: &CircuitProof,
        domain: &[u8],
    ) -> Result<(), FlockVerifyError> {
        let union = UnionInstance::new(&self.shape.registry, self.shape.counts.clone());
        let circuits: Vec<&dyn LincheckCircuit> = self
            .slots
            .iter()
            .map(|(_, r1cs)| r1cs.csc_lincheck_circuit() as &dyn LincheckCircuit)
            .collect();
        let mut challenger = FsChallenger::with_hash(domain, HashKind::Blake3);
        verify_circuit(
            &union,
            &self.shape.circuit,
            &self.public,
            &circuits,
            &proof.commitment,
            &proof.proof,
            &self.pcs_params,
            &mut challenger,
        )
        .map(|_| ())
    }

    pub(crate) fn num_constraints(&self) -> usize {
        self.shape
            .registry
            .types()
            .iter()
            .zip(&self.shape.counts)
            .map(|(table, count)| table.useful_bits * count)
            .sum()
    }

    pub(crate) fn preprocessing_size(&self) -> usize {
        let slots = self
            .slots
            .iter()
            .map(|(slot, r1cs)| {
                let table = &self.shape.registry.types()[self.shape.registry_slot(*slot)];
                SerializableBlockR1cs {
                    m: r1cs.m,
                    k_log: r1cs.k_log,
                    k_skip: r1cs.k_skip,
                    useful_bits: r1cs.useful_bits,
                    a_0: SerializableMatrix::from(&r1cs.a_0),
                    b_0: SerializableMatrix::from(&r1cs.b_0),
                    c_0: SerializableMatrix::from(&r1cs.c_0),
                    const_pin: r1cs.const_pin,
                    io_schema: table
                        .io_schema
                        .iter()
                        .map(|word| {
                            (
                                word.word_col,
                                matches!(word.dir, flock_prover::schedule::IoDirection::Out),
                            )
                        })
                        .collect(),
                }
            })
            .collect();
        // The wrappers publish fixed parameters first and the two digest words last.
        let fixed_public = self.public[..self.public.len() - 2]
            .iter()
            .map(|value| Some(*value))
            .chain([None, None])
            .collect();
        let artifact = PreprocessingArtifact {
            nu: self.nu,
            slots,
            counts: &self.shape.counts,
            fixed_public,
            wires: self.shape.circuit.wires(),
            registry_digest: self.shape.registry.digest(),
            circuit_digest: self.shape.circuit.digest(),
            pcs_params: &self.pcs_params,
        };
        bincode::serialized_size(&artifact)
            .expect("Flock preprocessing artifact must serialize")
            .try_into()
            .expect("Flock preprocessing artifact must fit usize")
    }
}

impl CircuitProof {
    pub(crate) fn proof_size(&self) -> usize {
        bincode::serialized_size(self)
            .expect("Flock circuit proof must serialize")
            .try_into()
            .expect("Flock circuit proof must fit usize")
    }
}

#[derive(Serialize)]
struct PreprocessingArtifact<'a> {
    nu: usize,
    slots: Vec<SerializableBlockR1cs<'a>>,
    counts: &'a [usize],
    fixed_public: Vec<Option<F128>>,
    wires: &'a [Vec<usize>],
    registry_digest: [u8; 32],
    circuit_digest: [u8; 32],
    pcs_params: &'a PcsParams,
}

#[derive(Serialize)]
struct SerializableBlockR1cs<'a> {
    m: usize,
    k_log: usize,
    k_skip: usize,
    useful_bits: usize,
    a_0: SerializableMatrix<'a>,
    b_0: SerializableMatrix<'a>,
    c_0: SerializableMatrix<'a>,
    const_pin: Option<usize>,
    io_schema: Vec<(usize, bool)>,
}

#[derive(Serialize)]
struct SerializableMatrix<'a> {
    num_rows: usize,
    num_cols: usize,
    rows: &'a [Vec<usize>],
}

impl<'a> From<&'a SparseBinaryMatrix> for SerializableMatrix<'a> {
    fn from(matrix: &'a SparseBinaryMatrix) -> Self {
        Self {
            num_rows: matrix.num_rows,
            num_cols: matrix.num_cols,
            rows: &matrix.rows,
        }
    }
}

pub(crate) fn pack4(words: [u32; 4]) -> F128 {
    F128::new(
        u64::from(words[0]) | (u64::from(words[1]) << 32),
        u64::from(words[2]) | (u64::from(words[3]) << 32),
    )
}

pub(crate) fn unpack4(value: F128) -> [u32; 4] {
    [
        value.lo as u32,
        (value.lo >> 32) as u32,
        value.hi as u32,
        (value.hi >> 32) as u32,
    ]
}

pub(crate) fn pack8(words: &[u32; 8]) -> [F128; 2] {
    [
        pack4(words[..4].try_into().unwrap()),
        pack4(words[4..].try_into().unwrap()),
    ]
}

pub(crate) fn unpack8(a: F128, b: F128) -> [u32; 8] {
    let a = unpack4(a);
    let b = unpack4(b);
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}

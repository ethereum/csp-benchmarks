use std::borrow::Cow;

use utils::harness::{AuditStatus, BenchProperties};

mod circuit;
mod full_blake3;
mod full_sha256;

const TRANSCRIPT_DOMAIN: &[u8] = b"csp-benchmarks-flock-hash-v1";
const SHA256_BLOCK_BYTES: usize = 64;
const SHA256_LEN_BYTES: usize = 8;
const BLAKE3_BLOCK_BYTES: usize = 64;
const BLAKE3_CHUNK_BYTES: usize = 1024;

pub const FLOCK_BENCH_PROPERTIES: BenchProperties = BenchProperties {
    proving_system: Cow::Borrowed("Flock"),
    field_curve: Cow::Borrowed("F2^128"),
    iop: Cow::Borrowed("Flock"),
    pcs: Some(Cow::Borrowed("Ligerito")),
    arithm: Cow::Borrowed("R1CS"),
    is_zk: false,
    is_zkvm: false,
    security_bits: 128,
    is_pq: true,
    is_maintained: true,
    is_audited: AuditStatus::NotAudited,
    isa: None,
};

pub struct PreparedSha256 {
    setup: full_sha256::FullSha256Setup,
}

pub struct Sha256Proof {
    proof: full_sha256::FullSha256Proof,
}

pub struct PreparedBlake3 {
    setup: full_blake3::FullBlake3Setup,
}

pub struct Blake3Proof {
    proof: full_blake3::FullBlake3Proof,
}

pub fn sha256_compression_count(input_size: usize) -> usize {
    (input_size + 1 + SHA256_LEN_BYTES).div_ceil(SHA256_BLOCK_BYTES)
}

pub fn sha256_operation_count(input_size: usize) -> usize {
    sha256_compression_count(input_size)
}

pub fn blake3_compression_count(input_size: usize) -> usize {
    assert!(
        input_size.is_multiple_of(BLAKE3_BLOCK_BYTES) && input_size <= 2 * BLAKE3_CHUNK_BYTES,
        "BLAKE3 benchmark supports full blocks through 2048 bytes"
    );
    input_size / BLAKE3_BLOCK_BYTES + usize::from(input_size > BLAKE3_CHUNK_BYTES)
}

pub fn blake3_operation_count(input_size: usize) -> usize {
    blake3_compression_count(input_size)
}

pub fn prepare_sha256(input_size: usize) -> PreparedSha256 {
    PreparedSha256 {
        setup: full_sha256::prepare(input_size),
    }
}

pub fn prove_sha256(prepared: &PreparedSha256) -> Sha256Proof {
    Sha256Proof {
        proof: full_sha256::prove(&prepared.setup, TRANSCRIPT_DOMAIN),
    }
}

pub fn verify_sha256(prepared: &PreparedSha256, proof: &Sha256Proof) {
    full_sha256::verify(&prepared.setup, &proof.proof, TRANSCRIPT_DOMAIN);
}

pub fn prepare_blake3(input_size: usize) -> PreparedBlake3 {
    PreparedBlake3 {
        setup: full_blake3::prepare(input_size),
    }
}

pub fn prove_blake3(prepared: &PreparedBlake3) -> Blake3Proof {
    Blake3Proof {
        proof: full_blake3::prove(&prepared.setup, TRANSCRIPT_DOMAIN),
    }
}

pub fn verify_blake3(prepared: &PreparedBlake3, proof: &Blake3Proof) {
    full_blake3::verify(&prepared.setup, &proof.proof, TRANSCRIPT_DOMAIN);
}

pub fn num_constraints_sha256(prepared: &PreparedSha256) -> usize {
    full_sha256::num_constraints(&prepared.setup)
}

pub fn num_constraints_blake3(prepared: &PreparedBlake3) -> usize {
    full_blake3::num_constraints(&prepared.setup)
}

pub fn preprocessing_size_sha256(prepared: &PreparedSha256) -> usize {
    full_sha256::preprocessing_size(&prepared.setup)
}

pub fn preprocessing_size_blake3(prepared: &PreparedBlake3) -> usize {
    full_blake3::preprocessing_size(&prepared.setup)
}

pub fn proof_size_sha256(proof: &Sha256Proof) -> usize {
    full_sha256::proof_size(&proof.proof)
}

pub fn proof_size_blake3(proof: &Blake3Proof) -> usize {
    full_blake3::proof_size(&proof.proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduced_sha256_roundtrip() {
        let prepared = prepare_sha256(128);
        let proof = prove_sha256(&prepared);
        verify_sha256(&prepared, &proof);
        assert!(proof_size_sha256(&proof) > 0);
        assert_eq!(prepared.setup.circuit.shape.counts[0], 3);
        assert!(preprocessing_size_sha256(&prepared) > 0);
    }

    #[test]
    fn reduced_blake3_roundtrip() {
        let prepared = prepare_blake3(128);
        let proof = prove_blake3(&prepared);
        verify_blake3(&prepared, &proof);
        assert!(proof_size_blake3(&proof) > 0);
        assert_eq!(prepared.setup.circuit.shape.counts[0], 2);
        assert!(preprocessing_size_blake3(&prepared) > 0);
    }

    #[test]
    fn blake3_two_chunk_roundtrip() {
        let prepared = prepare_blake3(2048);
        let proof = prove_blake3(&prepared);
        verify_blake3(&prepared, &proof);
        assert_eq!(prepared.setup.circuit.shape.counts[0], 33);
    }

    #[test]
    fn byte_size_maps_to_hash_operations() {
        assert_eq!(sha256_compression_count(128), 3);
        assert_eq!(sha256_compression_count(2048), 33);
        assert_eq!(blake3_compression_count(128), 2);
        assert_eq!(blake3_compression_count(1024), 16);
        assert_eq!(blake3_compression_count(2048), 33);
    }
}

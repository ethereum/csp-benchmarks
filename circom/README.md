# Circom benchmarks

This benchmark code is from: https://github.com/brevis-network/zk-benchmark/tree/main/circom

## Hash circuits

SHA-256 and Keccak-256 take message bytes as `in[N]`, digest bytes as `hash[32]`, and expose `out[32]`, constrained equal to `hash`. Message bytes are range checked inside the circuits. No auxiliary inputs are required.

The implementations adapt these verified zk.golf submissions:

- [SHA-256](https://zk.golf/api/submissions/75f88d68-6cae-4acf-8adc-7d41bce17042/download): single-row XOR3 and majority identities, and combined round additions. Each word reduction constrains the result and carry bits.
- [Keccak-f1600](https://zk.golf/api/submissions/5bdce6d5-90a2-4208-bee3-0924b20ccb3b/download): two XOR3 operations for column parity, one XOR3 for each theta output, and one constraint per chi output. The byte wrapper implements the Keccak-256 sponge with a 136-byte rate and `0x01` padding suffix.

The Circom ports are checked against Node's SHA-256 and `js-sha3`'s Keccak-256, with witness checks against the compiled R1CS. The Lean proofs apply to the original submissions.

Circom 2.2.3 with `--O2` produces these constraint counts:

| Message bytes | SHA-256 | Keccak-256 |
| --- | ---: | ---: |
| 128 | 53,048 | 93,184 |
| 256 | 89,224 | 187,328 |
| 512 | 161,576 | 375,744 |
| 1024 | 306,280 | 752,576 |
| 2048 | 595,688 | 1,506,240 |

### Compile and check

With Circom 2.2.3 and SnarkJS 0.7.5 installed, run from the repository root:

```bash
artifacts="$PWD/target/circom-hashes"
for algorithm in sha256 keccak; do
  for size in 128 256 512 1024 2048; do
    name="${algorithm}_${size}"
    mkdir -p "$artifacts/$name"
    circom "circom/circuits/$algorithm/$name.circom" --O2 --r1cs --wasm --c -o "$artifacts/$name"
    node circom/tests/hash-circuits.cjs "$artifacts/$name"
  done
done
mkdir -p "$artifacts/bitwise"
circom circom/tests/bitwise.circom --O2 --r1cs --wasm -o "$artifacts/bitwise"
node circom/tests/hash-circuits.cjs "$artifacts/bitwise"
```

The tests compare three message patterns, reject incorrect digests and invalid bytes, and check that forged output witnesses fail the R1CS. The bitwise tests cover all eight Boolean input combinations and check output uniqueness.

Generate each Groth16 zkey from the corresponding `.r1cs` and copy its generated `.cpp` and `.dat` together. The largest circuit requires a prepared setup file with at least 2^21 points, available from [PSE's Powers of Tau ceremony](https://github.com/privacy-ethereum/perpetualpowersoftau#prepared-phase-2-files). The hash and ECDSA zkeys and `checksums.sha256` must be published together in the release selected by CI.

For the 2,048-byte Keccak setup, run SnarkJS with `NODE_OPTIONS=--max-old-space-size=16384` to allow a 16 GiB JavaScript heap.

## Prerequisites

Use the same toolchain as `.github/workflows/rust_benchmarks_parallel.yml`:

```bash
rustup toolchain install nightly-2025-08-18-aarch64-apple-darwin \
  --component llvm-tools rustc-dev
rustup override set nightly-2025-08-18-aarch64-apple-darwin
```

The ECDSA circuit also needs [circom](https://github.com/iden3/circom) 2.2.3 on PATH. Its witness
generator is 57 MiB of generated C++ — roughly three times the largest artifact stored here — so
`build.rs` compiles it from `ecdsa_32.circom` on demand rather than keeping it in the repo. Every
other circuit ships its `.cpp` and `.dat` in tree and needs nothing installed. The first build
after a clean checkout spends about five minutes in circom before the C++ compile starts.

The secp256r1 (P-256) ECDSA circuit, `ecdsa_p256_32`, is built the same way, so a clean build
compiles both generators. Its benchmark needs the `circom-ecdsa-p256-bench` feature.

## Run the benchmarks

The default benchmarks include SHA-256, Keccak-256, Poseidon, and secp256k1 ECDSA.

From `circom/`, download the keys listed in the checksum manifest:

```bash
release=https://github.com/privacy-ethereum/csp-benchmarks/releases/download/zkeys-v2
while read -r checksum zkey; do
  mkdir -p "$(dirname "$zkey")"
  curl --fail --location --retry 3 "$release/$(basename "$zkey")" --output "$zkey"
done < checksums.sha256
shasum -a 256 --check checksums.sha256
```

```bash
cargo bench
```

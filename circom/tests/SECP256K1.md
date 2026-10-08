# secp256k1 ECDSA validation

## Caller preconditions

The public interface is `r[4]`, `s[4]`, `msghash[4]`, and `pubkey[2][4]`, using little-endian 64-bit limbs. The circuit validates the finite public key, reduces the prehash modulo the group order, and constrains `R.x mod n = r` for a finite verification result. Fake-GLV decomposition values are derived during witness generation and constrained inside the circuit. Points are handled in eight 32-bit limbs per coordinate, converted at the boundary; scalars stay in 64-bit limbs.

`Secp256k1AddComplete` requires valid curve points with canonical 32-bit-limb coordinates when finite. `Secp256k1DoubleAddComplete`, the Straus step `2a + b`, takes an accumulator with a canonical x and a y in 32-bit limbs, and a canonical table entry; its output has the accumulator's form. Infinity is `(x,y,isInf) = (0,0,1)`. `GLV4StrausLoop` range-checks both coordinates of its bases, and the ECDSA circuit supplies finite bases on the curve.

## Regression commands

Run from the repository root with Circom 2.2.3, Node, SnarkJS 0.7.5, and Python with `cryptography`. The Node script uses an existing local or global SnarkJS installation.

```sh
mkdir -p target/k1-checks/ecdsa_32 target/k1-checks/point_ops target/k1-checks/straus
circom circom/circuits/ecdsa/ecdsa_32.circom --O2 --r1cs --wasm --sym -o target/k1-checks/ecdsa_32
circom circom/tests/secp256k1/point_ops.circom --O2 --r1cs --wasm --sym -o target/k1-checks/point_ops
circom circom/tests/secp256k1/straus.circom --O2 --r1cs --wasm --sym -o target/k1-checks/straus
python3 circom/tests/secp256k1-reference.py target/k1-checks/vectors.json
node circom/tests/secp256k1-circuits.cjs target/k1-checks target/k1-checks/vectors.json
```

The Python reference checks the Straus sentinel `D` and terminal constant `C`, reproduces the comb's final-doubling scalar by exhaustive search, checks the `(32, 8)` reduction table and the quotient, coefficient and register bounds of the modular checks against `secp256k1_utils32.circom`, and generates independently verified signatures and invalid inputs. The sentinel vectors use public keys and `S = [u2]Q` values that make table entries `T[1]`, `T[2]`, `T[3]`, `T[4]`, and `T[8]` a doubling or infinity; the Node test checks that each one reaches its entry. The Node tests check witnesses against the R1CS and reject mutations of outputs, selectors, infinity flags, signature inputs, slopes, and modular certificates. The Straus test constructs an infinity accumulator at three loop steps, followed by recovery to the finite terminal point.

## Validation boundaries

Groth16 proving, verification, and benchmark timings require a zkey matching the compiled circuit. The `ecdsa_32_0001.zkey` listed in `checksums.sha256` was generated for the previous circuit and does not match this one. The regressions provide executable coverage, not a formal proof of this Circom implementation.

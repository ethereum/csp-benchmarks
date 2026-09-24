pragma circom 2.0.2;

// Entry point for the ECDSA target on secp256r1 (P-256).
//
// The name carries the harness input size for ECDSA (32), because
// witnesscalc-adapter requires the directory, the .cpp and the .dat to share
// the circuit's name.
//
// Compiled with --O2: 685,914 nonlinear constraints, 685,914 total.

include "./ecdsa_p256_comb_verify.circom";

component main {public [r, s, msghash, pubkey]} = ECDSAP256CombVerify();

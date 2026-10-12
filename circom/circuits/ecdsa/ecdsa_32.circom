pragma circom 2.0.2;

// Entry point for the ECDSA target.
//
// The name is ecdsa_32 because the harness uses `input_size = 32` for ECDSA
// (utils/src/harness.rs: BenchTarget::Ecdsa => vec![32]), and
// witnesscalc-adapter requires the directory, the .cpp and the .dat to carry
// that same name.
//
// Compiled with Circom 2.2.3 --O2: 279,647 nonlinear constraints, 279,647 total.

include "./ecdsa4_comb_verify.circom";

component main {public [r, s, msghash, pubkey]} = ECDSA4CombVerify();

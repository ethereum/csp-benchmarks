pragma circom 2.0.0;

include "sha256_bits.circom";
include "../bits.circom";

/**
 * Wrapper around SHA256 to support bytes as input instead of bits
 * @param  N   The number of input bytes
 * @input  in  The input bytes
 * @output out The SHA256 output of the n input bytes, in bytes
 *
 * SOURCE: https://github.com/celer-network/zk-benchmark/blob/main/circom/circuits/sha256/sha256_bytes.circom
 */
template Sha256Bytes(N) {
  signal input in[N];
  signal output out[32];

  // convert input bytes to bits
  component byte_to_bits[N];
  for (var i = 0; i < N; i++) {
    byte_to_bits[i] = SmallNum2Bits(8);
    byte_to_bits[i].in <== in[i];
  }

  // sha256 over bits
  component sha256 = Sha256(N*8);
  for (var i = 0; i < N; i++) {
    for (var j = 0; j < 8; j++) {
      sha256.in[i*8+j] <== byte_to_bits[i].out[7-j];
    }
  }

  // convert output bytes to bits
  for (var i = 0; i < 32; i++) {
    var byte = 0;
    for (var j = 0; j < 8; j++) byte += sha256.out[i*8+j] * 2**(7-j);
    out[i] <== byte;
  }
}

template Sha256Hash(N) {
    signal input in[N];
    signal input hash[32];

    component sha256 = Sha256Bytes(N);
    sha256.in <== in;

    for (var i = 0; i < 32; i++) {
        sha256.out[i] === hash[i];
    }
}

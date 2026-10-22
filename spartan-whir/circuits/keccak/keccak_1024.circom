pragma circom 2.2.3;

include "keccak_hash.circom";

component main {public [hash]} = Keccak256Hash(1024);

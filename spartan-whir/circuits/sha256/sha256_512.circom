pragma circom 2.2.3;

include "sha256_hash.circom";

component main {public [hash]} = Sha256Hash(512);

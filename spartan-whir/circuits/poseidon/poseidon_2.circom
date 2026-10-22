pragma circom 2.2.3;

include "poseidon_hash.circom";

component main {public [hash]} = PoseidonHash(2);

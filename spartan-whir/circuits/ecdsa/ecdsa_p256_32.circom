pragma circom 2.2.0;
include "verify.circom";
component main {public [msghash, pubkey]} = KbEcdsaVerify(1);

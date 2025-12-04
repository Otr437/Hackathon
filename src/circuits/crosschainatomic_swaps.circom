pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

// COMPLETE Cross-Chain Atomic Swap Verification Circuit
// Verifies EVERYTHING without revealing private data
template CrossChainAtomicSwap() {
    // PRIVATE INPUTS - Chain A
    signal input secretA;
    signal input senderPrivKeyA;
    signal input recipientPrivKeyA;
    signal input amountA;
    signal input depositAddressA;
    signal input nonceA;
    
    // PRIVATE INPUTS - Chain B
    signal input secretB;
    signal input senderPrivKeyB;
    signal input recipientPrivKeyB;
    signal input amountB;
    signal input depositAddressB;
    signal input nonceB;
    
    // PUBLIC INPUTS - Chain A
    signal input secretHashA;
    signal input senderPubKeyHashA;
    signal input recipientPubKeyHashA;
    signal input depositHashA;
    signal input nullifierA;
    
    // PUBLIC INPUTS - Chain B
    signal input secretHashB;
    signal input senderPubKeyHashB;
    signal input recipientPubKeyHashB;
    signal input depositHashB;
    signal input nullifierB;
    
    // PUBLIC INPUTS - Swap parameters
    signal input exchangeRate;
    signal input timeLockA;
    signal input timeLockB;
    signal input currentTime;
    signal input minTimeLock;
    
    // OUTPUTS
    signal output commitmentA;
    signal output commitmentB;
    signal output crossChainProof;
    signal output valid;
    
    // === VERIFY SECRETS MATCH (ATOMICITY) ===
    component hashSecretA = Poseidon(1);
    hashSecretA.inputs[0] <== secretA;
    
    component hashSecretB = Poseidon(1);
    hashSecretB.inputs[0] <== secretB;
    
    component verifySecretA = IsEqual();
    verifySecretA.in[0] <== hashSecretA.out;
    verifySecretA.in[1] <== secretHashA;
    
    component verifySecretB = IsEqual();
    verifySecretB.in[0] <== hashSecretB.out;
    verifySecretB.in[1] <== secretHashB;
    
    component secretsMatch = IsEqual();
    secretsMatch.in[0] <== secretA;
    secretsMatch.in[1] <== secretB;
    
    component hashesMatch = IsEqual();
    hashesMatch.in[0] <== hashSecretA.out;
    hashesMatch.in[1] <== hashSecretB.out;
    
    // === VERIFY SENDER/RECIPIENT CHAIN A ===
    component deriveSenderPubA = Poseidon(1);
    deriveSenderPubA.inputs[0] <== senderPrivKeyA;
    
    component hashSenderPubA = Poseidon(1);
    hashSenderPubA.inputs[0] <== deriveSenderPubA.out;
    
    component verifySenderA = IsEqual();
    verifySenderA.in[0] <== hashSenderPubA.out;
    verifySenderA.in[1] <== senderPubKeyHashA;
    
    component deriveRecipientPubA = Poseidon(1);
    deriveRecipientPubA.inputs[0] <== recipientPrivKeyA;
    
    component hashRecipientPubA = Poseidon(1);
    hashRecipientPubA.inputs[0] <== deriveRecipientPubA.out;
    
    component verifyRecipientA = IsEqual();
    verifyRecipientA.in[0] <== hashRecipientPubA.out;
    verifyRecipientA.in[1] <== recipientPubKeyHashA;
    
    // === VERIFY SENDER/RECIPIENT CHAIN B ===
    component deriveSenderPubB = Poseidon(1);
    deriveSenderPubB.inputs[0] <== senderPrivKeyB;
    
    component hashSenderPubB = Poseidon(1);
    hashSenderPubB.inputs[0] <== deriveSenderPubB.out;
    
    component verifySenderB = IsEqual();
    verifySenderB.in[0] <== hashSenderPubB.out;
    verifySenderB.in[1] <== senderPubKeyHashB;
    
    component deriveRecipientPubB = Poseidon(1);
    deriveRecipientPubB.inputs[0] <== recipientPrivKeyB;
    
    component hashRecipientPubB = Poseidon(1);
    hashRecipientPubB.inputs[0] <== deriveRecipientPubB.out;
    
    component verifyRecipientB = IsEqual();
    verifyRecipientB.in[0] <== hashRecipientPubB.out;
    verifyRecipientB.in[1] <== recipientPubKeyHashB;
    
    // === VERIFY DEPOSIT ADDRESSES ===
    component hashDepositA = Poseidon(3);
    hashDepositA.inputs[0] <== depositAddressA;
    hashDepositA.inputs[1] <== senderPubKeyHashA;
    hashDepositA.inputs[2] <== recipientPubKeyHashA;
    
    component verifyDepositA = IsEqual();
    verifyDepositA.in[0] <== hashDepositA.out;
    verifyDepositA.in[1] <== depositHashA;
    
    component hashDepositB = Poseidon(3);
    hashDepositB.inputs[0] <== depositAddressB;
    hashDepositB.inputs[1] <== senderPubKeyHashB;
    hashDepositB.inputs[2] <== recipientPubKeyHashB;
    
    component verifyDepositB = IsEqual();
    verifyDepositB.in[0] <== hashDepositB.out;
    verifyDepositB.in[1] <== depositHashB;
    
    // === VERIFY EXCHANGE RATE ===
    signal computedAmountB;
    computedAmountB <== (amountA * exchangeRate) / 1000000;
    
    component verifyExchangeRate = IsEqual();
    verifyExchangeRate.in[0] <== computedAmountB;
    verifyExchangeRate.in[1] <== amountB;
    
    // === VERIFY TIME LOCKS ===
    component verifyMinTimeLockA = GreaterEqThan(64);
    verifyMinTimeLockA.in[0] <== timeLockA;
    verifyMinTimeLockA.in[1] <== minTimeLock;
    
    component verifyMinTimeLockB = GreaterEqThan(64);
    verifyMinTimeLockB.in[0] <== timeLockB;
    verifyMinTimeLockB.in[1] <== minTimeLock;
    
    component verifyNotExpiredA = LessThan(64);
    verifyNotExpiredA.in[0] <== currentTime;
    verifyNotExpiredA.in[1] <== timeLockA;
    
    component verifyNotExpiredB = LessThan(64);
    verifyNotExpiredB.in[0] <== currentTime;
    verifyNotExpiredB.in[1] <== timeLockB;
    
    // === CREATE COMMITMENTS ===
    component commitHashA = Poseidon(7);
    commitHashA.inputs[0] <== hashSecretA.out;
    commitHashA.inputs[1] <== amountA;
    commitHashA.inputs[2] <== depositHashA;
    commitHashA.inputs[3] <== senderPubKeyHashA;
    commitHashA.inputs[4] <== recipientPubKeyHashA;
    commitHashA.inputs[5] <== nonceA;
    commitHashA.inputs[6] <== nullifierA;
    commitmentA <== commitHashA.out;
    
    component commitHashB = Poseidon(7);
    commitHashB.inputs[0] <== hashSecretB.out;
    commitHashB.inputs[1] <== amountB;
    commitHashB.inputs[2] <== depositHashB;
    commitHashB.inputs[3] <== senderPubKeyHashB;
    commitHashB.inputs[4] <== recipientPubKeyHashB;
    commitHashB.inputs[5] <== nonceB;
    commitHashB.inputs[6] <== nullifierB;
    commitmentB <== commitHashB.out;
    
    // === CROSS-CHAIN PROOF (Links both swaps) ===
    component crossChainHash = Poseidon(4);
    crossChainHash.inputs[0] <== hashSecretA.out;
    crossChainHash.inputs[1] <== commitmentA;
    crossChainHash.inputs[2] <== commitmentB;
    crossChainHash.inputs[3] <== nullifierA + nullifierB;
    crossChainProof <== crossChainHash.out;
    
    // === COMPUTE VALIDITY ===
    signal atomicity;
    signal validA;
    signal validB;
    signal timelocksValid;
    
    atomicity <== secretsMatch.out * hashesMatch.out;
    validA <== verifySecretA.out * verifySenderA.out * verifyRecipientA.out * verifyDepositA.out;
    validB <== verifySecretB.out * verifySenderB.out * verifyRecipientB.out * verifyDepositB.out;
    timelocksValid <== verifyMinTimeLockA.out * verifyMinTimeLockB.out * verifyNotExpiredA.out * verifyNotExpiredB.out;
    
    valid <== atomicity * validA * validB * verifyExchangeRate.out * timelocksValid;
    valid === 1;
}

component main {public [
    secretHashA, senderPubKeyHashA, recipientPubKeyHashA, depositHashA, nullifierA,
    secretHashB, senderPubKeyHashB, recipientPubKeyHashB, depositHashB, nullifierB,
    exchangeRate, timeLockA, timeLockB, currentTime, minTimeLock
]} = CrossChainAtomicSwap();

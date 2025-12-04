pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/mimcsponge.circom";

template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];
    
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}

template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    component selectors[levels];
    component hashers[levels];
    
    for (var i = 0; i < levels; i++) {
        selectors[i] = DualMux();
        selectors[i].in[0] <== i == 0 ? leaf : hashers[i-1].out;
        selectors[i].in[1] <== pathElements[i];
        selectors[i].s <== pathIndices[i];
        
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== selectors[i].out[0];
        hashers[i].inputs[1] <== selectors[i].out[1];
        
        // Ensure pathIndices is binary
        pathIndices[i] * (pathIndices[i] - 1) === 0;
    }
    
    root === hashers[levels-1].out;
}

template CommitmentHasher() {
    signal input nullifier;
    signal input secret;
    signal output commitment;
    signal output nullifierHash;
    
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== nullifier;
    commitmentHasher.inputs[1] <== secret;
    commitment <== commitmentHasher.out;
    
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== nullifier;
    nullifierHasher.inputs[1] <== secret;
    nullifierHash <== nullifierHasher.out;
}

template RangeCheck(n) {
    signal input in;
    signal output out;
    
    component lt = LessThan(n);
    lt.in[0] <== in;
    lt.in[1] <== (1 << n);
    out <== lt.out;
}

template Withdraw(levels) {
    // Public signals
    signal input root;
    signal input nullifierHash;
    signal input recipient;
    signal input relayer;
    signal input fee;
    signal input refund;
    
    // Private signals
    signal input nullifier;
    signal input secret;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    // Intermediate signals
    signal commitment;
    signal calculatedNullifierHash;
    
    // Hash the commitment
    component commitmentHasher = CommitmentHasher();
    commitmentHasher.nullifier <== nullifier;
    commitmentHasher.secret <== secret;
    commitment <== commitmentHasher.commitment;
    calculatedNullifierHash <== commitmentHasher.nullifierHash;
    
    // Verify nullifier hash
    nullifierHash === calculatedNullifierHash;
    
    // Verify merkle tree inclusion
    component tree = MerkleTreeChecker(levels);
    tree.leaf <== commitment;
    tree.root <== root;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
    
    // Range checks for addresses and amounts
    component recipientCheck = RangeCheck(160);
    recipientCheck.in <== recipient;
    recipientCheck.out === 1;
    
    component relayerCheck = RangeCheck(160);
    relayerCheck.in <== relayer;
    relayerCheck.out === 1;
    
    component feeCheck = RangeCheck(64);
    feeCheck.in <== fee;
    feeCheck.out === 1;
    
    component refundCheck = RangeCheck(64);
    refundCheck.in <== refund;
    refundCheck.out === 1;
}

template MultiTokenWithdraw(levels) {
    // Public signals
    signal input root;
    signal input nullifierHash;
    signal input recipient;
    signal input relayer;
    signal input fee;
    signal input refund;
    signal input tokenAddress;
    signal input amount;
    signal input tokenType;
    
    // Private signals
    signal input nullifier;
    signal input secret;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    // Use base withdraw template
    component withdraw = Withdraw(levels);
    withdraw.root <== root;
    withdraw.nullifierHash <== nullifierHash;
    withdraw.recipient <== recipient;
    withdraw.relayer <== relayer;
    withdraw.fee <== fee;
    withdraw.refund <== refund;
    withdraw.nullifier <== nullifier;
    withdraw.secret <== secret;
    
    for (var i = 0; i < levels; i++) {
        withdraw.pathElements[i] <== pathElements[i];
        withdraw.pathIndices[i] <== pathIndices[i];
    }
    
    // Additional token validations
    component tokenCheck = RangeCheck(160);
    tokenCheck.in <== tokenAddress;
    tokenCheck.out === 1;
    
    component amountCheck = RangeCheck(128);
    amountCheck.in <== amount;
    amountCheck.out === 1;
    
    component typeCheck = LessThan(3);
    typeCheck.in[0] <== tokenType;
    typeCheck.in[1] <== 4;
    typeCheck.out === 1;
}

template BatchWithdraw(levels, batchSize) {
    // Public signals arrays
    signal input roots[batchSize];
    signal input nullifierHashes[batchSize];
    signal input recipients[batchSize];
    signal input relayers[batchSize];
    signal input fees[batchSize];
    signal input refunds[batchSize];
    
    // Private signals arrays
    signal input nullifiers[batchSize];
    signal input secrets[batchSize];
    signal input pathElements[batchSize][levels];
    signal input pathIndices[batchSize][levels];
    
    // Batch processing
    component withdraws[batchSize];
    
    for (var i = 0; i < batchSize; i++) {
        withdraws[i] = Withdraw(levels);
        withdraws[i].root <== roots[i];
        withdraws[i].nullifierHash <== nullifierHashes[i];
        withdraws[i].recipient <== recipients[i];
        withdraws[i].relayer <== relayers[i];
        withdraws[i].fee <== fees[i];
        withdraws[i].refund <== refunds[i];
        withdraws[i].nullifier <== nullifiers[i];
        withdraws[i].secret <== secrets[i];
        
        for (var j = 0; j < levels; j++) {
            withdraws[i].pathElements[j] <== pathElements[i][j];
            withdraws[i].pathIndices[j] <== pathIndices[i][j];
        }
    }
}

template ComplianceWithdraw(levels) {
    // Public signals
    signal input root;
    signal input nullifierHash;
    signal input recipient;
    signal input relayer;
    signal input fee;
    signal input refund;
    signal input timestamp;
    signal input minAge;
    
    // Private signals
    signal input nullifier;
    signal input secret;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input commitmentTimestamp;
    
    // Base withdrawal verification
    component withdraw =
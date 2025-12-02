pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";

template MerkleTreeInclusionProof(levels) {
    signal input leaf;
    signal input pathIndices[levels];
    signal input siblings[levels];
    signal input root;

    component hashers[levels];
    signal computedPath[levels+1];
    
    computedPath[0] <== leaf;
    
    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        
        hashers[i].inputs[0] <== pathIndices[i] == 0 ? computedPath[i] : siblings[i];
        hashers[i].inputs[1] <== pathIndices[i] == 0 ? siblings[i] : computedPath[i];
        
        computedPath[i+1] <== hashers[i].out;
    }
    
    computedPath[levels] === root;
}

template PrivateSwap(levels) {
    signal input secret;
    signal input nullifier;
    signal input amountIn;
    signal input amountOut;
    signal input recipient;
    signal input chainIdFrom;
    signal input chainIdTo;
    signal input tokenFrom;
    signal input tokenTo;
    signal input timestamp;
    signal input relayer;
    signal input fee;
    
    signal input commitmentIn;
    signal input root;
    signal input pathIndices[levels];
    signal input siblings[levels];
    
    signal output nullifierHash;
    signal output commitmentOut;
    signal output newRoot;
    
    signal output publicNullifierHash;
    signal output publicRoot;
    signal output publicAmountIn;
    signal output publicAmountOut;
    signal output publicRecipient;
    signal output publicChainIdFrom;
    signal output publicChainIdTo;
    signal output publicTokenFrom;
    signal output publicTokenTo;
    signal output publicRelayer;
    signal output publicFee;
    signal output publicTimestamp;

    component merkleProof = MerkleTreeInclusionProof(levels);
    merkleProof.leaf <== commitmentIn;
    merkleProof.pathIndices <== pathIndices;
    merkleProof.siblings <== siblings;
    merkleProof.root <== root;

    component commitmentHasher = Poseidon(4);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== amountIn;
    commitmentHasher.inputs[2] <== chainIdFrom;
    commitmentHasher.inputs[3] <== nullifier;
    commitmentHasher.out === commitmentIn;

    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== secret;
    nullifierHasher.inputs[1] <== chainIdFrom;
    nullifierHasher.inputs[2] <== nullifier;
    nullifierHash <== nullifierHasher.out;

    component outputHasher = Poseidon(5);
    outputHasher.inputs[0] <== secret;
    outputHasher.inputs[1] <== amountOut;
    outputHasher.inputs[2] <== recipient;
    outputHasher.inputs[3] <== chainIdTo;
    outputHasher.inputs[4] <== timestamp;
    commitmentOut <== outputHasher.out;

    component insertHasher = Poseidon(2);
    insertHasher.inputs[0] <== root;
    insertHasher.inputs[1] <== commitmentOut;
    newRoot <== insertHasher.out;

    component amountInCheck = LessThan(64);
    amountInCheck.in[0] <== 0;
    amountInCheck.in[1] <== amountIn;
    amountInCheck.out === 1;

    component amountOutCheck = LessThan(64);
    amountOutCheck.in[0] <== 0;
    amountOutCheck.in[1] <== amountOut;
    amountOutCheck.out === 1;

    component feeCheck = LessThan(64);
    feeCheck.in[0] <== fee;
    feeCheck.in[1] <== amountOut;
    feeCheck.out === 1;

    publicNullifierHash <== nullifierHash;
    publicRoot <== root;
    publicAmountIn <== amountIn;
    publicAmountOut <== amountOut;
    publicRecipient <== recipient;
    publicChainIdFrom <== chainIdFrom;
    publicChainIdTo <== chainIdTo;
    publicTokenFrom <== tokenFrom;
    publicTokenTo <== tokenTo;
    publicRelayer <== relayer;
    publicFee <== fee;
    publicTimestamp <== timestamp;
}

component main = PrivateSwap(20);

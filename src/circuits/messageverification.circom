pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

// Cross-Chain Message Verification Circuit
// Verifies messages between chains without revealing message content
template CrossChainMessageVerifier() {
    // PRIVATE INPUTS
    signal input messageContent;        // Actual message (secret)
    signal input senderPrivKey;         // Message sender private key
    signal input recipientPrivKey;      // Message recipient private key
    signal input messageNonce;          // Message nonce
    signal input sourceChainId;         // Source chain ID
    signal input targetChainId;         // Target chain ID
    
    // PUBLIC INPUTS
    signal input messageHash;           // Hash of message (public)
    signal input senderPubKeyHash;      // Hash of sender's pubkey
    signal input recipientPubKeyHash;   // Hash of recipient's pubkey
    signal input messageCommitment;     // Public commitment to message
    signal input chainLinkHash;         // Links source and target chains
    
    // OUTPUTS
    signal output messageProof;         // Proof of valid message
    signal output verified;             // 1 if message valid
    
    // === VERIFY MESSAGE HASH ===
    component hashMessage = Poseidon(1);
    hashMessage.inputs[0] <== messageContent;
    
    component verifyMessage = IsEqual();
    verifyMessage.in[0] <== hashMessage.out;
    verifyMessage.in[1] <== messageHash;
    
    // === VERIFY SENDER ===
    component deriveSenderPub = Poseidon(1);
    deriveSenderPub.inputs[0] <== senderPrivKey;
    
    component hashSenderPub = Poseidon(1);
    hashSenderPub.inputs[0] <== deriveSenderPub.out;
    
    component verifySender = IsEqual();
    verifySender.in[0] <== hashSenderPub.out;
    verifySender.in[1] <== senderPubKeyHash;
    
    // === VERIFY RECIPIENT ===
    component deriveRecipientPub = Poseidon(1);
    deriveRecipientPub.inputs[0] <== recipientPrivKey;
    
    component hashRecipientPub = Poseidon(1);
    hashRecipientPub.inputs[0] <== deriveRecipientPub.out;
    
    component verifyRecipient = IsEqual();
    verifyRecipient.in[0] <== hashRecipientPub.out;
    verifyRecipient.in[1] <== recipientPubKeyHash;
    
    // === VERIFY MESSAGE COMMITMENT ===
    component commitHash = Poseidon(5);
    commitHash.inputs[0] <== hashMessage.out;
    commitHash.inputs[1] <== senderPubKeyHash;
    commitHash.inputs[2] <== recipientPubKeyHash;
    commitHash.inputs[3] <== messageNonce;
    commitHash.inputs[4] <== sourceChainId + targetChainId;
    
    component verifyCommitment = IsEqual();
    verifyCommitment.in[0] <== commitHash.out;
    verifyCommitment.in[1] <== messageCommitment;
    
    // === VERIFY CHAIN LINK ===
    component chainLink = Poseidon(2);
    chainLink.inputs[0] <== sourceChainId;
    chainLink.inputs[1] <== targetChainId;
    
    component verifyChainLink = IsEqual();
    verifyChainLink.in[0] <== chainLink.out;
    verifyChainLink.in[1] <== chainLinkHash;
    
    // === CREATE MESSAGE PROOF ===
    component proofHash = Poseidon(3);
    proofHash.inputs[0] <== hashMessage.out;
    proofHash.inputs[1] <== messageCommitment;
    proofHash.inputs[2] <== chainLinkHash;
    messageProof <== proofHash.out;
    
    // === COMPUTE VALIDITY ===
    signal check1;
    signal check2;
    
    check1 <== verifyMessage.out * verifySender.out;
    check2 <== verifyRecipient.out * verifyCommitment.out;
    verified <== check1 * check2 * verifyChainLink.out;
    verified === 1;
}

component main {public [messageHash, senderPubKeyHash, recipientPubKeyHash, messageCommitment, chainLinkHash]} = CrossChainMessageVerifier();

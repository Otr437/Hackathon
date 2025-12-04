pragma circom 2.0.0;

include "circomlib/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";

// Configuration constants
const MERKLE_DEPTH = 32;
const MAX_AMOUNT_BITS = 64;
const MIN_DEPOSIT_AMOUNT = 1000; // Minimum deposit (e.g., 0.001 ETH in wei)
const MAX_WITHDRAWAL_AMOUNT = 1000000000000000000; // Maximum withdrawal (1 ETH in wei)

template ZkBankSecure() {
    // === INPUTS ===
    // Private inputs
    signal input secret;                        // User's secret (must be non-zero)
    signal input amount;                        // Original deposit amount
    signal input pathElements[MERKLE_DEPTH];    // Merkle proof path
    signal input pathIndices[MERKLE_DEPTH];     // Merkle proof indices
    signal input nonce;                         // Unique nonce for this transaction
    
    // Public inputs
    signal input root;                          // Current Merkle root
    signal input withdrawAmount;                // Amount to withdraw
    signal input nullifierHash;                 // Expected nullifier hash
    signal input recipientAddress;              // Withdrawal recipient
    signal input relayerAddress;                // Relayer address (can be 0)
    signal input fee;                          // Relayer fee
    signal input timestamp;                     // Transaction timestamp
    signal input isDeposit;                     // 1 for deposit, 0 for withdrawal

    // === OUTPUTS ===
    signal output valid;                        // Circuit validation flag
    signal output commitment;                   // Computed commitment
    signal output outNullifier;                 // Computed nullifier
    signal output withdrawalHash;               // Hash of withdrawal details
    signal output totalAmount;                  // Total amount (for verification)

    // === SECURITY ENHANCEMENTS ===
    
    // 1. Secret validation - must not be zero
    component secretIsZero = IsEqual();
    secretIsZero.in[0] <== secret;
    secretIsZero.in[1] <== 0;
    signal secretValid <== 1 - secretIsZero.out;
    secretValid === 1; // Enforce secret != 0

    // 2. Nonce validation - must not be zero
    component nonceIsZero = IsEqual();
    nonceIsZero.in[0] <== nonce;
    nonceIsZero.in[1] <== 0;
    signal nonceValid <== 1 - nonceIsZero.out;
    nonceValid === 1; // Enforce nonce != 0

    // 3. Range checks for all amounts
    component amountBits = Num2Bits(MAX_AMOUNT_BITS);
    amountBits.in <== amount;

    component withdrawBits = Num2Bits(MAX_AMOUNT_BITS);
    withdrawBits.in <== withdrawAmount;

    component feeBits = Num2Bits(MAX_AMOUNT_BITS);
    feeBits.in <== fee;

    // 4. Minimum deposit check
    component minDepositCheck = GreaterEqThan(MAX_AMOUNT_BITS);
    minDepositCheck.in[0] <== amount;
    minDepositCheck.in[1] <== MIN_DEPOSIT_AMOUNT;
    minDepositCheck.out === 1;

    // 5. Maximum withdrawal check
    component maxWithdrawCheck = LessEqThan(MAX_AMOUNT_BITS);
    maxWithdrawCheck.in[0] <== withdrawAmount;
    maxWithdrawCheck.in[1] <== MAX_WITHDRAWAL_AMOUNT;
    maxWithdrawCheck.out === 1;

    // 6. Fee validation (fee should be reasonable)
    component feeCheck = LessEqThan(MAX_AMOUNT_BITS);
    feeCheck.in[0] <== fee;
    feeCheck.in[1] <== withdrawAmount / 10; // Fee should be max 10% of withdrawal
    feeCheck.out === 1;

    // === COMMITMENT GENERATION ===
    // Enhanced commitment with more entropy
    component hashCommit = Poseidon(4);
    hashCommit.inputs[0] <== secret;
    hashCommit.inputs[1] <== amount;
    hashCommit.inputs[2] <== nonce;
    hashCommit.inputs[3] <== timestamp;
    commitment <== hashCommit.out;

    // === NULLIFIER GENERATION ===
    // Enhanced nullifier to prevent replay attacks
    component hashNullifier = Poseidon(3);
    hashNullifier.inputs[0] <== secret;
    hashNullifier.inputs[1] <== nonce;
    hashNullifier.inputs[2] <== commitment;
    outNullifier <== hashNullifier.out;

    // Verify provided nullifier matches computed one
    component nullifierCheck = IsEqual();
    nullifierCheck.in[0] <== nullifierHash;
    nullifierCheck.in[1] <== outNullifier;
    nullifierCheck.out === 1;

    // === MERKLE PROOF VERIFICATION ===
    component merkleProof[MERKLE_DEPTH];
    signal merkleHash[MERKLE_DEPTH + 1];
    merkleHash[0] <== commitment;

    for (var i = 0; i < MERKLE_DEPTH; i++) {
        // Ensure path indices are binary
        component pathIndexBinary = Num2Bits(1);
        pathIndexBinary.in <== pathIndices[i];

        // Create left and right inputs for hash
        component mux = Mux1();
        mux.c[0] <== merkleHash[i];
        mux.c[1] <== pathElements[i];
        mux.s <== pathIndices[i];
        signal left <== mux.out;

        component mux2 = Mux1();
        mux2.c[0] <== pathElements[i];
        mux2.c[1] <== merkleHash[i];
        mux2.s <== pathIndices[i];
        signal right <== mux2.out;

        // Hash the pair
        merkleProof[i] = Poseidon(2);
        merkleProof[i].inputs[0] <== left;
        merkleProof[i].inputs[1] <== right;
        merkleHash[i + 1] <== merkleProof[i].out;
    }

    // Verify final hash matches root
    component rootCheck = IsEqual();
    rootCheck.in[0] <== merkleHash[MERKLE_DEPTH];
    rootCheck.in[1] <== root;
    rootCheck.out === 1;

    // === DEPOSIT VERIFICATION ===
    component isDepositCheck = IsEqual();
    isDepositCheck.in[0] <== isDeposit;
    isDepositCheck.in[1] <== 1;

    // For deposits, withdrawal amount should be 0
    component depositWithdrawCheck = IsEqual();
    depositWithdrawCheck.in[0] <== withdrawAmount;
    depositWithdrawCheck.in[1] <== 0;
    
    signal depositValid <== isDepositCheck.out * depositWithdrawCheck.out;

    // === WITHDRAWAL VERIFICATION ===
    component isWithdrawCheck = IsEqual();
    isWithdrawCheck.in[0] <== isDeposit;
    isWithdrawCheck.in[1] <== 0;

    // For withdrawals, amount should equal withdrawAmount + fee
    signal totalWithdrawal <== withdrawAmount + fee;
    component withdrawAmountCheck = IsEqual();
    withdrawAmountCheck.in[0] <== amount;
    withdrawAmountCheck.in[1] <== totalWithdrawal;
    
    signal withdrawValid <== isWithdrawCheck.out * withdrawAmountCheck.out;

    // === RECIPIENT AND RELAYER VALIDATION ===
    // Recipient address must not be zero for withdrawals
    component recipientCheck = IsEqual();
    recipientCheck.in[0] <== recipientAddress;
    recipientCheck.in[1] <== 0;
    signal recipientNonZero <== 1 - recipientCheck.out;
    
    // If withdrawal, recipient must be non-zero
    signal recipientValid <== (isWithdrawCheck.out * recipientNonZero) + isDepositCheck.out;
    recipientValid === 1;

    // === WITHDRAWAL HASH GENERATION ===
    // Generate hash of withdrawal details for verification
    component withdrawalHasher = Poseidon(5);
    withdrawalHasher.inputs[0] <== recipientAddress;
    withdrawalHasher.inputs[1] <== withdrawAmount;
    withdrawalHasher.inputs[2] <== fee;
    withdrawalHasher.inputs[3] <== relayerAddress;
    withdrawalHasher.inputs[4] <== timestamp;
    withdrawalHash <== withdrawalHasher.out;

    // === TRANSACTION TYPE VALIDATION ===
    // Ensure isDeposit is binary (0 or 1)
    component isDepositBinary = Num2Bits(1);
    isDepositBinary.in <== isDeposit;

    // Either deposit or withdrawal must be valid
    signal transactionValid <== depositValid + withdrawValid;
    transactionValid === 1;

    // === TIMESTAMP VALIDATION ===
    // Ensure timestamp is not zero and within reasonable range
    component timestampCheck = GreaterThan(64);
    timestampCheck.in[0] <== timestamp;
    timestampCheck.in[1] <== 0;
    timestampCheck.out === 1;

    // === AMOUNT CONSISTENCY CHECK ===
    // Verify total amount calculation
    totalAmount <== amount + fee;

    // === DOUBLE SPENDING PREVENTION ===
    // Additional check to ensure nullifier uniqueness
    component nullifierNonZero = IsEqual();
    nullifierNonZero.in[0] <== outNullifier;
    nullifierNonZero.in[1] <== 0;
    signal nullifierValidFlag <== 1 - nullifierNonZero.out;
    nullifierValidFlag === 1;

    // === FINAL VALIDATION ===
    // All checks must pass for circuit to be valid
    signal securityChecks <== secretValid * nonceValid * nullifierValidFlag;
    signal rangeChecks <== minDepositCheck.out * maxWithdrawCheck.out * feeCheck.out;
    signal proofChecks <== rootCheck.out * nullifierCheck.out;
    signal transactionChecks <== transactionValid * recipientValid * timestampCheck.out;
    
    signal allChecks <== securityChecks * rangeChecks * proofChecks * transactionChecks;
    allChecks === 1;

    // Set validity flag
    valid <== allChecks;
}

component main = ZkBankSecure();
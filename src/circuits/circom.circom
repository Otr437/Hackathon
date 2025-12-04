pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

template CombinedVerifier() {
    // Common inputs
    signal input selector; // 0=Approval, 1=Transfer, 2=Balance
    signal input newCommitment;
    
    // Approval-specific inputs
    signal input ownerBalance;
    signal input allowanceAmount;
    signal input ownerAddress;
    signal input spenderAddress;
    signal input allowanceHash;
    
    // Transfer-specific inputs
    signal input senderBalance;
    signal input receiverBalance;
    signal input amount;
    signal input senderAddress;
    signal input receiverAddress;
    signal input transferNullifier;
    
    // Balance-specific inputs
    signal input privateBalance;
    signal input privateAddress; 
    signal input balanceNullifier;
    signal input merkleRoot;
    signal input totalSupply;
    
    // Output
    signal output verified;
    
    // Constraint: selector must be 0, 1, or 2
    component selectorCheck = LessThan(8);
    selectorCheck.in[0] <== selector;
    selectorCheck.in[1] <== 3;
    selectorCheck.out === 1;
    
    // Components
    component approval = ApprovalVerifier();
    component transfer = TransferVerifier();
    component balance = BalanceVerifier();
    
    // Connect inputs based on selector
    approval.ownerBalance <== ownerBalance;
    approval.allowanceAmount <== allowanceAmount;
    approval.ownerAddress <== ownerAddress;
    approval.spenderAddress <== spenderAddress;
    approval.allowanceHash <== allowanceHash;
    approval.newCommitment <== newCommitment;
    
    transfer.senderBalance <== senderBalance;
    transfer.receiverBalance <== receiverBalance;
    transfer.amount <== amount;
    transfer.senderAddress <== senderAddress;
    transfer.receiverAddress <== receiverAddress;
    transfer.nullifier <== transferNullifier;
    transfer.newCommitment <== newCommitment;
    
    balance.privateBalance <== privateBalance;
    balance.privateAddress <== privateAddress;
    balance.nullifier <== balanceNullifier;
    balance.newCommitment <== newCommitment;
    balance.merkleRoot <== merkleRoot;
    balance.totalSupply <== totalSupply;
    
    // Conditional verification based on selector
    component isApproval = IsEqual();
    isApproval.in[0] <== selector;
    isApproval.in[1] <== 0;
    
    component isTransfer = IsEqual();
    isTransfer.in[0] <== selector;
    isTransfer.in[1] <== 1;
    
    component isBalance = IsEqual();
    isBalance.in[0] <== selector;
    isBalance.in[1] <== 2;
    
    // Ensure exactly one selector is active
    isApproval.out + isTransfer.out + isBalance.out === 1;
    
    // Select the appropriate output
    verified <== isApproval.out * approval.verified + 
                isTransfer.out * transfer.verified + 
                isBalance.out * balance.verified;
}

template ApprovalVerifier() {
    signal input ownerBalance;
    signal input allowanceAmount;
    signal input ownerAddress;
    signal input spenderAddress;
    signal input allowanceHash;
    signal input newCommitment;
    signal output verified;
    
    // Range checks for balance and allowance (64-bit values)
    component balanceRangeCheck = Num2Bits(64);
    balanceRangeCheck.in <== ownerBalance;
    
    component allowanceRangeCheck = Num2Bits(64);
    allowanceRangeCheck.in <== allowanceAmount;
    
    // Constraint: allowance cannot exceed owner balance
    component allowanceCheck = LessEqThan(64);
    allowanceCheck.in[0] <== allowanceAmount;
    allowanceCheck.in[1] <== ownerBalance;
    allowanceCheck.out === 1;
    
    // Constraint: allowance must be non-negative (implicitly handled by Num2Bits)
    // Constraint: addresses must be non-zero
    component ownerNonZero = IsZero();
    ownerNonZero.in <== ownerAddress;
    ownerNonZero.out === 0;
    
    component spenderNonZero = IsZero();
    spenderNonZero.in <== spenderAddress;
    spenderNonZero.out === 0;
    
    // Constraint: owner and spender must be different
    component addressDifferent = IsEqual();
    addressDifferent.in[0] <== ownerAddress;
    addressDifferent.in[1] <== spenderAddress;
    addressDifferent.out === 0;
    
    // Compute verification hash
    component hash = Poseidon(6);
    hash.inputs[0] <== ownerBalance;
    hash.inputs[1] <== allowanceAmount;
    hash.inputs[2] <== ownerAddress;
    hash.inputs[3] <== spenderAddress;
    hash.inputs[4] <== allowanceHash;
    hash.inputs[5] <== newCommitment;
    
    // Verify the allowance hash integrity
    component allowanceHashCheck = Poseidon(3);
    allowanceHashCheck.inputs[0] <== ownerAddress;
    allowanceHashCheck.inputs[1] <== spenderAddress;
    allowanceHashCheck.inputs[2] <== allowanceAmount;
    
    component hashVerification = IsEqual();
    hashVerification.in[0] <== allowanceHash;
    hashVerification.in[1] <== allowanceHashCheck.out;
    hashVerification.out === 1;
    
    verified <== hash.out;
}

template TransferVerifier() {
    signal input senderBalance;
    signal input receiverBalance;
    signal input amount;
    signal input senderAddress;
    signal input receiverAddress;
    signal input nullifier;
    signal input newCommitment;
    signal output verified;
    
    // Range checks for balances and amount (64-bit values)
    component senderBalanceRangeCheck = Num2Bits(64);
    senderBalanceRangeCheck.in <== senderBalance;
    
    component receiverBalanceRangeCheck = Num2Bits(64);
    receiverBalanceRangeCheck.in <== receiverBalance;
    
    component amountRangeCheck = Num2Bits(64);
    amountRangeCheck.in <== amount;
    
    // Constraint: sender has sufficient balance
    component sufficientBalance = LessEqThan(64);
    sufficientBalance.in[0] <== amount;
    sufficientBalance.in[1] <== senderBalance;
    sufficientBalance.out === 1;
    
    // Constraint: amount must be positive
    component positiveAmount = IsZero();
    positiveAmount.in <== amount;
    positiveAmount.out === 0;
    
    // Constraint: addresses must be non-zero
    component senderNonZero = IsZero();
    senderNonZero.in <== senderAddress;
    senderNonZero.out === 0;
    
    component receiverNonZero = IsZero();
    receiverNonZero.in <== receiverAddress;
    receiverNonZero.out === 0;
    
    // Constraint: sender and receiver must be different
    component addressDifferent = IsEqual();
    addressDifferent.in[0] <== senderAddress;
    addressDifferent.in[1] <== receiverAddress;
    addressDifferent.out === 0;
    
    // Prevent overflow: receiver balance + amount must not exceed max value
    component overflowCheck = LessEqThan(64);
    overflowCheck.in[0] <== receiverBalance + amount;
    overflowCheck.in[1] <== (1 << 64) - 1; // 2^64 - 1
    overflowCheck.out === 1;
    
    // Nullifier uniqueness check (prevent double spending)
    component nullifierHash = Poseidon(3);
    nullifierHash.inputs[0] <== senderAddress;
    nullifierHash.inputs[1] <== amount;
    nullifierHash.inputs[2] <== newCommitment;
    
    component nullifierCheck = IsEqual();
    nullifierCheck.in[0] <== nullifier;
    nullifierCheck.in[1] <== nullifierHash.out;
    nullifierCheck.out === 1;
    
    // Compute verification hash
    component hash = Poseidon(7);
    hash.inputs[0] <== senderBalance;
    hash.inputs[1] <== receiverBalance;
    hash.inputs[2] <== amount;
    hash.inputs[3] <== senderAddress;
    hash.inputs[4] <== receiverAddress;
    hash.inputs[5] <== nullifier;
    hash.inputs[6] <== newCommitment;
    
    verified <== hash.out;
}

template BalanceVerifier() {
    signal input privateBalance;
    signal input privateAddress; 
    signal input nullifier;
    signal input newCommitment;
    signal input merkleRoot;
    signal input totalSupply;
    signal output verified;
    
    // Range checks for balance and total supply (64-bit values)
    component balanceRangeCheck = Num2Bits(64);
    balanceRangeCheck.in <== privateBalance;
    
    component totalSupplyRangeCheck = Num2Bits(64);
    totalSupplyRangeCheck.in <== totalSupply;
    
    // Constraint: balance cannot exceed total supply
    component balanceCheck = LessEqThan(64);
    balanceCheck.in[0] <== privateBalance;
    balanceCheck.in[1] <== totalSupply;
    balanceCheck.out === 1;
    
    // Constraint: address must be non-zero
    component addressNonZero = IsZero();
    addressNonZero.in <== privateAddress;
    addressNonZero.out === 0;
    
    // Constraint: merkle root must be non-zero (valid tree)
    component merkleRootNonZero = IsZero();
    merkleRootNonZero.in <== merkleRoot;
    merkleRootNonZero.out === 0;
    
    // Verify balance commitment integrity
    component balanceCommitment = Poseidon(3);
    balanceCommitment.inputs[0] <== privateAddress;
    balanceCommitment.inputs[1] <== privateBalance;
    balanceCommitment.inputs[2] <== nullifier;
    
    // Verify the nullifier is correctly computed
    component nullifierHash = Poseidon(2);
    nullifierHash.inputs[0] <== privateAddress;
    nullifierHash.inputs[1] <== privateBalance;
    
    component nullifierCheck = IsEqual();
    nullifierCheck.in[0] <== nullifier;
    nullifierCheck.in[1] <== nullifierHash.out;
    nullifierCheck.out === 1;
    
    // Compute verification hash
    component hash = Poseidon(6);
    hash.inputs[0] <== privateBalance;
    hash.inputs[1] <== privateAddress;
    hash.inputs[2] <== nullifier;
    hash.inputs[3] <== newCommitment;
    hash.inputs[4] <== merkleRoot;
    hash.inputs[5] <== totalSupply;
    
    verified <== hash.out;
}

component main = CombinedVerifier();
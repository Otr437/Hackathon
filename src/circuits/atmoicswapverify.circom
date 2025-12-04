// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISwapVerifier {
    function verifyProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[15] memory input
    ) external view returns (bool);
}

interface IDepositVerifier {
    function verifyProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[5] memory input
    ) external view returns (bool);
}

interface IMessageVerifier {
    function verifyProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[5] memory input
    ) external view returns (bool);
}

contract CompleteAtomicSwap {
    ISwapVerifier public immutable swapVerifier;
    IDepositVerifier public immutable depositVerifier;
    IMessageVerifier public immutable messageVerifier;
    
    address public immutable crossChainMessenger;
    address public immutable linkedContract; // Contract on other chain
    uint256 public immutable chainId;
    
    bytes32 public merkleRoot;
    mapping(bytes32 => Swap) public swaps;
    mapping(bytes32 => bool) public usedNullifiers;
    mapping(bytes32 => Deposit) public deposits;
    mapping(bytes32 => CrossChainMessage) public messages;
    
    struct Swap {
        bytes32 commitment;
        bytes32 secretHash;
        bytes32 depositHash;
        bytes32 nullifier;
        address depositor;
        uint256 amount;
        uint256 timeLock;
        address depositAddress;
        bytes32 linkedSwap; // Swap on other chain
        SwapStatus status;
    }
    
    struct Deposit {
        bytes32 depositHash;
        bytes32 depositProof;
        address depositor;
        uint256 amount;
        uint256 timestamp;
        bool verified;
    }
    
    struct CrossChainMessage {
        bytes32 messageHash;
        bytes32 messageProof;
        bytes32 sourceCommitment;
        bytes32 targetCommitment;
        uint256 timestamp;
        bool executed;
    }
    
    enum SwapStatus {
        None,
        Initiated,
        Deposited,
        Completed,
        Refunded
    }
    
    event SwapInitiated(
        bytes32 indexed commitment,
        bytes32 indexed nullifier,
        bytes32 linkedSwap,
        uint256 amount
    );
    
    event DepositVerified(
        bytes32 indexed depositHash,
        bytes32 indexed commitment,
        uint256 amount
    );
    
    event SwapCompleted(
        bytes32 indexed commitment,
        bytes32 indexed linkedSwap,
        bytes32 secretHash
    );
    
    event CrossChainMessageReceived(
        bytes32 indexed messageHash,
        bytes32 indexed sourceCommitment,
        bytes32 targetCommitment
    );
    
    event SwapRefunded(bytes32 indexed commitment);
    event MerkleRootUpdated(bytes32 oldRoot, bytes32 newRoot);
    
    constructor(
        address _swapVerifier,
        address _depositVerifier,
        address _messageVerifier,
        address _crossChainMessenger,
        address _linkedContract,
        uint256 _chainId,
        bytes32 _initialRoot
    ) {
        swapVerifier = ISwapVerifier(_swapVerifier);
        depositVerifier = IDepositVerifier(_depositVerifier);
        messageVerifier = IMessageVerifier(_messageVerifier);
        crossChainMessenger = _crossChainMessenger;
        linkedContract = _linkedContract;
        chainId = _chainId;
        merkleRoot = _initialRoot;
    }
    
    // === STEP 1: INITIATE SWAP WITH ZK PROOF ===
    function initiateSwap(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[15] memory publicInputs,
        bytes32 linkedSwap
    ) external returns (bytes32 commitment) {
        // publicInputs layout:
        // [0] secretHashA, [1] senderPubKeyHashA, [2] recipientPubKeyHashA
        // [3] depositHashA, [4] nullifierA, [5] secretHashB
        // [6] senderPubKeyHashB, [7] recipientPubKeyHashB, [8] depositHashB
        // [9] nullifierB, [10] exchangeRate, [11] timeLockA, [12] timeLockB
        // [13] currentTime, [14] minTimeLock
        
        bytes32 nullifier = bytes32(publicInputs[4]);
        require(!usedNullifiers[nullifier], "Nullifier used");
        
        // Verify ZK proof
        require(swapVerifier.verifyProof(a, b, c, publicInputs), "Invalid swap proof");
        
        // Compute commitment
        commitment = keccak256(abi.encodePacked(
            publicInputs[0],  // secretHash
            publicInputs[3],  // depositHash
            publicInputs[1],  // senderPubKeyHash
            publicInputs[2],  // recipientPubKeyHash
            publicInputs[4]   // nullifier
        ));
        
        // Store swap
        swaps[commitment] = Swap({
            commitment: commitment,
            secretHash: bytes32(publicInputs[0]),
            depositHash: bytes32(publicInputs[3]),
            nullifier: nullifier,
            depositor: msg.sender,
            amount: 0, // Set after deposit verification
            timeLock: publicInputs[11],
            depositAddress: address(0), // Set after deposit
            linkedSwap: linkedSwap,
            status: SwapStatus.Initiated
        });
        
        usedNullifiers[nullifier] = true;
        
        emit SwapInitiated(commitment, nullifier, linkedSwap, 0);
        return commitment;
    }
    
    // === STEP 2: VERIFY DEPOSIT WITH ZK PROOF ===
    function verifyDeposit(
        bytes32 commitment,
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[5] memory publicInputs,
        address depositAddress
    ) external payable {
        // publicInputs: [depositHash, depositorPubKeyHash, minAmount, maxAmount, depositCommitment]
        
        Swap storage swap = swaps[commitment];
        require(swap.status == SwapStatus.Initiated, "Invalid status");
        require(msg.value > 0, "No deposit");
        
        // Verify deposit proof
        require(depositVerifier.verifyProof(a, b, c, publicInputs), "Invalid deposit proof");
        
        // Verify deposit hash matches swap
        require(bytes32(publicInputs[0]) == swap.depositHash, "Deposit hash mismatch");
        
        // Store deposit
        bytes32 depositHash = bytes32(publicInputs[0]);
        deposits[depositHash] = Deposit({
            depositHash: depositHash,
            depositProof: bytes32(publicInputs[4]),
            depositor: msg.sender,
            amount: msg.value,
            timestamp: block.timestamp,
            verified: true
        });
        
        // Update swap
        swap.amount = msg.value;
        swap.depositAddress = depositAddress;
        swap.status = SwapStatus.Deposited;
        
        emit DepositVerified(depositHash, commitment, msg.value);
    }
    
    // === STEP 3: COMPLETE SWAP VIA CROSS-CHAIN MESSAGE ===
    function completeSwapViaMessage(
        bytes32 commitment,
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[5] memory publicInputs,
        uint256 secret,
        address payable recipient
    ) external {
        // publicInputs: [messageHash, senderPubKeyHash, recipientPubKeyHash, messageCommitment, chainLinkHash]
        
        Swap storage swap = swaps[commitment];
        require(swap.status == SwapStatus.Deposited, "Invalid status");
        require(block.timestamp < swap.timeLock, "Expired");
        
        // Verify message proof
        require(messageVerifier.verifyProof(a, b, c, publicInputs), "Invalid message proof");
        
        // Verify secret
        bytes32 computedSecretHash = keccak256(abi.encodePacked(secret));
        require(computedSecretHash == swap.secretHash, "Wrong secret");
        
        // Store message
        bytes32 messageHash = bytes32(publicInputs[0]);
        messages[messageHash] = CrossChainMessage({
            messageHash: messageHash,
            messageProof: bytes32(publicInputs[3]),
            sourceCommitment: swap.linkedSwap,
            targetCommitment: commitment,
            timestamp: block.timestamp,
            executed: true
        });
        
        // Complete swap
        swap.status = SwapStatus.Completed;
        
        // Transfer funds
        (bool success, ) = recipient.call{value: swap.amount}("");
        require(success, "Transfer failed");
        
        emit SwapCompleted(commitment, swap.linkedSwap, swap.secretHash);
        emit CrossChainMessageReceived(messageHash, swap.linkedSwap, commitment);
    }
    
    // === STEP 4: REFUND AFTER TIMELOCK ===
    function refund(bytes32 commitment) external {
        Swap storage swap = swaps[commitment];
        require(swap.status == SwapStatus.Deposited, "Invalid status");
        require(block.timestamp >= swap.timeLock, "Not expired");
        require(msg.sender == swap.depositor, "Not depositor");
        
        swap.status = SwapStatus.Refunded;
        
        (bool success, ) = payable(swap.depositor).call{value: swap.amount}("");
        require(success, "Refund failed");
        
        emit SwapRefunded(commitment);
    }
    
    // === MERKLE ROOT UPDATE ===
    function updateMerkleRoot(bytes32 newRoot, bytes memory proof) external {
        // In production, verify Merkle proof here
        bytes32 oldRoot = merkleRoot;
        merkleRoot = newRoot;
        emit MerkleRootUpdated(oldRoot, newRoot);
    }
    
    // === VIEW FUNCTIONS ===
    function getSwap(bytes32 commitment) external view returns (Swap memory) {
        return swaps[commitment];
    }
    
    function getDeposit(bytes32 depositHash) external view returns (Deposit memory) {
        return deposits[depositHash];
    }
    
    function getMessage(bytes32 messageHash) external view returns (CrossChainMessage memory) {
        return messages[messageHash];
    }
    
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }
}

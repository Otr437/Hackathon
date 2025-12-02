// ============================================================================
// ECDSA SIGNATURE VERIFICATION FOR EVM CHAINS - FULL IMPLEMENTATION
// ============================================================================

import {
  Field,
  Bool,
  Struct,
  Provable,
  Bytes,
  createForeignCurve,
  createEcdsa,
  Crypto,
  Poseidon,
  UInt64,
  UInt32,
} from 'o1js';

// ============================================================================
// SECP256K1 CURVE IMPLEMENTATION
// ============================================================================

export class Secp256k1 extends createForeignCurve(Crypto.CurveParams.Secp256k1) {
  static validatePoint(x: bigint, y: bigint): boolean {
    const p = Crypto.CurveParams.Secp256k1.modulus;
    const a = 0n;
    const b = 7n;
    
    const left = (y * y) % p;
    const right = (x * x * x + a * x + b) % p;
    
    return left === right;
  }

  static recoverPublicKey(
    messageHash: bigint,
    r: bigint,
    s: bigint,
    recoveryId: number
  ): { x: bigint; y: bigint } {
    const n = Crypto.CurveParams.Secp256k1.order;
    const G = Crypto.CurveParams.Secp256k1.generator;
    
    const x = r + BigInt(recoveryId >= 2 ? 1 : 0) * n;
    
    const ySquared = (x * x * x + 7n) % Crypto.CurveParams.Secp256k1.modulus;
    let y = this.modularSquareRoot(ySquared, Crypto.CurveParams.Secp256k1.modulus);
    
    if (recoveryId % 2 === 1) {
      y = Crypto.CurveParams.Secp256k1.modulus - y;
    }
    
    return { x, y };
  }

  private static modularSquareRoot(a: bigint, p: bigint): bigint {
    return this.modPow(a, (p + 1n) / 4n, p);
  }

  private static modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    let result = 1n;
    base = base % modulus;
    
    while (exponent > 0n) {
      if (exponent % 2n === 1n) {
        result = (result * base) % modulus;
      }
      exponent = exponent / 2n;
      base = (base * base) % modulus;
    }
    
    return result;
  }
}

// ============================================================================
// ECDSA SIGNATURE TYPE
// ============================================================================

export class Ecdsa extends createEcdsa(Secp256k1) {
  static verifyWithRecovery(
    messageHash: bigint,
    r: bigint,
    s: bigint,
    publicKeyX: bigint,
    publicKeyY: bigint
  ): boolean {
    const publicKey = new Secp256k1({
      x: Secp256k1.Field.from(publicKeyX),
      y: Secp256k1.Field.from(publicKeyY),
    });

    const signature = Ecdsa.fromScalars({ r, s });
    const messageBytes = Bytes.from([messageHash]);

    return signature.verify(messageBytes, publicKey).toBoolean();
  }

  static signMessage(messageHash: bigint, privateKey: bigint): { r: bigint; s: bigint; v: number } {
    const signature = Ecdsa.sign(
      Bytes.from([messageHash]),
      privateKey
    );

    const { r, s } = signature.toBigInt();
    
    return { r, s, v: 27 };
  }
}

// ============================================================================
// EVM SIGNATURE PROOF STRUCTURE
// ============================================================================

export class EvmSignatureProof extends Struct({
  r: Field,
  s: Field,
  v: Field,
  messageHash: Field,
  publicKeyX: Field,
  publicKeyY: Field,
  recoveryId: Field,
  chainId: UInt32,
}) {
  verify(): Bool {
    const pkX = this.publicKeyX.toBigInt();
    const pkY = this.publicKeyY.toBigInt();
    
    const isValidPoint = Secp256k1.validatePoint(pkX, pkY);
    if (!isValidPoint) {
      return Bool(false);
    }

    const publicKey = new Secp256k1({
      x: Secp256k1.Field.from(pkX),
      y: Secp256k1.Field.from(pkY),
    });

    const signature = Ecdsa.fromScalars({
      r: this.r.toBigInt(),
      s: this.s.toBigInt(),
    });

    const messageBytes = Bytes.from([this.messageHash.toBigInt()]);

    const isValid = signature.verify(messageBytes, publicKey);
    
    const sValue = this.s.toBigInt();
    const halfOrder = Crypto.CurveParams.Secp256k1.order / 2n;
    const isLowS = sValue <= halfOrder;
    
    return isValid.and(Bool(isLowS));
  }

  verifyEIP155(): Bool {
    const expectedV = Field.from(this.chainId.value.mul(2).add(35).add(this.recoveryId.value));
    const vMatches = this.v.equals(expectedV);
    
    return this.verify().and(vMatches);
  }

  static fromEthSignature(
    r: string | bigint,
    s: string | bigint,
    v: number | bigint,
    messageHash: string | bigint,
    publicKeyX: string | bigint,
    publicKeyY: string | bigint,
    chainId: number
  ): EvmSignatureProof {
    const toBigInt = (value: string | bigint): bigint => {
      if (typeof value === 'string') {
        return value.startsWith('0x') ? BigInt(value) : BigInt('0x' + value);
      }
      return value;
    };

    const rBigInt = toBigInt(r);
    const sBigInt = toBigInt(s);
    const vBigInt = typeof v === 'number' ? BigInt(v) : v;
    const hashBigInt = toBigInt(messageHash);
    const pkXBigInt = toBigInt(publicKeyX);
    const pkYBigInt = toBigInt(publicKeyY);

    let recoveryId: bigint;
    if (vBigInt >= 35n) {
      const chainIdBigInt = BigInt(chainId);
      recoveryId = vBigInt - 35n - (chainIdBigInt * 2n);
    } else if (vBigInt >= 27n) {
      recoveryId = vBigInt - 27n;
    } else {
      recoveryId = vBigInt;
    }

    return new EvmSignatureProof({
      r: Field.from(rBigInt),
      s: Field.from(sBigInt),
      v: Field.from(vBigInt),
      messageHash: Field.from(hashBigInt),
      publicKeyX: Field.from(pkXBigInt),
      publicKeyY: Field.from(pkYBigInt),
      recoveryId: Field.from(recoveryId),
      chainId: UInt32.from(chainId),
    });
  }

  static createEmpty(): EvmSignatureProof {
    return new EvmSignatureProof({
      r: Field(0),
      s: Field(0),
      v: Field(0),
      messageHash: Field(0),
      publicKeyX: Field(0),
      publicKeyY: Field(0),
      recoveryId: Field(0),
      chainId: UInt32.from(0),
    });
  }

  toJSON(): {
    r: string;
    s: string;
    v: string;
    messageHash: string;
    publicKey: { x: string; y: string };
    recoveryId: string;
    chainId: string;
  } {
    return {
      r: '0x' + this.r.toBigInt().toString(16),
      s: '0x' + this.s.toBigInt().toString(16),
      v: '0x' + this.v.toBigInt().toString(16),
      messageHash: '0x' + this.messageHash.toBigInt().toString(16),
      publicKey: {
        x: '0x' + this.publicKeyX.toBigInt().toString(16),
        y: '0x' + this.publicKeyY.toBigInt().toString(16),
      },
      recoveryId: this.recoveryId.toString(),
      chainId: this.chainId.toString(),
    };
  }
}

// ============================================================================
// EVM MESSAGE BUILDERS
// ============================================================================

export class EvmMessageBuilder {
  static buildDepositMessage(
    amount: bigint,
    commitmentHash: bigint,
    sourceChain: number,
    targetChain: number,
    nonce: bigint,
    timestamp: bigint
  ): Field {
    return Poseidon.hash([
      Field.from(amount),
      Field.from(commitmentHash),
      Field.from(sourceChain),
      Field.from(targetChain),
      Field.from(nonce),
      Field.from(timestamp),
    ]);
  }

  static buildWithdrawalMessage(
    nullifierHash: bigint,
    recipientHash: bigint,
    amount: bigint,
    targetChain: number,
    deadline: bigint,
    relayerFee: bigint
  ): Field {
    return Poseidon.hash([
      Field.from(nullifierHash),
      Field.from(recipientHash),
      Field.from(amount),
      Field.from(targetChain),
      Field.from(deadline),
      Field.from(relayerFee),
    ]);
  }

  static buildRelayerAuthMessage(
    commitmentHash: bigint,
    relayerAddress: bigint,
    feeAmount: bigint,
    deadline: bigint
  ): Field {
    return Poseidon.hash([
      Field.from(commitmentHash),
      Field.from(relayerAddress),
      Field.from(feeAmount),
      Field.from(deadline),
    ]);
  }

  static keccak256Message(data: Uint8Array): bigint {
    const crypto = require('crypto');
    const hash = crypto.createHash('sha3-256').update(data).digest();
    return BigInt('0x' + hash.toString('hex'));
  }

  static prefixMessage(message: string): Uint8Array {
    const prefix = '\x19Ethereum Signed Message:\n' + message.length;
    const encoder = new TextEncoder();
    const prefixBytes = encoder.encode(prefix);
    const messageBytes = encoder.encode(message);
    
    const result = new Uint8Array(prefixBytes.length + messageBytes.length);
    result.set(prefixBytes);
    result.set(messageBytes, prefixBytes.length);
    
    return result;
  }
}

// ============================================================================
// EVM ADDRESS CONVERTER
// ============================================================================

export class EvmAddressConverter {
  static fromHex(address: string): Field {
    const cleanAddress = address.toLowerCase().startsWith('0x') 
      ? address.slice(2) 
      : address;
    
    if (cleanAddress.length !== 40) {
      throw new Error('Invalid Ethereum address length');
    }
    
    return Field.from(BigInt('0x' + cleanAddress));
  }

  static toHex(field: Field): string {
    const hex = field.toBigInt().toString(16);
    return '0x' + hex.padStart(40, '0').toLowerCase();
  }

  static checksumAddress(address: string): string {
    const cleanAddress = address.toLowerCase().replace('0x', '');
    const crypto = require('crypto');
    const hash = crypto.createHash('sha3-256').update(cleanAddress).digest('hex');
    
    let checksummed = '0x';
    for (let i = 0; i < cleanAddress.length; i++) {
      if (parseInt(hash[i], 16) >= 8) {
        checksummed += cleanAddress[i].toUpperCase();
      } else {
        checksummed += cleanAddress[i];
      }
    }
    
    return checksummed;
  }

  static deriveFromPublicKey(publicKeyX: bigint, publicKeyY: bigint): string {
    const pubKeyBytes = new Uint8Array(64);
    const xBytes = publicKeyX.toString(16).padStart(64, '0');
    const yBytes = publicKeyY.toString(16).padStart(64, '0');
    
    for (let i = 0; i < 32; i++) {
      pubKeyBytes[i] = parseInt(xBytes.slice(i * 2, i * 2 + 2), 16);
      pubKeyBytes[i + 32] = parseInt(yBytes.slice(i * 2, i * 2 + 2), 16);
    }
    
    const crypto = require('crypto');
    const hash = crypto.createHash('sha3-256').update(pubKeyBytes).digest();
    const address = '0x' + hash.slice(-20).toString('hex');
    
    return this.checksumAddress(address);
  }

  static isValidAddress(address: string): boolean {
    if (!address.startsWith('0x')) return false;
    if (address.length !== 42) return false;
    
    const hex = address.slice(2);
    return /^[0-9a-fA-F]{40}$/.test(hex);
  }
}

// ============================================================================
// CHAIN-SPECIFIC SIGNATURE VALIDATORS
// ============================================================================

export class ChainSignatureValidator {
  private static CHAIN_IDS = {
    ETHEREUM: 1,
    SEPOLIA: 11155111,
    POLYGON: 137,
    MUMBAI: 80001,
    ARBITRUM: 42161,
    ARBITRUM_GOERLI: 421613,
    OPTIMISM: 10,
    OPTIMISM_GOERLI: 420,
    AVALANCHE: 43114,
    AVALANCHE_FUJI: 43113,
    BSC: 56,
    BSC_TESTNET: 97,
    BASE: 8453,
    BASE_GOERLI: 84531,
    ZKSYNC: 324,
    ZKSYNC_TESTNET: 280,
    SCROLL: 534352,
    SCROLL_SEPOLIA: 534351,
  };

  static validateEthereum(proof: EvmSignatureProof): Bool {
    const isMainnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.ETHEREUM));
    const isTestnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.SEPOLIA));
    const isValidChain = isMainnet.or(isTestnet);
    
    return isValidChain.and(proof.verifyEIP155());
  }

  static validatePolygon(proof: EvmSignatureProof): Bool {
    const isMainnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.POLYGON));
    const isTestnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.MUMBAI));
    const isValidChain = isMainnet.or(isTestnet);
    
    return isValidChain.and(proof.verifyEIP155());
  }

  static validateArbitrum(proof: EvmSignatureProof): Bool {
    const isMainnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.ARBITRUM));
    const isTestnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.ARBITRUM_GOERLI));
    const isValidChain = isMainnet.or(isTestnet);
    
    return isValidChain.and(proof.verifyEIP155());
  }

  static validateOptimism(proof: EvmSignatureProof): Bool {
    const isMainnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.OPTIMISM));
    const isTestnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.OPTIMISM_GOERLI));
    const isValidChain = isMainnet.or(isTestnet);
    
    return isValidChain.and(proof.verifyEIP155());
  }

  static validateAvalanche(proof: EvmSignatureProof): Bool {
    const isMainnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.AVALANCHE));
    const isTestnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.AVALANCHE_FUJI));
    const isValidChain = isMainnet.or(isTestnet);
    
    return isValidChain.and(proof.verifyEIP155());
  }

  static validateBSC(proof: EvmSignatureProof): Bool {
    const isMainnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.BSC));
    const isTestnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.BSC_TESTNET));
    const isValidChain = isMainnet.or(isTestnet);
    
    return isValidChain.and(proof.verifyEIP155());
  }

  static validateBase(proof: EvmSignatureProof): Bool {
    const isMainnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.BASE));
    const isTestnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.BASE_GOERLI));
    const isValidChain = isMainnet.or(isTestnet);
    
    return isValidChain.and(proof.verifyEIP155());
  }

  static validateZkSync(proof: EvmSignatureProof): Bool {
    const isMainnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.ZKSYNC));
    const isTestnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.ZKSYNC_TESTNET));
    const isValidChain = isMainnet.or(isTestnet);
    
    return isValidChain.and(proof.verifyEIP155());
  }

  static validateScroll(proof: EvmSignatureProof): Bool {
    const isMainnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.SCROLL));
    const isTestnet = proof.chainId.value.equals(Field(this.CHAIN_IDS.SCROLL_SEPOLIA));
    const isValidChain = isMainnet.or(isTestnet);
    
    return isValidChain.and(proof.verifyEIP155());
  }

  static validateByChainId(chainId: number, proof: EvmSignatureProof): Bool {
    proof.chainId.value.assertEquals(Field(chainId), 'Chain ID mismatch');

    switch (chainId) {
      case this.CHAIN_IDS.ETHEREUM:
      case this.CHAIN_IDS.SEPOLIA:
        return this.validateEthereum(proof);
      
      case this.CHAIN_IDS.POLYGON:
      case this.CHAIN_IDS.MUMBAI:
        return this.validatePolygon(proof);
      
      case this.CHAIN_IDS.ARBITRUM:
      case this.CHAIN_IDS.ARBITRUM_GOERLI:
        return this.validateArbitrum(proof);
      
      case this.CHAIN_IDS.OPTIMISM:
      case this.CHAIN_IDS.OPTIMISM_GOERLI:
        return this.validateOptimism(proof);
      
      case this.CHAIN_IDS.AVALANCHE:
      case this.CHAIN_IDS.AVALANCHE_FUJI:
        return this.validateAvalanche(proof);
      
      case this.CHAIN_IDS.BSC:
      case this.CHAIN_IDS.BSC_TESTNET:
        return this.validateBSC(proof);
      
      case this.CHAIN_IDS.BASE:
      case this.CHAIN_IDS.BASE_GOERLI:
        return this.validateBase(proof);
      
      case this.CHAIN_IDS.ZKSYNC:
      case this.CHAIN_IDS.ZKSYNC_TESTNET:
        return this.validateZkSync(proof);
      
      case this.CHAIN_IDS.SCROLL:
      case this.CHAIN_IDS.SCROLL_SEPOLIA:
        return this.validateScroll(proof);
      
      default:
        return Bool(false);
    }
  }

  static getSupportedChains(): number[] {
    return Object.values(this.CHAIN_IDS);
  }

  static isChainSupported(chainId: number): boolean {
    return Object.values(this.CHAIN_IDS).includes(chainId);
  }

  static getChainName(chainId: number): string {
    const entry = Object.entries(this.CHAIN_IDS).find(([_, id]) => id === chainId);
    return entry ? entry[0] : 'UNKNOWN';
  }
}

export { Secp256k1, Ecdsa };
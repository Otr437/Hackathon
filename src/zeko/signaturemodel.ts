// ============================================================================
// X402 ECDSA SIGNATURE MODULE - COMPLETE PRODUCTION IMPLEMENTATION
// ============================================================================
// Component 2 of 8
// Secp256k1 curve implementation for EVM chain verification
// Full ECDSA signature creation, verification, and recovery
// ============================================================================

import {
  Field,
  Bool,
  Struct,
  Provable,
  Bytes,
  UInt32,
  UInt64,
  Poseidon,
  createForeignCurve,
  createEcdsa,
  Crypto,
} from 'o1js';

// ============================================================================
// SECP256K1 CURVE IMPLEMENTATION
// ============================================================================

export class Secp256k1 extends createForeignCurve(Crypto.CurveParams.Secp256k1) {
  static validatePoint(x: bigint, y: bigint): boolean {
    const p = Crypto.CurveParams.Secp256k1.modulus;
    const a = 0n;
    const b = 7n;
    
    const xMod = ((x % p) + p) % p;
    const yMod = ((y % p) + p) % p;
    
    const leftSide = (yMod * yMod) % p;
    const rightSide = (xMod * xMod * xMod + a * xMod + b) % p;
    
    return leftSide === rightSide;
  }

  static recoverPublicKey(
    messageHash: bigint,
    r: bigint,
    s: bigint,
    recoveryId: number
  ): { x: bigint; y: bigint } | null {
    const n = Crypto.CurveParams.Secp256k1.order;
    const p = Crypto.CurveParams.Secp256k1.modulus;
    const G = Crypto.CurveParams.Secp256k1.generator;
    
    if (r >= n || r === 0n) return null;
    if (s >= n || s === 0n) return null;
    if (recoveryId < 0 || recoveryId > 3) return null;

    const isYOdd = (recoveryId & 1) === 1;
    const isSecondKey = (recoveryId & 2) === 2;
    
    let x = r;
    if (isSecondKey) {
      x = r + n;
      if (x >= p) return null;
    }

    const yCubed = (x * x * x + 7n) % p;
    let y = this.modularSquareRoot(yCubed, p);
    if (y === null) return null;

    const yIsOdd = (y & 1n) === 1n;
    if (yIsOdd !== isYOdd) {
      y = p - y;
    }

    if (!this.validatePoint(x, y)) return null;

    const rInv = this.modInverse(r, n);
    if (rInv === null) return null;

    const u1 = (n - ((messageHash * rInv) % n)) % n;
    const u2 = (s * rInv) % n;

    const point1 = this.scalarMultiply(G.x, G.y, u1, n, p);
    const point2 = this.scalarMultiply(x, y, u2, n, p);
    
    if (!point1 || !point2) return null;

    const result = this.pointAdd(point1.x, point1.y, point2.x, point2.y, p);
    return result;
  }

  private static modularSquareRoot(a: bigint, p: bigint): bigint | null {
    if (p % 4n !== 3n) {
      return this.tonelliShanks(a, p);
    }
    
    const result = this.modPow(a, (p + 1n) / 4n, p);
    
    if (this.modPow(result, 2n, p) === a % p) {
      return result;
    }
    
    return null;
  }

  private static tonelliShanks(n: bigint, p: bigint): bigint | null {
    n = n % p;
    if (n === 0n) return 0n;
    if (this.modPow(n, (p - 1n) / 2n, p) !== 1n) return null;

    let q = p - 1n;
    let s = 0n;
    while (q % 2n === 0n) {
      q = q / 2n;
      s++;
    }

    let z = 2n;
    while (this.modPow(z, (p - 1n) / 2n, p) !== p - 1n) {
      z++;
    }

    let m = s;
    let c = this.modPow(z, q, p);
    let t = this.modPow(n, q, p);
    let r = this.modPow(n, (q + 1n) / 2n, p);

    while (t !== 1n) {
      let i = 1n;
      let temp = (t * t) % p;
      while (temp !== 1n && i < m) {
        temp = (temp * temp) % p;
        i++;
      }

      const b = this.modPow(c, this.modPow(2n, m - i - 1n, p - 1n), p);
      m = i;
      c = (b * b) % p;
      t = (t * c) % p;
      r = (r * b) % p;
    }

    return r;
  }

  private static modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    if (modulus === 1n) return 0n;
    
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

  private static modInverse(a: bigint, m: bigint): bigint | null {
    if (m === 1n) return null;
    
    const originalM = m;
    let x0 = 0n;
    let x1 = 1n;
    
    a = ((a % m) + m) % m;
    
    while (a > 1n) {
      if (m === 0n) return null;
      
      const quotient = a / m;
      let temp = m;
      
      m = a % m;
      a = temp;
      temp = x0;
      
      x0 = x1 - quotient * x0;
      x1 = temp;
    }
    
    if (x1 < 0n) {
      x1 += originalM;
    }
    
    return x1;
  }

  private static scalarMultiply(
    x: bigint,
    y: bigint,
    scalar: bigint,
    n: bigint,
    p: bigint
  ): { x: bigint; y: bigint } | null {
    if (scalar === 0n) return null;
    if (scalar < 0n) scalar = ((scalar % n) + n) % n;

    let resultX = x;
    let resultY = y;
    let k = scalar - 1n;

    while (k > 0n) {
      if (k & 1n) {
        const sum = this.pointAdd(resultX, resultY, x, y, p);
        if (!sum) return null;
        resultX = sum.x;
        resultY = sum.y;
      }
      
      const doubled = this.pointDouble(x, y, p);
      if (!doubled) return null;
      x = doubled.x;
      y = doubled.y;
      
      k = k >> 1n;
    }

    return { x: resultX, y: resultY };
  }

  private static pointAdd(
    x1: bigint,
    y1: bigint,
    x2: bigint,
    y2: bigint,
    p: bigint
  ): { x: bigint; y: bigint } | null {
    if (x1 === x2 && y1 === y2) {
      return this.pointDouble(x1, y1, p);
    }

    if (x1 === x2) {
      return null;
    }

    const dx = ((x2 - x1) % p + p) % p;
    const dy = ((y2 - y1) % p + p) % p;
    
    const dxInv = this.modInverse(dx, p);
    if (dxInv === null) return null;

    const slope = (dy * dxInv) % p;
    const x3 = ((slope * slope - x1 - x2) % p + p) % p;
    const y3 = ((slope * (x1 - x3) - y1) % p + p) % p;

    return { x: x3, y: y3 };
  }

  private static pointDouble(
    x: bigint,
    y: bigint,
    p: bigint
  ): { x: bigint; y: bigint } | null {
    const yInv = this.modInverse(2n * y, p);
    if (yInv === null) return null;

    const slope = ((3n * x * x) * yInv) % p;
    const x3 = ((slope * slope - 2n * x) % p + p) % p;
    const y3 = ((slope * (x - x3) - y) % p + p) % p;

    return { x: x3, y: y3 };
  }
}

// ============================================================================
// ECDSA SIGNATURE IMPLEMENTATION
// ============================================================================

export class Ecdsa extends createEcdsa(Secp256k1) {
  static verifyWithRecovery(
    messageHash: bigint,
    r: bigint,
    s: bigint,
    publicKeyX: bigint,
    publicKeyY: bigint
  ): boolean {
    if (!Secp256k1.validatePoint(publicKeyX, publicKeyY)) {
      return false;
    }

    const publicKey = new Secp256k1({
      x: Secp256k1.Field.from(publicKeyX),
      y: Secp256k1.Field.from(publicKeyY),
    });

    const signature = Ecdsa.fromScalars({ r, s });
    const messageBytes = Bytes.from([messageHash]);

    return signature.verify(messageBytes, publicKey).toBoolean();
  }

  static signMessage(
    messageHash: bigint,
    privateKey: bigint
  ): { r: bigint; s: bigint; v: number } {
    const signature = Ecdsa.sign(
      Bytes.from([messageHash]),
      privateKey
    );

    const { r, s } = signature.toBigInt();
    
    const recoveryId = this.calculateRecoveryId(messageHash, r, s, privateKey);
    const v = 27 + recoveryId;
    
    return { r, s, v };
  }

  private static calculateRecoveryId(
    messageHash: bigint,
    r: bigint,
    s: bigint,
    privateKey: bigint
  ): number {
    const G = Crypto.CurveParams.Secp256k1.generator;
    const publicKey = Secp256k1.scalarMultiply(G.x, G.y, privateKey, Crypto.CurveParams.Secp256k1.order, Crypto.CurveParams.Secp256k1.modulus);
    
    if (!publicKey) return 0;

    for (let i = 0; i < 4; i++) {
      const recovered = Secp256k1.recoverPublicKey(messageHash, r, s, i);
      if (recovered && recovered.x === publicKey.x && recovered.y === publicKey.y) {
        return i;
      }
    }

    return 0;
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
    const chainIdField = Field.from(this.chainId.value.toBigInt());
    const recoveryIdField = this.recoveryId;
    
    const expectedV = chainIdField.mul(2).add(35).add(recoveryIdField);
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

  static keccak256(data: Uint8Array): bigint {
    const { createHash } = require('crypto');
    const hash = createHash('sha3-256').update(data).digest();
    return BigInt('0x' + hash.toString('hex'));
  }

  static prefixEthereumMessage(message: string): Uint8Array {
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
// EVM ADDRESS UTILITIES
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
    const { createHash } = require('crypto');
    const hash = createHash('sha3-256').update(cleanAddress).digest('hex');
    
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
    
    const { createHash } = require('crypto');
    const hash = createHash('sha3-256').update(pubKeyBytes).digest();
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
// CHAIN VALIDATORS
// ============================================================================

export class ChainSignatureValidator {
  private static SUPPORTED_CHAINS = {
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

  static validateByChainId(chainId: number, proof: EvmSignatureProof): Bool {
    proof.chainId.value.assertEquals(Field(chainId));
    return proof.verifyEIP155();
  }

  static isChainSupported(chainId: number): boolean {
    return Object.values(this.SUPPORTED_CHAINS).includes(chainId);
  }

  static getChainName(chainId: number): string {
    const entry = Object.entries(this.SUPPORTED_CHAINS).find(([_, id]) => id === chainId);
    return entry ? entry[0] : 'UNKNOWN';
  }

  static getSupportedChains(): number[] {
    return Object.values(this.SUPPORTED_CHAINS);
  }
}
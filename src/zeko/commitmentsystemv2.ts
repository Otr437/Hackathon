// ============================================================================
// X402 COMMITMENT SYSTEM - DECEMBER 2025 PRODUCTION
// ============================================================================
// Component 4 of 8 - STANDALONE MODULE
// Transfer commitment creation, verification, storage, and utilities
// ============================================================================

import {
  Field,
  Poseidon,
  PublicKey,
  UInt64,
  UInt32,
  Bool,
  Struct,
} from 'o1js';

// ============================================================================
// TRANSFER COMMITMENT STRUCTURE
// ============================================================================

export class TransferCommitment extends Struct({
  hash: Field,
  amount: UInt64,
  recipientHash: Field,
  sourceChain: UInt32,
  targetChain: UInt32,
  timestamp: UInt64,
  nonce: Field,
}) {
  static create(
    amount: UInt64,
    recipient: Field,
    secret: Field,
    sourceChain: UInt32,
    targetChain: UInt32,
    timestamp: UInt64,
    nonce: Field
  ): TransferCommitment {
    const hash = Poseidon.hash([
      amount.value,
      recipient,
      secret,
      sourceChain.value,
      targetChain.value,
      timestamp.value,
      nonce,
    ]);

    const recipientHash = Poseidon.hash([recipient, secret]);

    return new TransferCommitment({
      hash,
      amount,
      recipientHash,
      sourceChain,
      targetChain,
      timestamp,
      nonce,
    });
  }

  verify(recipient: Field, secret: Field): Bool {
    const recomputedHash = Poseidon.hash([
      this.amount.value,
      recipient,
      secret,
      this.sourceChain.value,
      this.targetChain.value,
      this.timestamp.value,
      this.nonce,
    ]);

    const recomputedRecipientHash = Poseidon.hash([recipient, secret]);

    return this.hash
      .equals(recomputedHash)
      .and(this.recipientHash.equals(recomputedRecipientHash));
  }

  isExpired(currentTime: UInt64): Bool {
    const EXPIRY_SECONDS = UInt64.from(86400);
    const expiryTime = this.timestamp.add(EXPIRY_SECONDS);
    return currentTime.greaterThan(expiryTime);
  }

  toJSON(): {
    hash: string;
    amount: string;
    recipientHash: string;
    sourceChain: string;
    targetChain: string;
    timestamp: string;
    nonce: string;
  } {
    return {
      hash: this.hash.toString(),
      amount: this.amount.toString(),
      recipientHash: this.recipientHash.toString(),
      sourceChain: this.sourceChain.toString(),
      targetChain: this.targetChain.toString(),
      timestamp: this.timestamp.toString(),
      nonce: this.nonce.toString(),
    };
  }

  static fromJSON(json: {
    hash: string;
    amount: string;
    recipientHash: string;
    sourceChain: string;
    targetChain: string;
    timestamp: string;
    nonce: string;
  }): TransferCommitment {
    return new TransferCommitment({
      hash: Field.from(json.hash),
      amount: UInt64.from(json.amount),
      recipientHash: Field.from(json.recipientHash),
      sourceChain: UInt32.from(json.sourceChain),
      targetChain: UInt32.from(json.targetChain),
      timestamp: UInt64.from(json.timestamp),
      nonce: Field.from(json.nonce),
    });
  }
}

// ============================================================================
// COMMITMENT BUILDER
// ============================================================================

export class CommitmentBuilder {
  private amount?: UInt64;
  private recipient?: Field;
  private secret?: Field;
  private sourceChain?: UInt32;
  private targetChain?: UInt32;
  private timestamp?: UInt64;
  private nonce?: Field;

  setAmount(amount: bigint | UInt64 | number): CommitmentBuilder {
    if (amount instanceof UInt64) {
      this.amount = amount;
    } else if (typeof amount === 'number') {
      this.amount = UInt64.from(BigInt(amount));
    } else {
      this.amount = UInt64.from(amount);
    }
    return this;
  }

  setRecipient(recipient: Field | PublicKey | string): CommitmentBuilder {
    if (recipient instanceof Field) {
      this.recipient = recipient;
    } else if (recipient instanceof PublicKey) {
      this.recipient = CommitmentUtils.recipientFromPublicKey(recipient);
    } else {
      this.recipient = Field.from(BigInt(recipient));
    }
    return this;
  }

  setSecret(secret: Field | string | bigint): CommitmentBuilder {
    if (secret instanceof Field) {
      this.secret = secret;
    } else if (typeof secret === 'string') {
      const clean = secret.startsWith('0x') ? secret.slice(2) : secret;
      this.secret = Field.from(BigInt('0x' + clean));
    } else {
      this.secret = Field.from(secret);
    }
    return this;
  }

  setSourceChain(chainId: number | UInt32): CommitmentBuilder {
    if (chainId instanceof UInt32) {
      this.sourceChain = chainId;
    } else {
      this.sourceChain = UInt32.from(chainId);
    }
    return this;
  }

  setTargetChain(chainId: number | UInt32): CommitmentBuilder {
    if (chainId instanceof UInt32) {
      this.targetChain = chainId;
    } else {
      this.targetChain = UInt32.from(chainId);
    }
    return this;
  }

  setTimestamp(timestamp: bigint | UInt64 | number): CommitmentBuilder {
    if (timestamp instanceof UInt64) {
      this.timestamp = timestamp;
    } else if (typeof timestamp === 'number') {
      this.timestamp = UInt64.from(BigInt(timestamp));
    } else {
      this.timestamp = UInt64.from(timestamp);
    }
    return this;
  }

  setNonce(nonce: Field | string | bigint): CommitmentBuilder {
    if (nonce instanceof Field) {
      this.nonce = nonce;
    } else if (typeof nonce === 'string') {
      const clean = nonce.startsWith('0x') ? nonce.slice(2) : nonce;
      this.nonce = Field.from(BigInt('0x' + clean));
    } else {
      this.nonce = Field.from(nonce);
    }
    return this;
  }

  useCurrentTimestamp(): CommitmentBuilder {
    this.timestamp = UInt64.from(BigInt(Math.floor(Date.now() / 1000)));
    return this;
  }

  generateSecret(): CommitmentBuilder {
    this.secret = CommitmentUtils.generateSecret();
    return this;
  }

  generateNonce(): CommitmentBuilder {
    this.nonce = CommitmentUtils.generateNonce();
    return this;
  }

  build(): TransferCommitment {
    if (!this.amount) throw new Error('Amount not set');
    if (!this.recipient) throw new Error('Recipient not set');
    if (!this.secret) throw new Error('Secret not set');
    if (!this.sourceChain) throw new Error('Source chain not set');
    if (!this.targetChain) throw new Error('Target chain not set');
    if (!this.timestamp) throw new Error('Timestamp not set');
    if (!this.nonce) throw new Error('Nonce not set');

    return TransferCommitment.create(
      this.amount,
      this.recipient,
      this.secret,
      this.sourceChain,
      this.targetChain,
      this.timestamp,
      this.nonce
    );
  }

  buildWithDefaults(): TransferCommitment {
    if (!this.timestamp) this.useCurrentTimestamp();
    if (!this.secret) this.generateSecret();
    if (!this.nonce) this.generateNonce();
    return this.build();
  }

  reset(): CommitmentBuilder {
    this.amount = undefined;
    this.recipient = undefined;
    this.secret = undefined;
    this.sourceChain = undefined;
    this.targetChain = undefined;
    this.timestamp = undefined;
    this.nonce = undefined;
    return this;
  }
}

// ============================================================================
// COMMITMENT STORE
// ============================================================================

export class CommitmentStore {
  private commitments: Map<string, TransferCommitment>;
  private commitmentsByRecipient: Map<string, Set<string>>;
  private commitmentsByChain: Map<number, Set<string>>;
  private commitmentsByTimestamp: Map<number, Set<string>>;

  constructor() {
    this.commitments = new Map();
    this.commitmentsByRecipient = new Map();
    this.commitmentsByChain = new Map();
    this.commitmentsByTimestamp = new Map();
  }

  add(commitment: TransferCommitment): void {
    const hashStr = commitment.hash.toString();

    if (this.commitments.has(hashStr)) {
      throw new Error('Commitment already exists');
    }

    this.commitments.set(hashStr, commitment);

    const recipientHashStr = commitment.recipientHash.toString();
    if (!this.commitmentsByRecipient.has(recipientHashStr)) {
      this.commitmentsByRecipient.set(recipientHashStr, new Set());
    }
    this.commitmentsByRecipient.get(recipientHashStr)!.add(hashStr);

    const sourceChain = Number(commitment.sourceChain.value.toString());
    if (!this.commitmentsByChain.has(sourceChain)) {
      this.commitmentsByChain.set(sourceChain, new Set());
    }
    this.commitmentsByChain.get(sourceChain)!.add(hashStr);

    const targetChain = Number(commitment.targetChain.value.toString());
    if (!this.commitmentsByChain.has(targetChain)) {
      this.commitmentsByChain.set(targetChain, new Set());
    }
    this.commitmentsByChain.get(targetChain)!.add(hashStr);

    const timestampBucket = Math.floor(Number(commitment.timestamp.value.toString()) / 3600);
    if (!this.commitmentsByTimestamp.has(timestampBucket)) {
      this.commitmentsByTimestamp.set(timestampBucket, new Set());
    }
    this.commitmentsByTimestamp.get(timestampBucket)!.add(hashStr);
  }

  get(hash: Field): TransferCommitment | undefined {
    return this.commitments.get(hash.toString());
  }

  has(hash: Field): boolean {
    return this.commitments.has(hash.toString());
  }

  getByRecipient(recipientHash: Field): TransferCommitment[] {
    const hashes = this.commitmentsByRecipient.get(recipientHash.toString());
    if (!hashes) return [];

    return Array.from(hashes)
      .map(hash => this.commitments.get(hash))
      .filter((c): c is TransferCommitment => c !== undefined);
  }

  getByChain(chainId: number): TransferCommitment[] {
    const hashes = this.commitmentsByChain.get(chainId);
    if (!hashes) return [];

    return Array.from(hashes)
      .map(hash => this.commitments.get(hash))
      .filter((c): c is TransferCommitment => c !== undefined);
  }

  getByTimeRange(startTime: bigint, endTime: bigint): TransferCommitment[] {
    const startBucket = Math.floor(Number(startTime) / 3600);
    const endBucket = Math.floor(Number(endTime) / 3600);

    const results: TransferCommitment[] = [];

    for (let bucket = startBucket; bucket <= endBucket; bucket++) {
      const hashes = this.commitmentsByTimestamp.get(bucket);
      if (hashes) {
        hashes.forEach(hash => {
          const commitment = this.commitments.get(hash);
          if (commitment) {
            const timestamp = commitment.timestamp.value.toBigInt();
            if (timestamp >= startTime && timestamp <= endTime) {
              results.push(commitment);
            }
          }
        });
      }
    }

    return results;
  }

  getAll(): TransferCommitment[] {
    return Array.from(this.commitments.values());
  }

  size(): number {
    return this.commitments.size;
  }

  clear(): void {
    this.commitments.clear();
    this.commitmentsByRecipient.clear();
    this.commitmentsByChain.clear();
    this.commitmentsByTimestamp.clear();
  }

  remove(hash: Field): boolean {
    const hashStr = hash.toString();
    const commitment = this.commitments.get(hashStr);

    if (!commitment) return false;

    this.commitments.delete(hashStr);

    const recipientHashStr = commitment.recipientHash.toString();
    this.commitmentsByRecipient.get(recipientHashStr)?.delete(hashStr);

    const sourceChain = Number(commitment.sourceChain.value.toString());
    this.commitmentsByChain.get(sourceChain)?.delete(hashStr);

    const targetChain = Number(commitment.targetChain.value.toString());
    this.commitmentsByChain.get(targetChain)?.delete(hashStr);

    const timestampBucket = Math.floor(Number(commitment.timestamp.value.toString()) / 3600);
    this.commitmentsByTimestamp.get(timestampBucket)?.delete(hashStr);

    return true;
  }

  exportToJSON(): string {
    const data = Array.from(this.commitments.values()).map(c => c.toJSON());
    return JSON.stringify(data, null, 2);
  }

  importFromJSON(json: string): void {
    const data = JSON.parse(json);
    this.clear();

    data.forEach((item: any) => {
      const commitment = TransferCommitment.fromJSON(item);
      this.add(commitment);
    });
  }

  async saveToFile(filepath: string): Promise<void> {
    const fs = require('fs').promises;
    const json = this.exportToJSON();
    await fs.writeFile(filepath, json, 'utf8');
  }

  async loadFromFile(filepath: string): Promise<void> {
    const fs = require('fs').promises;
    const json = await fs.readFile(filepath, 'utf8');
    this.importFromJSON(json);
  }
}

// ============================================================================
// COMMITMENT UTILITIES
// ============================================================================

export class CommitmentUtils {
  static generateSecret(): Field {
    const crypto = require('crypto');
    const randomBytes = crypto.randomBytes(32);
    return Field.from(BigInt('0x' + randomBytes.toString('hex')));
  }

  static generateNonce(): Field {
    const crypto = require('crypto');
    const randomBytes = crypto.randomBytes(32);
    return Field.from(BigInt('0x' + randomBytes.toString('hex')));
  }

  static getCurrentTimestamp(): UInt64 {
    return UInt64.from(BigInt(Math.floor(Date.now() / 1000)));
  }

  static recipientFromPublicKey(publicKey: PublicKey): Field {
    return Poseidon.hash([publicKey.x, publicKey.y]);
  }

  static recipientFromAddress(address: string): Field {
    const cleanAddress = address.toLowerCase().startsWith('0x')
      ? address.slice(2)
      : address;
    return Field.from(BigInt('0x' + cleanAddress));
  }

  static sortByTimestamp(commitments: TransferCommitment[]): TransferCommitment[] {
    return commitments.sort((a, b) =>
      Number(a.timestamp.value.sub(b.timestamp.value).toString())
    );
  }

  static sortByAmount(commitments: TransferCommitment[]): TransferCommitment[] {
    return commitments.sort((a, b) =>
      Number(a.amount.value.sub(b.amount.value).toString())
    );
  }

  static filterByChain(
    commitments: TransferCommitment[],
    sourceChain?: number,
    targetChain?: number
  ): TransferCommitment[] {
    return commitments.filter(c => {
      if (sourceChain !== undefined && Number(c.sourceChain.value.toString()) !== sourceChain) {
        return false;
      }
      if (targetChain !== undefined && Number(c.targetChain.value.toString()) !== targetChain) {
        return false;
      }
      return true;
    });
  }

  static filterByAmount(
    commitments: TransferCommitment[],
    minAmount: bigint,
    maxAmount: bigint
  ): TransferCommitment[] {
    return commitments.filter(c => {
      const amount = c.amount.value.toBigInt();
      return amount >= minAmount && amount <= maxAmount;
    });
  }

  static filterExpired(
    commitments: TransferCommitment[],
    currentTime: bigint
  ): TransferCommitment[] {
    const currentTimeField = UInt64.from(currentTime);
    return commitments.filter(c => c.isExpired(currentTimeField).toBoolean());
  }

  static filterActive(
    commitments: TransferCommitment[],
    currentTime: bigint
  ): TransferCommitment[] {
    const currentTimeField = UInt64.from(currentTime);
    return commitments.filter(c => !c.isExpired(currentTimeField).toBoolean());
  }

  static groupByChain(
    commitments: TransferCommitment[]
  ): Map<number, TransferCommitment[]> {
    const groups = new Map<number, TransferCommitment[]>();

    commitments.forEach(c => {
      const sourceChain = Number(c.sourceChain.value.toString());
      if (!groups.has(sourceChain)) {
        groups.set(sourceChain, []);
      }
      groups.get(sourceChain)!.push(c);
    });

    return groups;
  }

  static groupByRecipient(
    commitments: TransferCommitment[]
  ): Map<string, TransferCommitment[]> {
    const groups = new Map<string, TransferCommitment[]>();

    commitments.forEach(c => {
      const recipientHash = c.recipientHash.toString();
      if (!groups.has(recipientHash)) {
        groups.set(recipientHash, []);
      }
      groups.get(recipientHash)!.push(c);
    });

    return groups;
  }

  static getTotalAmount(commitments: TransferCommitment[]): bigint {
    return commitments.reduce(
      (sum, c) => sum + c.amount.value.toBigInt(),
      0n
    );
  }

  static getStatistics(commitments: TransferCommitment[]): {
    total: number;
    totalAmount: bigint;
    averageAmount: bigint;
    uniqueRecipients: number;
    uniqueChains: number;
    oldestTimestamp: bigint;
    newestTimestamp: bigint;
  } {
    if (commitments.length === 0) {
      return {
        total: 0,
        totalAmount: 0n,
        averageAmount: 0n,
        uniqueRecipients: 0,
        uniqueChains: 0,
        oldestTimestamp: 0n,
        newestTimestamp: 0n,
      };
    }

    const totalAmount = this.getTotalAmount(commitments);
    const sorted = this.sortByTimestamp(commitments);

    const recipients = new Set(commitments.map(c => c.recipientHash.toString()));
    const chains = new Set(commitments.map(c => c.sourceChain.value.toString()));

    return {
      total: commitments.length,
      totalAmount,
      averageAmount: totalAmount / BigInt(commitments.length),
      uniqueRecipients: recipients.size,
      uniqueChains: chains.size,
      oldestTimestamp: sorted[0].timestamp.value.toBigInt(),
      newestTimestamp: sorted[sorted.length - 1].timestamp.value.toBigInt(),
    };
  }
}
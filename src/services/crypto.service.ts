import crypto from 'crypto';
import secrets from '@digitaldefiance/secrets';
import EthCrypto from 'eth-crypto';
import { ethers } from 'ethers';
import { KmsService } from './kms.service';

export class CryptoService {
  /**
   * Splits a private key hex string into strict 2-of-2 shares.
   * @param privateKeyHex 256-bit private key in hex
   * @returns Share B (for KMS/DB) and Share C (ephemeral for citizen)
   */
  static splitKey(privateKeyHex: string): { shareB: string; shareC: string } {
    const cleanKey = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
    const shares = secrets.share(cleanKey, 2, 2);
    return {
      shareB: shares[0],
      shareC: shares[1],
    };
  }

  /**
   * Combines 2 shares to reconstruct the private key hex.
   */
  static combineShares(share1: string, share2: string): string {
    return secrets.combine([share1, share2]);
  }

  /**
   * Generates a 256-bit (32 bytes) symmetric session key.
   */
  static generateSessionKey(): Buffer {
    return crypto.randomBytes(32);
  }

  /**
   * Encrypts a raw file buffer using AES-256-GCM.
   */
  static encryptFile(fileBuffer: Buffer, sessionKey: Buffer) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);

    let ciphertext = cipher.update(fileBuffer);
    const finalBuffer = cipher.final();
    ciphertext = Buffer.concat([ciphertext, finalBuffer]);
    const authTag = cipher.getAuthTag();

    return { ciphertext, iv, authTag };
  }

  /**
   * Decrypts a ciphertext buffer using AES-256-GCM.
   */
  static decryptFile(ciphertext: Buffer, sessionKey: Buffer, iv: Buffer, authTag: Buffer): Buffer {
    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ciphertext);
    const finalBuffer = decipher.final();
    return Buffer.concat([decrypted, finalBuffer]);
  }

  /**
   * Wraps (encrypts) the session key using the citizen's public key via ECIES.
   */
  static async wrapSessionKey(sessionKey: Buffer, publicKey: string) {
    const sessionKeyHex = sessionKey.toString('hex');
    const cleanPublicKey = publicKey.startsWith('0x') ? publicKey.slice(2) : publicKey;
    return await EthCrypto.encryptWithPublicKey(cleanPublicKey, sessionKeyHex);
  }

  /**
   * Unwraps (decrypts) the session key using the citizen's private key.
   */
  static async unwrapSessionKey(encryptedSessionKey: any, privateKey: string): Promise<Buffer> {
    const cleanPrivateKey = privateKey.startsWith('0x') ? privateKey.slice(2) : privateKey;
    const sessionKeyHex = await EthCrypto.decryptWithPrivateKey(cleanPrivateKey, encryptedSessionKey);
    return Buffer.from(sessionKeyHex, 'hex');
  }

  /**
   * Encrypts the session key with the server's MASTER_KMS_KEY for in-memory tamper forensics.
   */
  static encryptSessionKeyWithKms(sessionKey: Buffer) {
    const sessionKeyHex = sessionKey.toString('hex');
    return KmsService.encryptShareB(sessionKeyHex);
  }

  /**
   * Decrypts the KMS-encrypted session key for in-memory tamper forensics.
   */
  static decryptSessionKeyWithKms(encryptedKey: string, iv: string, authTag: string): Buffer {
    const sessionKeyHex = KmsService.decryptShareB(encryptedKey, iv, authTag);
    return Buffer.from(sessionKeyHex, 'hex');
  }

  /**
   * Embeds an invisible forensic trailer watermark into the document buffer
   * before Keccak-256 hashing and IPFS encryption.
   */
  static embedDocumentWatermark(buffer: Buffer, documentId: string): Buffer {
    const marker = Buffer.from(`\n%%CONSORTIUM-DOC-ID:${documentId}%%\n`, 'utf8');
    return Buffer.concat([buffer, marker]);
  }

  /**
   * Extracts the embedded documentId watermark from an uploaded buffer (zero-hint forensics).
   */
  static extractDocumentWatermark(buffer: Buffer): string | null {
    // Scan trailer window first (last 2048 bytes)
    const trailerWindow = buffer.subarray(Math.max(0, buffer.length - 2048)).toString('utf8');
    const trailerMatch = trailerWindow.match(/%%CONSORTIUM-DOC-ID:([a-fA-F0-9-]+)%%/);
    if (trailerMatch) {
      return trailerMatch[1];
    }

    // Fallback: scan whole buffer as string
    const fullText = buffer.toString('utf8');
    const fullMatch = fullText.match(/%%CONSORTIUM-DOC-ID:([a-fA-F0-9-]+)%%/);
    return fullMatch ? fullMatch[1] : null;
  }

  /**
   * Splits a buffer into fixed 4KB chunks and computes Keccak-256 chunk hashes.
   */
  static computeChunkHashes(buffer: Buffer, chunkSize: number = 4096): string[] {
    const hashes: string[] = [];
    for (let i = 0; i < buffer.length; i += chunkSize) {
      const chunk = buffer.subarray(i, Math.min(i + chunkSize, buffer.length));
      hashes.push(ethers.keccak256(chunk));
    }
    return hashes;
  }

  /**
   * Compares an uploaded buffer's 4KB chunks against authentic chunk hashes.
   */
  static compareChunkHashes(
    authenticChunkHashes: string[],
    uploadedBuffer: Buffer,
    chunkSize: number = 4096
  ) {
    const uploadedChunkHashes = this.computeChunkHashes(uploadedBuffer, chunkSize);
    const maxChunks = Math.max(authenticChunkHashes.length, uploadedChunkHashes.length);
    const intactChunkIndices: number[] = [];
    const corruptedChunkIndices: number[] = [];

    for (let i = 0; i < maxChunks; i++) {
      const authHash = authenticChunkHashes[i];
      const upHash = uploadedChunkHashes[i];
      if (authHash && upHash && authHash === upHash) {
        intactChunkIndices.push(i);
      } else {
        corruptedChunkIndices.push(i);
      }
    }

    return {
      totalChunks: authenticChunkHashes.length,
      uploadedChunks: uploadedChunkHashes.length,
      intactChunksCount: intactChunkIndices.length,
      corruptedChunksCount: corruptedChunkIndices.length,
      intactChunkIndices,
      corruptedChunkIndices,
    };
  }

  /**
   * Delegates KMS Share B encryption to KmsService.
   */
  static encryptShareB(shareB: string) {
    return KmsService.encryptShareB(shareB);
  }

  /**
   * Delegates KMS Share B decryption to KmsService.
   */
  static decryptShareB(encryptedShareB: string, iv: string, authTag: string) {
    return KmsService.decryptShareB(encryptedShareB, iv, authTag);
  }
}

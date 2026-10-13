import crypto from 'crypto';
import secrets from '@digitaldefiance/secrets';
import EthCrypto from 'eth-crypto';
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

import crypto from 'crypto';
import secrets from '@digitaldefiance/secrets';
import EthCrypto from 'eth-crypto';

// Use a deterministic MASTER_KMS_KEY for dev/test if not in env
const MASTER_KMS_KEY = process.env.MASTER_KMS_KEY || '0000000000000000000000000000000000000000000000000000000000000000';

export class CryptoService {
  /**
   * Splits a private key hex string into 3 shares with a threshold of 2.
   * @param privateKeyHex 256-bit private key in hex
   */
  static splitKey(privateKeyHex: string) {
    // Strip '0x' if present
    const cleanKey = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
    // secrets.share expects a hex string
    const shares = secrets.share(cleanKey, 3, 2);
    return {
      shareA: shares[0],
      shareB: shares[1],
      shareC: shares[2]
    };
  }

  /**
   * Combines any 2 valid shares to reconstruct the private key.
   */
  static combineShares(share1: string, share2: string): string {
    const combined = secrets.combine([share1, share2]);
    // Optionally pad or add '0x' depending on downstream requirements,
    // but typically we'll return raw hex.
    return combined;
  }

  /**
   * Generates a 256-bit (32 bytes) symmetric session key.
   */
  static generateSessionKey(): Buffer {
    return crypto.randomBytes(32);
  }

  /**
   * Encrypts a raw file buffer using AES-256-GCM and the session key.
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
   * EthCrypto expects the public key as a 130-character hex string (with or without '0x' prefix).
   */
  static async wrapSessionKey(sessionKey: Buffer, publicKey: string) {
    const sessionKeyHex = sessionKey.toString('hex');
    const encrypted = await EthCrypto.encryptWithPublicKey(publicKey, sessionKeyHex);
    return encrypted; // { iv, ephemPublicKey, ciphertext, mac }
  }

  /**
   * Unwraps (decrypts) the session key using the citizen's private key.
   */
  static async unwrapSessionKey(encryptedSessionKey: any, privateKey: string): Promise<Buffer> {
    const sessionKeyHex = await EthCrypto.decryptWithPrivateKey(privateKey, encryptedSessionKey);
    return Buffer.from(sessionKeyHex, 'hex');
  }

  /**
   * Symmetrically encrypts Share B using the MASTER_KMS_KEY for safe storage.
   */
  static encryptShareB(shareB: string): string {
    const iv = crypto.randomBytes(12);
    const key = Buffer.from(MASTER_KMS_KEY, 'hex'); 
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let ciphertext = cipher.update(shareB, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    // Store as IV : AuthTag : Ciphertext
    return `${iv.toString('hex')}:${authTag}:${ciphertext}`;
  }

  /**
   * Decrypts an encrypted Share B using the MASTER_KMS_KEY.
   */
  static decryptShareB(encryptedShareBPayload: string): string {
    const parts = encryptedShareBPayload.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted Share B payload');
    }
    const [ivHex, authTagHex, ciphertextHex] = parts;
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const key = Buffer.from(MASTER_KMS_KEY, 'hex');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ciphertextHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}

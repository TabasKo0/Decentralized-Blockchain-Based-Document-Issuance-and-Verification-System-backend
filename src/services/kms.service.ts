import crypto from 'crypto';

export class KmsService {
  /**
   * Derives a 32-byte Buffer from MASTER_KMS_KEY.
   */
  private static getKeyBuffer(): Buffer {
    const rawKey = process.env.MASTER_KMS_KEY || '0000000000000000000000000000000000000000000000000000000000000000';
    if (rawKey.length === 64 && /^[0-9a-fA-F]+$/.test(rawKey)) {
      return Buffer.from(rawKey, 'hex');
    }
    return crypto.createHash('sha256').update(rawKey).digest();
  }

  /**
   * Symmetrically encrypts Share B using AES-256-GCM.
   * @param shareB Raw Shamir Share B string.
   * @returns Encrypted Share B, IV hex, and AuthTag hex.
   */
  static encryptShareB(shareB: string): { encryptedShareB: string; iv: string; authTag: string } {
    const key = this.getKeyBuffer();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let ciphertext = cipher.update(shareB, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    return {
      encryptedShareB: ciphertext,
      iv: iv.toString('hex'),
      authTag,
    };
  }

  /**
   * Decrypts AES-256-GCM encrypted Share B using the MASTER_KMS_KEY.
   * @param encryptedShareB Hex ciphertext.
   * @param iv Hex initialization vector.
   * @param authTag Hex authentication tag.
   * @returns Decrypted Share B string.
   */
  static decryptShareB(encryptedShareB: string, iv: string, authTag: string): string {
    const key = this.getKeyBuffer();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    let decrypted = decipher.update(encryptedShareB, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}

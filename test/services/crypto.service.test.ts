import * as dotenv from 'dotenv';
dotenv.config();

import { expect } from 'chai';
import { CryptoService } from '../../src/services/crypto.service';
import EthCrypto from 'eth-crypto';

describe('CryptoService', function () {
  const dummyPrivateKey = '0x1111111111111111111111111111111111111111111111111111111111111111'; // 32 bytes

  describe('Shamir\'s Secret Sharing (Strict 2-of-2)', function () {
    it('should split and combine keys correctly with strict 2-of-2 threshold', function () {
      const shares = CryptoService.splitKey(dummyPrivateKey);

      expect(shares).to.have.property('shareB');
      expect(shares).to.have.property('shareC');

      // Combine Share B and Share C
      const recoveredBC = CryptoService.combineShares(shares.shareB, shares.shareC);
      expect(recoveredBC).to.equal(dummyPrivateKey.slice(2));
    });
  });

  describe('Hybrid Envelope Encryption', function () {
    const dummyFile = Buffer.from('Hello, Decentralized World!', 'utf8');

    it('should generate a 32-byte session key', function () {
      const sessionKey = CryptoService.generateSessionKey();
      expect(sessionKey).to.be.instanceOf(Buffer);
      expect(sessionKey.length).to.equal(32);
    });

    it('should encrypt and decrypt a file buffer', function () {
      const sessionKey = CryptoService.generateSessionKey();

      const { ciphertext, iv, authTag } = CryptoService.encryptFile(dummyFile, sessionKey);
      expect(ciphertext).to.be.instanceOf(Buffer);
      expect(ciphertext.length).to.be.greaterThan(0);

      const decrypted = CryptoService.decryptFile(ciphertext, sessionKey, iv, authTag);
      expect(decrypted.toString('utf8')).to.equal('Hello, Decentralized World!');
    });

    it('should throw an error when decrypting with a tampered authTag', function () {
      const sessionKey = CryptoService.generateSessionKey();

      const { ciphertext, iv, authTag } = CryptoService.encryptFile(dummyFile, sessionKey);

      // Tamper with the authTag by flipping a bit
      const tamperedAuthTag = Buffer.from(authTag);
      tamperedAuthTag[0] ^= 1;

      expect(() => {
        CryptoService.decryptFile(ciphertext, sessionKey, iv, tamperedAuthTag);
      }).to.throw();
    });
  });

  describe('ECIES Session Key Wrapping', function () {
    it('should wrap and unwrap session key using EthCrypto', async function () {
      const identity = EthCrypto.createIdentity(); // { privateKey, publicKey, address }
      const sessionKey = CryptoService.generateSessionKey();

      const encryptedSessionKey = await CryptoService.wrapSessionKey(sessionKey, identity.publicKey);

      const unwrappedSessionKey = await CryptoService.unwrapSessionKey(encryptedSessionKey, identity.privateKey);

      expect(unwrappedSessionKey.toString('hex')).to.equal(sessionKey.toString('hex'));
    });
  });

  describe('KMS Share B Encryption', function () {
    it('should encrypt and decrypt Share B payload symmetrically', function () {
      const shares = CryptoService.splitKey(dummyPrivateKey);
      const shareB = shares.shareB;

      const { encryptedShareB, iv, authTag } = CryptoService.encryptShareB(shareB);

      expect(encryptedShareB).to.be.a('string');
      expect(iv).to.be.a('string');
      expect(authTag).to.be.a('string');

      const decryptedShareB = CryptoService.decryptShareB(encryptedShareB, iv, authTag);
      expect(decryptedShareB).to.equal(shareB);
    });
  });

  describe('Self-Identifying Watermarking & Forensics', function () {
    const testDocId = '873d7b59-e7bd-45c2-8fe7-bd3ab7782b37';
    const rawBuffer = Buffer.from('Official Degree Certificate Content', 'utf8');

    it('should embed and extract document watermark', function () {
      const stamped = CryptoService.embedDocumentWatermark(rawBuffer, testDocId);
      expect(stamped.length).to.be.greaterThan(rawBuffer.length);

      const extracted = CryptoService.extractDocumentWatermark(stamped);
      expect(extracted).to.equal(testDocId);
    });

    it('should extract watermark even if body content is modified', function () {
      const stamped = CryptoService.embedDocumentWatermark(rawBuffer, testDocId);
      // Tamper with content in the middle
      const tampered = Buffer.from(stamped);
      tampered[5] = 0x58; // modify one byte

      const extracted = CryptoService.extractDocumentWatermark(tampered);
      expect(extracted).to.equal(testDocId);
    });

    it('should compute chunk hashes and detect corrupted 4KB chunks', function () {
      const largeBuffer = Buffer.alloc(10000, 0x41); // ~10KB (3 chunks)
      const chunkHashes = CryptoService.computeChunkHashes(largeBuffer, 4096);
      expect(chunkHashes.length).to.equal(3);

      // Tamper in chunk 1 (offset 5000)
      const tampered = Buffer.from(largeBuffer);
      tampered[5000] = 0x42;

      const comparison = CryptoService.compareChunkHashes(chunkHashes, tampered, 4096);
      expect(comparison.totalChunks).to.equal(3);
      expect(comparison.intactChunksCount).to.equal(2);
      expect(comparison.corruptedChunksCount).to.equal(1);
      expect(comparison.corruptedChunkIndices).to.deep.equal([1]);
    });

    it('should encrypt and decrypt session key with KMS', function () {
      const sessionKey = CryptoService.generateSessionKey();
      const wrapped = CryptoService.encryptSessionKeyWithKms(sessionKey);
      expect(wrapped).to.have.property('encryptedShareB');

      const unwrapped = CryptoService.decryptSessionKeyWithKms(wrapped.encryptedShareB, wrapped.iv, wrapped.authTag);
      expect(unwrapped.toString('hex')).to.equal(sessionKey.toString('hex'));
    });
  });
});

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
});

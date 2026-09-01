import * as dotenv from 'dotenv';
dotenv.config();

import { expect } from 'chai';
import { CryptoService } from '../../src/services/crypto.service';
import EthCrypto from 'eth-crypto';

describe('CryptoService', function () {
  const dummyPrivateKey = '0x1111111111111111111111111111111111111111111111111111111111111111'; // 32 bytes

  describe('Shamir\'s Secret Sharing', function () {
    it('should split and combine keys correctly with 2-of-3 threshold', function () {
      const shares = CryptoService.splitKey(dummyPrivateKey);
      
      expect(shares).to.have.property('shareA');
      expect(shares).to.have.property('shareB');
      expect(shares).to.have.property('shareC');

      // Combine A and B
      const recoveredAB = CryptoService.combineShares(shares.shareA, shares.shareB);
      expect(recoveredAB).to.equal(dummyPrivateKey.slice(2)); // combined returns without 0x

      // Combine B and C
      const recoveredBC = CryptoService.combineShares(shares.shareB, shares.shareC);
      expect(recoveredBC).to.equal(dummyPrivateKey.slice(2));

      // Combine A and C
      const recoveredAC = CryptoService.combineShares(shares.shareA, shares.shareC);
      expect(recoveredAC).to.equal(dummyPrivateKey.slice(2));
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
      // Just split a key to get a valid looking share
      const shares = CryptoService.splitKey(dummyPrivateKey);
      const shareB = shares.shareB;

      const encryptedPayload = CryptoService.encryptShareB(shareB);
      
      // Should be in format IV:AuthTag:Ciphertext
      const parts = encryptedPayload.split(':');
      expect(parts.length).to.equal(3);

      const decryptedShareB = CryptoService.decryptShareB(encryptedPayload);
      expect(decryptedShareB).to.equal(shareB);
    });
  });
});

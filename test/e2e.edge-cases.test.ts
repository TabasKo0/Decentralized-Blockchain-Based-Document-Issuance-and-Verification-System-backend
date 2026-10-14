import { expect } from 'chai';
import request from 'supertest';
import sinon from 'sinon';
import jwt from 'jsonwebtoken';
import EthCrypto from 'eth-crypto';
import crypto from 'crypto';
import { ethers } from 'ethers';
import app from '../src/app';
import { prisma } from '../src/db';
import { RelayerService } from '../src/services/relayer.service';
import { PinataService } from '../src/services/pinata.service';
import { CryptoService } from '../src/services/crypto.service';
import { setReadOnlyContractOverride } from '../src/controllers/document.controller';

describe('Comprehensive Automated Edge-Case & Security Test Suite', function () {
  this.timeout(15000);

  const JWT_SECRET = process.env.JWT_SECRET || 'YOUR_SUPER_SECRET_JWT_KEY';
  const MASTER_KMS_KEY =
    process.env.MASTER_KMS_KEY ||
    '0000000000000000000000000000000000000000000000000000000000000000';

  // Test Entities
  const citizenAIdentity = EthCrypto.createIdentity();
  const citizenBIdentity = EthCrypto.createIdentity();

  const userIssuerA = {
    address: '0x1111111111111111111111111111111111111111',
    role: 'ISSUER' as const,
  };
  const userIssuerB = {
    address: '0x2222222222222222222222222222222222222222',
    role: 'ISSUER' as const,
  };
  const userCitizenA = {
    address: ethers.getAddress(citizenAIdentity.address),
    role: 'CITIZEN' as const,
    publicKey: citizenAIdentity.publicKey,
  };
  const userCitizenB = {
    address: ethers.getAddress(citizenBIdentity.address),
    role: 'CITIZEN' as const,
    publicKey: citizenBIdentity.publicKey,
  };

  let tokenIssuerA: string;
  let tokenIssuerB: string;
  let tokenCitizenA: string;
  let tokenCitizenB: string;

  // In-Memory Pinata Storage & On-Chain Document Simulator
  const pinataStorage = new Map<string, any>();
  let ipfsCounter = 0;

  const createdDocIds: string[] = [];
  const createdGrantTokens: string[] = [];

  before(async function () {
    // 1. Seed or Upsert Test Users in PostgreSQL
    await prisma.user.upsert({
      where: { address: userIssuerA.address },
      update: { role: userIssuerA.role },
      create: { address: userIssuerA.address, role: userIssuerA.role },
    });
    await prisma.user.upsert({
      where: { address: userIssuerB.address },
      update: { role: userIssuerB.role },
      create: { address: userIssuerB.address, role: userIssuerB.role },
    });
    await prisma.user.upsert({
      where: { address: userCitizenA.address },
      update: { role: userCitizenA.role, publicKey: userCitizenA.publicKey },
      create: {
        address: userCitizenA.address,
        role: userCitizenA.role,
        publicKey: userCitizenA.publicKey,
      },
    });
    await prisma.user.upsert({
      where: { address: userCitizenB.address },
      update: { role: userCitizenB.role, publicKey: userCitizenB.publicKey },
      create: {
        address: userCitizenB.address,
        role: userCitizenB.role,
        publicKey: userCitizenB.publicKey,
      },
    });

    // 2. Generate Real JWTs
    tokenIssuerA = jwt.sign(
      { address: userIssuerA.address, role: 'ISSUER' },
      JWT_SECRET,
      { expiresIn: '2h' }
    );
    tokenIssuerB = jwt.sign(
      { address: userIssuerB.address, role: 'ISSUER' },
      JWT_SECRET,
      { expiresIn: '2h' }
    );
    tokenCitizenA = jwt.sign(
      { address: userCitizenA.address, role: 'CITIZEN' },
      JWT_SECRET,
      { expiresIn: '2h' }
    );
    tokenCitizenB = jwt.sign(
      { address: userCitizenB.address, role: 'CITIZEN' },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    // 3. Stub Pinata Network I/O
    sinon.stub(PinataService, 'pinJSONToIPFS').callsFake(async (payload: any) => {
      ipfsCounter++;
      const cid = `QmDeterministicMockCid_${ipfsCounter.toString().padStart(6, '0')}`;
      pinataStorage.set(cid, payload);
      return cid;
    });

    sinon.stub(PinataService, 'fetchFromIPFS').callsFake(async (cid: string) => {
      if (pinataStorage.has(cid)) {
        return pinataStorage.get(cid);
      }
      throw new Error(`Mock IPFS CID not found: ${cid}`);
    });

    // 4. Stub Relayer Sepolia Network I/O
    sinon.stub(RelayerService.prototype, 'issueDocument').callsFake(async () => {
      return {
        hash: `0xmockIssueTxHash_${Date.now()}`,
        blockNumber: 11900000,
      } as any;
    });

    sinon.stub(RelayerService.prototype, 'revokeDocument').callsFake(async () => {
      return {
        hash: `0xmockRevokeTxHash_${Date.now()}`,
        blockNumber: 11900001,
      } as any;
    });

    sinon.stub(RelayerService.prototype, 'supersedeDocument').callsFake(async () => {
      return {
        hash: `0xmockSupersedeTxHash_${Date.now()}`,
        blockNumber: 11900002,
      } as any;
    });

    // 5. Override Live Sepolia Read-Only Contract with In-Memory DB Simulator
    setReadOnlyContractOverride({
      documents: async (hash: string) => {
        const doc = await prisma.documentMetadata.findUnique({
          where: { documentHash: hash },
        });
        if (!doc) {
          return {
            documentHash: hash,
            issuer: ethers.ZeroAddress,
            citizen: ethers.ZeroAddress,
            docType: '',
            issuedAt: 0n,
            isRevoked: false,
            revocationReason: '',
            supersededBy: ethers.ZeroHash,
            expiresAt: 0n,
          };
        }
        return {
          documentHash: hash,
          issuer: doc.issuerAddress,
          citizen: doc.citizenAddress,
          docType: doc.docType,
          issuedAt: BigInt(Math.floor(doc.createdAt.getTime() / 1000)),
          isRevoked: doc.isRevoked,
          revocationReason: doc.revocationReason || '',
          supersededBy: doc.supersededByHash || ethers.ZeroHash,
          expiresAt: doc.expiresAt ? BigInt(Math.floor(doc.expiresAt.getTime() / 1000)) : 0n,
        };
      },
      isIssuer: async (addr: string) => true,
    });
  });

  after(async function () {
    // Restore all Sinon stubs & contract override
    sinon.restore();
    setReadOnlyContractOverride(null);

    // Clean up test verification grants and documents created in DB
    try {
      if (createdGrantTokens.length > 0) {
        await prisma.verificationGrant.deleteMany({
          where: { token: { in: createdGrantTokens } },
        });
      }
      if (createdDocIds.length > 0) {
        await prisma.verificationGrant.deleteMany({
          where: { documentId: { in: createdDocIds } },
        });
        await prisma.documentMetadata.deleteMany({
          where: { id: { in: createdDocIds } },
        });
      }
      await prisma.user.deleteMany({
        where: {
          address: {
            in: [
              userIssuerA.address,
              userIssuerB.address,
              userCitizenA.address,
              userCitizenB.address,
            ],
          },
        },
      });
    } catch (cleanupErr) {
      console.warn('Test cleanup warning:', cleanupErr);
    }
  });

  // =========================================================================
  // Category A: Ephemeral Grants & High-Concurrency Race Conditions
  // =========================================================================
  describe('Category A: Ephemeral Grants & High-Concurrency Race Conditions', function () {
    let testDocId: string;

    before(async function () {
      // Issue a base document for grant testing
      const res = await request(app)
        .post('/api/documents/issue')
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .attach('file', Buffer.from('Grant Test Document Content', 'utf8'), 'grant_test.pdf')
        .field('citizenAddress', userCitizenA.address)
        .field('docType', 'GrantDiploma');

      expect(res.status).to.equal(200);
      testDocId = res.body.documentId;
      createdDocIds.push(testDocId);
    });

    it('1. Parallel Race Condition Test: exactly 1 request returns 200 OK and 9 return 410 Gone (SELF_DESTRUCTED)', async function () {
      // Create a single-view grant
      const grantRes = await request(app)
        .post(`/api/documents/${testDocId}/grant`)
        .set('Authorization', `Bearer ${tokenCitizenA}`)
        .send({ maxViews: 1, ttlMinutes: 60, granteeLabel: 'Concurrent Employer Check' });

      expect(grantRes.status).to.equal(200);
      const grantToken = grantRes.body.token;
      createdGrantTokens.push(grantToken);

      // Fire 10 parallel requests concurrently
      const responses = await Promise.all(
        Array.from({ length: 10 }, () =>
          request(app).get(`/api/documents/verify-grant/${grantToken}`)
        )
      );

      const successResponses = responses.filter((r) => r.status === 200);
      const destructedResponses = responses.filter((r) => r.status === 410);

      expect(successResponses.length).to.equal(1);
      expect(destructedResponses.length).to.equal(9);

      expect(successResponses[0].body.verificationStatus).to.equal('AUTHENTIC');
      destructedResponses.forEach((r) => {
        expect(r.body.status).to.equal('SELF_DESTRUCTED');
        expect(r.body.verificationStatus).to.equal('VIEW_LIMIT_EXHAUSTED');
      });
    });

    it('2. TTL Expiration: grant with expiresAt in the past returns 410 Gone (GRANT_EXPIRED) with viewCount: 0', async function () {
      const expiredToken = crypto.randomBytes(32).toString('hex');
      createdGrantTokens.push(expiredToken);

      await prisma.verificationGrant.create({
        data: {
          token: expiredToken,
          documentId: testDocId,
          maxViews: 5,
          viewCount: 0,
          expiresAt: new Date(Date.now() - 60000), // 1 minute in the past
          granteeLabel: 'Expired Grant Test',
        },
      });

      const res = await request(app).get(`/api/documents/verify-grant/${expiredToken}`);
      expect(res.status).to.equal(410);
      expect(res.body.status).to.equal('SELF_DESTRUCTED');
      expect(res.body.verificationStatus).to.equal('GRANT_EXPIRED');
    });

    it('3. Cascade Revocation: revoking parent document causes grant with remaining views to return 410 Gone', async function () {
      // Create grant with 10 views
      const grantRes = await request(app)
        .post(`/api/documents/${testDocId}/grant`)
        .set('Authorization', `Bearer ${tokenCitizenA}`)
        .send({ maxViews: 10, ttlMinutes: 60, granteeLabel: 'Cascade Revocation Test' });

      expect(grantRes.status).to.equal(200);
      const grantToken = grantRes.body.token;
      createdGrantTokens.push(grantToken);

      // Verify 1 view works
      const view1 = await request(app).get(`/api/documents/verify-grant/${grantToken}`);
      expect(view1.status).to.equal(200);

      // Revoke the parent document
      await prisma.documentMetadata.update({
        where: { id: testDocId },
        data: { isRevoked: true, revocationReason: 'Parent document revoked' },
      });

      // Next view must immediately return 410 Gone
      const view2 = await request(app).get(`/api/documents/verify-grant/${grantToken}`);
      expect(view2.status).to.equal(410);
      expect(view2.body.status).to.equal('SELF_DESTRUCTED');
      expect(view2.body.verificationStatus).to.equal('REVOKED_ON_CHAIN');

      // Restore document revoked status for subsequent tests
      await prisma.documentMetadata.update({
        where: { id: testDocId },
        data: { isRevoked: false, revocationReason: null },
      });
    });

    it('4. Invalid Token Format: random/non-existent token returns 404 Not Found', async function () {
      const res = await request(app).get('/api/documents/verify-grant/non-existent-random-token-xyz');
      expect(res.status).to.equal(404);
      expect(res.body.verificationStatus).to.equal('UNREGISTERED_DOCUMENT');
    });
  });

  // =========================================================================
  // Category B: RBAC & Cross-Tenant Authorization Attacks
  // =========================================================================
  describe('Category B: RBAC & Cross-Tenant Authorization Attacks', function () {
    let docAId: string;

    before(async function () {
      const res = await request(app)
        .post('/api/documents/issue')
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .attach('file', Buffer.from('Doc A for RBAC tests', 'utf8'), 'rbac_doc_a.pdf')
        .field('citizenAddress', userCitizenA.address)
        .field('docType', 'DegreeA');

      docAId = res.body.documentId;
      createdDocIds.push(docAId);
    });

    it('5. Unauthenticated requests to /issue, /:id/download, /:id/grant, /:id/revoke, /:id/supersede return 401', async function () {
      const r1 = await request(app).post('/api/documents/issue');
      expect(r1.status).to.equal(401);

      const r2 = await request(app).get(`/api/documents/${docAId}/download`);
      expect(r2.status).to.equal(401);

      const r3 = await request(app).post(`/api/documents/${docAId}/grant`);
      expect(r3.status).to.equal(401);

      const r4 = await request(app).post(`/api/documents/${docAId}/revoke`);
      expect(r4.status).to.equal(401);

      const r5 = await request(app).post(`/api/documents/${docAId}/supersede`);
      expect(r5.status).to.equal(401);
    });

    it('6. A CITIZEN JWT attempting to call /issue, /:id/revoke, or /:id/supersede returns 403 Forbidden', async function () {
      const rIssue = await request(app)
        .post('/api/documents/issue')
        .set('Authorization', `Bearer ${tokenCitizenA}`)
        .attach('file', Buffer.from('Unauthorized issuance', 'utf8'), 'unauth.pdf')
        .field('citizenAddress', userCitizenA.address)
        .field('docType', 'Degree');
      expect(rIssue.status).to.equal(403);
      expect(rIssue.body.message).to.include('Requires ISSUER role');

      const rRevoke = await request(app)
        .post(`/api/documents/${docAId}/revoke`)
        .set('Authorization', `Bearer ${tokenCitizenA}`)
        .send({ reason: 'Citizen attempt' });
      expect(rRevoke.status).to.equal(403);

      const rSupersede = await request(app)
        .post(`/api/documents/${docAId}/supersede`)
        .set('Authorization', `Bearer ${tokenCitizenA}`)
        .send({ newDocumentId: docAId });
      expect(rSupersede.status).to.equal(403);
    });

    it('7. Cross-Citizen Snooping: Citizen B attempting to download or grant on Citizen A document returns 403', async function () {
      const rDl = await request(app)
        .get(`/api/documents/${docAId}/download`)
        .set('Authorization', `Bearer ${tokenCitizenB}`);
      expect(rDl.status).to.equal(403);
      expect(rDl.body.message).to.include('Forbidden');

      const rGrant = await request(app)
        .post(`/api/documents/${docAId}/grant`)
        .set('Authorization', `Bearer ${tokenCitizenB}`)
        .send({ maxViews: 1, ttlMinutes: 60 });
      expect(rGrant.status).to.equal(403);
      expect(rGrant.body.message).to.include('Forbidden');
    });

    it('8. Cross-Issuer Revocation: Issuer B attempting to revoke a document issued by Issuer A returns 403', async function () {
      const rRevoke = await request(app)
        .post(`/api/documents/${docAId}/revoke`)
        .set('Authorization', `Bearer ${tokenIssuerB}`)
        .send({ reason: 'Malicious revocation by Issuer B' });
      expect(rRevoke.status).to.equal(403);
      expect(rRevoke.body.message).to.include('Only the original issuer can revoke');
    });
  });

  // =========================================================================
  // Category C: Multi-Chunk (12KB+) Tamper Forensics & Verdict Classifications
  // =========================================================================
  describe('Category C: Multi-Chunk (12KB+) Tamper Forensics & Verdict Classifications', function () {
    let multiDocId: string;
    let authenticStampedBuffer: Buffer;
    const SECRET_PAYLOAD_STRING = 'TOP_SECRET_MEDICAL_GENOMIC_DATA_XYZZY';

    before(async function () {
      // Generate a ~14KB payload containing the secret token across 4 chunks (each chunk 4096 bytes)
      const baseBody = Buffer.alloc(14000, 0x61); // filled with 'a'
      baseBody.write(SECRET_PAYLOAD_STRING, 500, 'utf8');

      const issueRes = await request(app)
        .post('/api/documents/issue')
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .attach('file', baseBody, 'multi_chunk_doc.pdf')
        .field('citizenAddress', userCitizenA.address)
        .field('docType', 'MultiChunkDiploma');

      expect(issueRes.status).to.equal(200);
      multiDocId = issueRes.body.documentId;
      createdDocIds.push(multiDocId);

      // Download the authentic watermarked file
      const dlRes = await request(app)
        .get(`/api/documents/${multiDocId}/download`)
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .responseType('blob');

      expect(dlRes.status).to.equal(200);
      authenticStampedBuffer = Buffer.from(dlRes.body);
      expect(authenticStampedBuffer.length).to.be.greaterThan(14000);
    });

    it('9. Authentic Check: uploading the untouched watermarked file returns 200 OK, isValid: true, AUTHENTIC', async function () {
      const verifyRes = await request(app)
        .post('/api/documents/verify')
        .attach('file', authenticStampedBuffer, 'authentic.pdf');

      expect(verifyRes.status).to.equal(200);
      expect(verifyRes.body.isValid).to.equal(true);
      expect(verifyRes.body.verificationStatus).to.equal('AUTHENTIC');
      expect(verifyRes.body.tampered).to.equal(false);
      expect(verifyRes.body.metadata.id).to.equal(multiDocId);
    });

    it('10. Header Tampering: flipping bytes at offset 20 returns TAMPERED_FORGERY_DETECTED, HEADER_ALTERED, corruptedChunkIndices: [0]', async function () {
      const tampered = Buffer.from(authenticStampedBuffer);
      tampered[20] = tampered[20] === 0x61 ? 0x62 : 0x61; // flip byte at offset 20

      const verifyRes = await request(app)
        .post('/api/documents/verify')
        .attach('file', tampered, 'tampered_header.pdf');

      expect(verifyRes.status).to.equal(200);
      expect(verifyRes.body.isValid).to.equal(false);
      expect(verifyRes.body.verificationStatus).to.equal('TAMPERED_FORGERY_DETECTED');
      expect(verifyRes.body.tampered).to.equal(true);

      const forensics = verifyRes.body.forensics;
      expect(forensics.decryptionMode).to.equal('FULL_IN_MEMORY_AES_GCM');
      expect(forensics.verdict).to.equal('HEADER_ALTERED');
      expect(forensics.firstDivergentByteOffset).to.equal(20);
      expect(forensics.chunkForensics.corruptedChunkIndices).to.deep.equal([0]);
      expect(forensics.chunkForensics.intactChunkIndices).to.include(1);
      expect(forensics.chunkForensics.intactChunkIndices).to.include(2);
    });

    it('11. Mid-Stream Surgical Edit: flipping byte at offset 5000 returns TAMPERED_FORGERY_DETECTED, CONTENT_MODIFIED, corruptedChunkIndices: [1]', async function () {
      const tampered = Buffer.from(authenticStampedBuffer);
      tampered[5000] = tampered[5000] === 0x61 ? 0x62 : 0x61; // flip byte in Chunk 1 (4096-8191)

      const verifyRes = await request(app)
        .post('/api/documents/verify')
        .attach('file', tampered, 'tampered_midstream.pdf');

      expect(verifyRes.status).to.equal(200);
      expect(verifyRes.body.isValid).to.equal(false);
      expect(verifyRes.body.verificationStatus).to.equal('TAMPERED_FORGERY_DETECTED');

      const forensics = verifyRes.body.forensics;
      expect(forensics.verdict).to.equal('CONTENT_MODIFIED');
      expect(forensics.firstDivergentByteOffset).to.equal(5000);
      expect(forensics.chunkForensics.corruptedChunkIndices).to.deep.equal([1]);
      expect(forensics.chunkForensics.intactChunkIndices).to.include(0);
      expect(forensics.chunkForensics.intactChunkIndices).to.include(2);
    });

    it('12. Payload Truncation: removing 1,000 bytes while preserving HMAC watermark returns PAYLOAD_TRUNCATED', async function () {
      const trailerMatch = authenticStampedBuffer
        .toString('utf8')
        .match(/%%CONSORTIUM-FORENSIC-TAG:[^\r\n%]+%%/);
      expect(trailerMatch).to.not.be.null;

      const tagString = trailerMatch![0];
      const tagMarker = Buffer.from(`\n${tagString}\n`, 'utf8');

      // Slice out 1000 bytes from the body before the trailer
      const bodyPart = authenticStampedBuffer.subarray(0, authenticStampedBuffer.length - tagMarker.length);
      const truncatedBody = bodyPart.subarray(0, bodyPart.length - 1000);
      const truncatedFile = Buffer.concat([truncatedBody, tagMarker]);

      const verifyRes = await request(app)
        .post('/api/documents/verify')
        .attach('file', truncatedFile, 'truncated.pdf');

      expect(verifyRes.status).to.equal(200);
      expect(verifyRes.body.verificationStatus).to.equal('TAMPERED_FORGERY_DETECTED');

      const forensics = verifyRes.body.forensics;
      expect(forensics.sizeDifferenceBytes).to.be.lessThan(0);
      expect(forensics.verdict).to.equal('PAYLOAD_TRUNCATED');
    });

    it('13. Legacy Document Fallback: doc with null KMS key triggers METADATA_AND_CIPHERTEXT_LENGTH without 500 error', async function () {
      const legacyDocId = crypto.randomUUID();
      createdDocIds.push(legacyDocId);
      const legacyHash = '0x' + crypto.randomBytes(32).toString('hex');
      const mockCiphertext = Buffer.alloc(800, 0x41).toString('base64');
      const legacyCid = 'QmLegacyFallbackMockCid123';

      pinataStorage.set(legacyCid, {
        ciphertext: mockCiphertext,
        iv: Buffer.alloc(12).toString('base64'),
        authTag: Buffer.alloc(16).toString('base64'),
      });

      await prisma.documentMetadata.create({
        data: {
          id: legacyDocId,
          documentHash: legacyHash,
          ipfsCid: legacyCid,
          docType: 'LegacyDegree',
          issuerAddress: userIssuerA.address,
          citizenAddress: userCitizenA.address,
          kmsEncryptedSessionKey: null,
          sessionKeyIv: null,
          sessionKeyAuthTag: null,
          fileSize: 800,
          fileName: 'legacy.pdf',
        },
      });

      // Embed valid HMAC watermark for legacyDocId
      const legacyUploadedFile = CryptoService.embedDocumentWatermark(
        Buffer.alloc(950, 0x42),
        legacyDocId
      );

      const verifyRes = await request(app)
        .post('/api/documents/verify')
        .attach('file', legacyUploadedFile, 'legacy_tampered.pdf');

      expect(verifyRes.status).to.equal(200);
      expect(verifyRes.body.verificationStatus).to.equal('TAMPERED_FORGERY_DETECTED');
      expect(verifyRes.body.forensics.decryptionMode).to.equal('METADATA_AND_CIPHERTEXT_LENGTH');
      expect(verifyRes.body.forensics.sizeDifferenceBytes).to.be.greaterThan(0);
    });
  });

  // =========================================================================
  // Category D: Cryptographic & Zero-Trust IDOR Defenses
  // =========================================================================
  describe('Category D: Cryptographic & Zero-Trust IDOR Defenses', function () {
    let docIdD: string;
    let authenticBufferD: Buffer;

    before(async function () {
      const res = await request(app)
        .post('/api/documents/issue')
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .attach('file', Buffer.from('Doc D Secret Content for IDOR Tests', 'utf8'), 'doc_d.pdf')
        .field('citizenAddress', userCitizenA.address)
        .field('docType', 'CertificateD');

      docIdD = res.body.documentId;
      createdDocIds.push(docIdD);

      const dlRes = await request(app)
        .get(`/api/documents/${docIdD}/download`)
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .responseType('blob');

      authenticBufferD = Buffer.from(dlRes.body);
    });

    it('14. Unauthenticated Hint Ignore Test: untagged file passing documentId/claimedDocumentId returns UNREGISTERED_DOCUMENT', async function () {
      // Modify file and strip the watermark
      const untaggedFile = Buffer.from('Modified file with stripped watermark');

      const verifyRes = await request(app)
        .post('/api/documents/verify')
        .attach('file', untaggedFile, 'untagged.pdf')
        .field('documentId', docIdD)
        .field('claimedDocumentId', docIdD)
        .field('citizenAddress', userCitizenA.address)
        .field('docType', 'CertificateD');

      expect(verifyRes.status).to.equal(200);
      expect(verifyRes.body.isValid).to.equal(false);
      expect(verifyRes.body.verificationStatus).to.equal('UNREGISTERED_DOCUMENT');
      expect(verifyRes.body.forensics).to.be.undefined;
    });

    it('15. Cross-Document HMAC Splice Attack: Doc A ID with Doc B HMAC tag returns UNREGISTERED_DOCUMENT', async function () {
      // Create Doc B
      const resB = await request(app)
        .post('/api/documents/issue')
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .attach('file', Buffer.from('Doc B for Splice Attack', 'utf8'), 'doc_b.pdf')
        .field('citizenAddress', userCitizenA.address)
        .field('docType', 'CertificateB');

      const docIdB = resB.body.documentId;
      createdDocIds.push(docIdB);

      // Compute HMAC for Doc B
      const hmacB = crypto.createHmac('sha256', MASTER_KMS_KEY).update(docIdB).digest('hex');

      // Spliced tag: Doc A's UUID with Doc B's HMAC
      const splicedTag = Buffer.from(`\n%%CONSORTIUM-FORENSIC-TAG:${docIdD}.${hmacB}%%\n`, 'utf8');
      const splicedFile = Buffer.concat([Buffer.from('Spliced Attack Content'), splicedTag]);

      const verifyRes = await request(app)
        .post('/api/documents/verify')
        .attach('file', splicedFile, 'spliced.pdf');

      expect(verifyRes.status).to.equal(200);
      expect(verifyRes.body.isValid).to.equal(false);
      expect(verifyRes.body.verificationStatus).to.equal('UNREGISTERED_DOCUMENT');
      expect(verifyRes.body.forensics).to.be.undefined;
    });

    it('16. Single-Bit HMAC Mutation: flipping 1 hex character in HMAC signature returns UNREGISTERED_DOCUMENT', async function () {
      const trailerMatch = authenticBufferD
        .toString('utf8')
        .match(/%%CONSORTIUM-FORENSIC-TAG:([a-fA-F0-9-]+)\.([a-fA-F0-9]{64})%%/);
      expect(trailerMatch).to.not.be.null;

      const docId = trailerMatch![1];
      const validHmac = trailerMatch![2];

      // Mutate 1 character in the HMAC
      const mutatedChar = validHmac[0] === 'a' ? 'b' : 'a';
      const corruptedHmac = mutatedChar + validHmac.slice(1);

      const corruptedTag = Buffer.from(
        `\n%%CONSORTIUM-FORENSIC-TAG:${docId}.${corruptedHmac}%%\n`,
        'utf8'
      );
      const tamperedFile = Buffer.concat([Buffer.from('Modified body'), corruptedTag]);

      const verifyRes = await request(app)
        .post('/api/documents/verify')
        .attach('file', tamperedFile, 'corrupted_hmac.pdf');

      expect(verifyRes.status).to.equal(200);
      expect(verifyRes.body.isValid).to.equal(false);
      expect(verifyRes.body.verificationStatus).to.equal('UNREGISTERED_DOCUMENT');
      expect(verifyRes.body.forensics).to.be.undefined;
    });

    it('17. Zero-Knowledge Leak Check: forensics response does NOT leak secret plaintext content', async function () {
      // Modify byte 10 of authenticBufferD (which contains 'Secret Content')
      const tampered = Buffer.from(authenticBufferD);
      tampered[10] = 0x58; // modify one byte

      const verifyRes = await request(app)
        .post('/api/documents/verify')
        .attach('file', tampered, 'zk_check.pdf');

      expect(verifyRes.status).to.equal(200);
      expect(verifyRes.body.verificationStatus).to.equal('TAMPERED_FORGERY_DETECTED');

      const responseString = JSON.stringify(verifyRes.body);
      expect(responseString).to.not.include('Secret Content for IDOR Tests');
      expect(verifyRes.body.forensics).to.have.property('uploadedDivergentHexSlice');
    });
  });

  // =========================================================================
  // Category E: State Machine & Lifecycle Edge Cases (revoke & supersede)
  // =========================================================================
  describe('Category E: State Machine & Lifecycle Edge Cases (revoke & supersede)', function () {
    let docEId: string;
    let docEHash: string;
    let stampedBufferE: Buffer;

    before(async function () {
      const res = await request(app)
        .post('/api/documents/issue')
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .attach('file', Buffer.from('Doc E Lifecycle Test Content', 'utf8'), 'doc_e.pdf')
        .field('citizenAddress', userCitizenA.address)
        .field('docType', 'LifecycleDegree');

      docEId = res.body.documentId;
      docEHash = res.body.documentHash;
      createdDocIds.push(docEId);

      const dlRes = await request(app)
        .get(`/api/documents/${docEId}/download`)
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .responseType('blob');

      stampedBufferE = Buffer.from(dlRes.body);
    });

    it('18. Double Revocation: revoking an already-revoked document returns 400 Bad Request', async function () {
      // 1st Revocation (Success)
      const r1 = await request(app)
        .post(`/api/documents/${docEId}/revoke`)
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .send({ reason: 'Audit revocation' });
      expect(r1.status).to.equal(200);
      expect(r1.body.isRevoked).to.equal(true);

      // 2nd Revocation (Should fail with 400)
      const r2 = await request(app)
        .post(`/api/documents/${docEId}/revoke`)
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .send({ reason: 'Attempted duplicate revocation' });
      expect(r2.status).to.equal(400);
      expect(r2.body.message).to.equal('Document is already revoked');
    });

    it('19. Verification of Revoked Document: returns isValid: false, REVOKED_ON_CHAIN, and revocationReason', async function () {
      const verifyRes = await request(app)
        .post('/api/documents/verify')
        .attach('file', stampedBufferE, 'revoked_verify.pdf');

      expect(verifyRes.status).to.equal(200);
      expect(verifyRes.body.isValid).to.equal(false);
      expect(verifyRes.body.verificationStatus).to.equal('REVOKED_ON_CHAIN');
      expect(verifyRes.body.onChain.isRevoked).to.equal(true);
      expect(verifyRes.body.onChain.revocationReason).to.equal('Audit revocation');
    });

    it('20. Supersede Flow: superseding Document V1 with Document V2 updates supersededByHash and reflects on verification', async function () {
      // Issue V1
      const resV1 = await request(app)
        .post('/api/documents/issue')
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .attach('file', Buffer.from('Document V1 Initial Version', 'utf8'), 'doc_v1.pdf')
        .field('citizenAddress', userCitizenA.address)
        .field('docType', 'DiplomaV1');

      const v1Id = resV1.body.documentId;
      const v1Hash = resV1.body.documentHash;
      createdDocIds.push(v1Id);

      // Download V1
      const dlV1 = await request(app)
        .get(`/api/documents/${v1Id}/download`)
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .responseType('blob');
      const v1Buffer = Buffer.from(dlV1.body);

      // Issue V2 (successor)
      const resV2 = await request(app)
        .post('/api/documents/issue')
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .attach('file', Buffer.from('Document V2 Corrected Version', 'utf8'), 'doc_v2.pdf')
        .field('citizenAddress', userCitizenA.address)
        .field('docType', 'DiplomaV2');

      const v2Id = resV2.body.documentId;
      const v2Hash = resV2.body.documentHash;
      createdDocIds.push(v2Id);

      // Execute supersede
      const supersedeRes = await request(app)
        .post(`/api/documents/${v1Id}/supersede`)
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .send({ newDocumentId: v2Id });

      expect(supersedeRes.status).to.equal(200);
      expect(supersedeRes.body.isRevoked).to.equal(true);
      expect(supersedeRes.body.supersededByHash).to.equal(v2Hash);

      // Verify V1 reflects superseded status
      const verifyV1Res = await request(app)
        .post('/api/documents/verify')
        .attach('file', v1Buffer, 'v1_check.pdf');

      expect(verifyV1Res.status).to.equal(200);
      expect(verifyV1Res.body.isValid).to.equal(false);
      expect(verifyV1Res.body.verificationStatus).to.equal('REVOKED_ON_CHAIN');
      expect(verifyV1Res.body.onChain.supersededBy).to.equal(v2Hash);
      expect(verifyV1Res.body.onChain.revocationReason).to.equal('SUPERSEDED');
    });
  });

  // =========================================================================
  // Category F: Malformed Inputs
  // =========================================================================
  describe('Category F: Malformed Inputs', function () {
    it('21. Missing Files: calling /issue or /verify with no file attached returns 400 Bad Request', async function () {
      const issueRes = await request(app)
        .post('/api/documents/issue')
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .field('citizenAddress', userCitizenA.address)
        .field('docType', 'Degree');

      expect(issueRes.status).to.equal(400);
      expect(issueRes.body.message).to.equal('Document file is required');

      const verifyRes = await request(app).post('/api/documents/verify');
      expect(verifyRes.status).to.equal(400);
      expect(verifyRes.body.message).to.include('A file upload or documentHash is required');
    });

    it('22. Invalid Ethereum Address: calling /issue with invalid citizenAddress returns 400 Bad Request', async function () {
      const res = await request(app)
        .post('/api/documents/issue')
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .attach('file', Buffer.from('File content', 'utf8'), 'test.pdf')
        .field('citizenAddress', 'not-an-address')
        .field('docType', 'Degree');

      expect(res.status).to.equal(400);
      expect(res.body.message).to.equal('Invalid Ethereum citizenAddress');
    });
  });

  // =========================================================================
  // Category G: Dashboard Query Endpoints & Manual Grant Kill-Switch
  // =========================================================================
  describe('Category G: Dashboard Query Endpoints & Manual Grant Kill-Switch', function () {
    let dashboardDocId: string;
    let dashboardGrantToken: string;
    let dashboardGrantId: string;

    before(async function () {
      // Issue a fresh document for dashboard tests to Citizen A
      const issueRes = await request(app)
        .post('/api/documents/issue')
        .set('Authorization', `Bearer ${tokenIssuerA}`)
        .attach('file', Buffer.from('Dashboard Test Credential Content', 'utf8'), 'dash.pdf')
        .field('citizenAddress', userCitizenA.address)
        .field('docType', 'DashboardDegree');

      expect(issueRes.status).to.equal(200);
      dashboardDocId = issueRes.body.documentId;
      createdDocIds.push(dashboardDocId);

      // Create an active grant on this document
      const grantRes = await request(app)
        .post(`/api/documents/${dashboardDocId}/grant`)
        .set('Authorization', `Bearer ${tokenCitizenA}`)
        .send({ maxViews: 5, ttlMinutes: 120, granteeLabel: 'Dashboard Employer Link' });

      expect(grantRes.status).to.equal(200);
      dashboardGrantToken = grantRes.body.token;
      createdGrantTokens.push(dashboardGrantToken);

      const grantInDb = await prisma.verificationGrant.findUnique({
        where: { token: dashboardGrantToken },
      });
      dashboardGrantId = grantInDb!.id;
    });

    it('23. GET /api/documents/my-documents returns only authenticated citizen documents with grants and sanitized KMS keys', async function () {
      const res = await request(app)
        .get('/api/documents/my-documents')
        .set('Authorization', `Bearer ${tokenCitizenA}`);

      expect(res.status).to.equal(200);
      expect(res.body.success).to.equal(true);
      expect(Array.isArray(res.body.documents)).to.equal(true);
      expect(res.body.documents.length).to.be.greaterThan(0);

      const target = res.body.documents.find((d: any) => d.id === dashboardDocId);
      expect(target).to.not.be.undefined;
      expect(target.citizenAddress.toLowerCase()).to.equal(userCitizenA.address.toLowerCase());
      expect(target.status).to.equal('ACTIVE');
      expect(Array.isArray(target.grants)).to.equal(true);
      expect(target.grants.length).to.be.greaterThan(0);

      // Security Check: Assert KMS secrets are NEVER leaked in list
      res.body.documents.forEach((d: any) => {
        expect(d).to.not.have.property('kmsEncryptedSessionKey');
        expect(d).to.not.have.property('sessionKeyIv');
        expect(d).to.not.have.property('sessionKeyAuthTag');
      });
    });

    it('24. GET /api/documents/issued returns issuer ledger, supports filtering, and blocks non-issuers with 403', async function () {
      // Citizen attempt -> 403 Forbidden
      const citizenRes = await request(app)
        .get('/api/documents/issued')
        .set('Authorization', `Bearer ${tokenCitizenA}`);
      expect(citizenRes.status).to.equal(403);
      expect(citizenRes.body.message).to.include('Requires ISSUER role');

      // Issuer A fetch with filter
      const issuerRes = await request(app)
        .get('/api/documents/issued?docType=DashboardDegree')
        .set('Authorization', `Bearer ${tokenIssuerA}`);

      expect(issuerRes.status).to.equal(200);
      expect(issuerRes.body.success).to.equal(true);
      expect(Array.isArray(issuerRes.body.documents)).to.equal(true);

      const found = issuerRes.body.documents.find((d: any) => d.id === dashboardDocId);
      expect(found).to.not.be.undefined;
      expect(found.docType).to.equal('DashboardDegree');
      expect(found.issuerAddress.toLowerCase()).to.equal(userIssuerA.address.toLowerCase());
      expect(found).to.have.property('grantsCount');
      expect(found).to.have.property('activeGrantsCount');

      // Security Check: Assert KMS secrets are omitted
      issuerRes.body.documents.forEach((d: any) => {
        expect(d).to.not.have.property('kmsEncryptedSessionKey');
        expect(d).to.not.have.property('sessionKeyIv');
        expect(d).to.not.have.property('sessionKeyAuthTag');
      });
    });

    it('25. GET /api/documents/:id enforces owner/issuer RBAC (allows Citizen A & Issuer A, blocks Citizen B with 403)', async function () {
      // Citizen A (owner) -> 200 OK
      const ownerRes = await request(app)
        .get(`/api/documents/${dashboardDocId}`)
        .set('Authorization', `Bearer ${tokenCitizenA}`);
      expect(ownerRes.status).to.equal(200);
      expect(ownerRes.body.document.id).to.equal(dashboardDocId);
      expect(ownerRes.body.document.status).to.equal('ACTIVE');
      expect(ownerRes.body.document).to.not.have.property('kmsEncryptedSessionKey');

      // Issuer A (minting issuer) -> 200 OK
      const issuerRes = await request(app)
        .get(`/api/documents/${dashboardDocId}`)
        .set('Authorization', `Bearer ${tokenIssuerA}`);
      expect(issuerRes.status).to.equal(200);
      expect(issuerRes.body.document.id).to.equal(dashboardDocId);

      // Citizen B (unrelated citizen) -> 403 Forbidden
      const snooperRes = await request(app)
        .get(`/api/documents/${dashboardDocId}`)
        .set('Authorization', `Bearer ${tokenCitizenB}`);
      expect(snooperRes.status).to.equal(403);
      expect(snooperRes.body.message).to.include('Forbidden');
    });

    it('26. POST /api/documents/grants/:grantId/revoke kills grant early, blocks unauthorized users (403), and causes 410 on next verification', async function () {
      // Citizen B (unauthorized) attempt to kill Citizen A's grant -> 403 Forbidden
      const unauthRes = await request(app)
        .post(`/api/documents/grants/${dashboardGrantId}/revoke`)
        .set('Authorization', `Bearer ${tokenCitizenB}`);
      expect(unauthRes.status).to.equal(403);
      expect(unauthRes.body.message).to.include('Forbidden');

      // Active check before revoking: verification endpoint should return 200
      const preCheck = await request(app).get(`/api/documents/verify-grant/${dashboardGrantToken}`);
      expect(preCheck.status).to.equal(200);

      // Citizen A (owner) triggers manual kill-switch -> 200 OK
      const killRes = await request(app)
        .post(`/api/documents/grants/${dashboardGrantId}/revoke`)
        .set('Authorization', `Bearer ${tokenCitizenA}`);
      expect(killRes.status).to.equal(200);
      expect(killRes.body.success).to.equal(true);
      expect(killRes.body.grant.isRevoked).to.equal(true);

      // Immediate subsequent verification attempt must return 410 Gone / SELF_DESTRUCTED
      const postCheck = await request(app).get(`/api/documents/verify-grant/${dashboardGrantToken}`);
      expect(postCheck.status).to.equal(410);
      expect(postCheck.body.status).to.equal('SELF_DESTRUCTED');
      expect(postCheck.body.verificationStatus).to.equal('REVOKED_ON_CHAIN');

      // Duplicate revocation attempt -> 400 Bad Request
      const dupRes = await request(app)
        .post(`/api/documents/grants/${dashboardGrantId}/revoke`)
        .set('Authorization', `Bearer ${tokenCitizenA}`);
      expect(dupRes.status).to.equal(400);
      expect(dupRes.body.message).to.equal('Grant is already revoked');
    });
  });
});

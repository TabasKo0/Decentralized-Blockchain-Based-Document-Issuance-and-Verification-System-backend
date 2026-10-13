import type { Request, Response } from 'express';
import { randomUUID } from 'crypto';
import crypto from 'crypto';
import { ethers } from 'ethers';
import { prisma } from '../db';
import { CryptoService } from '../services/crypto.service';
import { PinataService } from '../services/pinata.service';
import { RelayerService } from '../services/relayer.service';
import type { AuthRequest } from '../middlewares/auth.middleware';

const relayerService = new RelayerService();

/**
 * Returns a read-only instance of DocumentIssuanceConsortium (no private key or relayer required).
 */
const getReadOnlyContract = () => {
  const rpcUrl = process.env.SEPOLIA_RPC_URL || process.env.RPC_URL || 'http://127.0.0.1:8545';
  const contractAddress = process.env.CONTRACT_ADDRESS || '0xa08Bfaf6f138c91e9a9562240030E6AdF7F3cF5e';
  const isSepolia = rpcUrl.includes('sepolia');
  const provider = isSepolia
    ? new ethers.JsonRpcProvider(rpcUrl, 11155111, { staticNetwork: true })
    : new ethers.JsonRpcProvider(rpcUrl);

  const ABI = [
    'function documents(bytes32) external view returns (bytes32 documentHash, address issuer, address citizen, string docType, uint256 issuedAt, bool isRevoked, string revocationReason, bytes32 supersededBy, uint64 expiresAt)',
    'function isIssuer(address) external view returns (bool)',
  ];

  return new ethers.Contract(contractAddress, ABI, provider);
};

/**
 * Issues an official certificate or document (Contract v2 + Watermarking + Chunked Hashes + KMS key storage)
 */
export const issueDocument = async (req: AuthRequest, res: Response) => {
  try {
    const file = req.file;
    const citizenWalletInput = req.body.citizenAddress || req.body.citizenWalletAddress;
    const docType = req.body.docType;
    const expiresAtInput = req.body.expiresAt ? Number(req.body.expiresAt) : 0;

    if (!file) {
      return res.status(400).json({ success: false, message: 'Document file is required' });
    }

    if (!citizenWalletInput || !docType) {
      return res.status(400).json({ success: false, message: 'citizenAddress and docType are required' });
    }

    const citizenAddress = ethers.getAddress(citizenWalletInput);
    const issuerAddress = req.user?.address ? ethers.getAddress(req.user.address) : relayerService.getRelayerAddress();

    // Fetch citizen's public key from database or request body
    const citizen = await prisma.user.findUnique({
      where: { address: citizenAddress },
    });

    const citizenPublicKey = req.body.citizenPublicKey || citizen?.publicKey;
    if (!citizenPublicKey) {
      return res.status(400).json({
        success: false,
        message: 'Citizen public key not found. Ensure citizen is registered or provide citizenPublicKey in request body.',
      });
    }

    // 1. Generate unique Document ID
    const documentId = randomUUID();

    // 2. Embed invisible forensic watermark trailer into buffer before hashing and encryption
    const stampedBuffer = CryptoService.embedDocumentWatermark(file.buffer, documentId);

    // 3. Compute 4KB chunk hashes for chunked block forensics
    const chunkHashes = CryptoService.computeChunkHashes(stampedBuffer, 4096);

    // 4. Derive authentic document hash (Keccak-256 of stamped buffer)
    const documentHash = ethers.keccak256(stampedBuffer);

    // 5. Generate 256-bit symmetric session key & encrypt stamped buffer (AES-256-GCM)
    const sessionKey = CryptoService.generateSessionKey();
    const { ciphertext, iv, authTag } = CryptoService.encryptFile(stampedBuffer, sessionKey);

    // 6. Wrap session key with citizen's public key via ECIES
    const encryptedKey = await CryptoService.wrapSessionKey(sessionKey, citizenPublicKey);

    // 7. Symmetrically encrypt session key with server MASTER_KMS_KEY for in-memory forensics
    const kmsWrappedKey = CryptoService.encryptSessionKeyWithKms(sessionKey);

    // 8. Bundle payload with chunkHashes and pin to IPFS via Pinata
    const payload = {
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      encryptedKey,
      chunkHashes,
      documentId,
      docType,
      fileName: file.originalname,
      mimeType: file.mimetype,
      issuedAt: new Date().toISOString(),
    };

    const ipfsCid = await PinataService.pinJSONToIPFS(
      payload,
      `${docType}_${citizenAddress}_${Date.now()}`
    );

    // 9. Anchor on Sepolia blockchain via Relayer (Contract v2)
    const receipt = await relayerService.issueDocument(documentHash, citizenAddress, docType, expiresAtInput);

    // 10. Persist metadata in PostgreSQL
    const docRecord = await prisma.documentMetadata.create({
      data: {
        id: documentId,
        documentHash,
        ipfsCid,
        docType,
        issuerAddress,
        citizenAddress,
        fileSize: stampedBuffer.length,
        fileName: file.originalname,
        mimeType: file.mimetype,
        kmsEncryptedSessionKey: kmsWrappedKey.encryptedShareB,
        sessionKeyIv: kmsWrappedKey.iv,
        sessionKeyAuthTag: kmsWrappedKey.authTag,
        expiresAt: expiresAtInput > 0 ? new Date(expiresAtInput * 1000) : null,
      },
    });

    res.json({
      success: true,
      documentId,
      txHash: receipt.hash,
      blockNumber: receipt.blockNumber,
      ipfsCid,
      documentHash,
      metadata: docRecord,
    });
  } catch (err: any) {
    console.error('issueDocument error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

/**
 * Creates an Ephemeral Verification Grant for a document.
 */
export const createGrant = async (req: AuthRequest, res: Response) => {
  try {
    const rawParam = req.params.id;
    const documentIdentifier = Array.isArray(rawParam) ? rawParam[0] : rawParam;

    if (!documentIdentifier) {
      return res.status(400).json({ success: false, message: 'Document ID or hash is required' });
    }

    const document = await prisma.documentMetadata.findFirst({
      where: {
        OR: [{ id: documentIdentifier }, { documentHash: documentIdentifier }],
      },
    });

    if (!document) {
      return res.status(404).json({ success: false, message: 'Document not found' });
    }

    // Ownership check: must be citizen or issuer
    const callerAddress = req.user?.address ? ethers.getAddress(req.user.address) : '';
    const isCitizen = callerAddress.toLowerCase() === document.citizenAddress.toLowerCase();
    const isIssuer = callerAddress.toLowerCase() === document.issuerAddress.toLowerCase();

    if (!isCitizen && !isIssuer) {
      return res.status(403).json({
        success: false,
        message: 'Forbidden: Only the citizen owner or issuer can generate verification grants',
      });
    }

    if (document.isRevoked) {
      return res.status(400).json({
        success: false,
        message: 'Cannot generate verification grant for a revoked document',
      });
    }

    const ttlMinutes = req.body.ttlMinutes
      ? Number(req.body.ttlMinutes)
      : req.body.validityMinutes
      ? Number(req.body.validityMinutes)
      : 1440; // Default 24 hours
    const maxViews = req.body.maxViews ? Number(req.body.maxViews) : 1; // Default 1 view
    const granteeLabel = req.body.granteeLabel || req.body.recipientName || null;

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000);

    const grant = await prisma.verificationGrant.create({
      data: {
        token,
        documentId: document.id,
        granteeLabel,
        maxViews,
        expiresAt,
      },
    });

    res.json({
      success: true,
      token: grant.token,
      grantToken: grant.token,
      verificationUrl: `/api/documents/verify-grant/${grant.token}`,
      maxViews: grant.maxViews,
      expiresAt: grant.expiresAt,
      granteeLabel: grant.granteeLabel,
      documentId: document.id,
      documentHash: document.documentHash,
    });
  } catch (err: any) {
    console.error('createGrant error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

/**
 * Public endpoint to verify and consume an Ephemeral Grant with true atomic view tracking.
 */
export const verifyGrant = async (req: Request, res: Response) => {
  try {
    const rawParam = req.params.token;
    const token = Array.isArray(rawParam) ? rawParam[0] : rawParam;

    if (!token) {
      return res.status(400).json({ success: false, message: 'Token parameter is required' });
    }

    const grant = await prisma.verificationGrant.findUnique({
      where: { token },
      include: {
        document: true,
      },
    });

    if (!grant) {
      return res.status(404).json({
        success: false,
        verificationStatus: 'UNREGISTERED_DOCUMENT',
        message: 'Grant token not found',
      });
    }

    // Check revocation
    if (grant.isRevoked || grant.document.isRevoked) {
      return res.status(410).json({
        success: false,
        status: 'SELF_DESTRUCTED',
        verificationStatus: 'REVOKED_ON_CHAIN',
        message: 'Document or verification grant has been revoked',
      });
    }

    // Check expiration
    if (new Date() > grant.expiresAt) {
      return res.status(410).json({
        success: false,
        status: 'SELF_DESTRUCTED',
        verificationStatus: 'EXPIRED',
        message: 'Verification grant has expired',
      });
    }

    // Check view count limit
    if (grant.viewCount >= grant.maxViews) {
      return res.status(410).json({
        success: false,
        status: 'SELF_DESTRUCTED',
        verificationStatus: 'VIEW_LIMIT_EXHAUSTED',
        message: 'Grant view limit exhausted',
      });
    }

    // True Atomic Increment (Refinement 2)
    const updateResult = await prisma.verificationGrant.updateMany({
      where: {
        id: grant.id,
        isRevoked: false,
        expiresAt: { gt: new Date() },
        viewCount: { lt: grant.maxViews },
      },
      data: {
        viewCount: { increment: 1 },
      },
    });

    if (updateResult.count !== 1) {
      return res.status(410).json({
        success: false,
        status: 'SELF_DESTRUCTED',
        verificationStatus: 'VIEW_LIMIT_EXHAUSTED',
        message: 'Grant view limit exhausted during concurrent consumption',
      });
    }

    // Query on-chain status from Sepolia
    const readOnlyContract = getReadOnlyContract();
    const onChainRecord = await readOnlyContract.documents(grant.document.documentHash);

    const onChainExists = Boolean(onChainRecord && onChainRecord.issuedAt > 0n);
    const onChainRevoked = onChainExists && Boolean(onChainRecord.isRevoked);
    const isValid = onChainExists && !onChainRevoked;

    res.json({
      success: true,
      isValid,
      verificationStatus: isValid ? 'AUTHENTIC' : onChainRevoked ? 'REVOKED_ON_CHAIN' : 'UNREGISTERED_DOCUMENT',
      grant: {
        granteeLabel: grant.granteeLabel,
        viewsRemaining: Math.max(0, grant.maxViews - (grant.viewCount + 1)),
        expiresAt: grant.expiresAt,
      },
      document: {
        id: grant.document.id,
        documentHash: grant.document.documentHash,
        docType: grant.document.docType,
        citizenAddress: grant.document.citizenAddress,
        issuerAddress: grant.document.issuerAddress,
        isRevoked: grant.document.isRevoked,
        revocationReason: grant.document.revocationReason,
        supersededByHash: grant.document.supersededByHash,
        issuedAt: grant.document.createdAt,
        ipfsCid: grant.document.ipfsCid,
      },
      onChain: {
        exists: onChainExists,
        isRevoked: onChainRevoked,
        revocationReason: onChainExists ? onChainRecord.revocationReason : null,
        supersededBy: onChainExists ? onChainRecord.supersededBy : null,
        expiresAt: onChainExists ? onChainRecord.expiresAt.toString() : null,
        onChainTimestamp: onChainExists ? onChainRecord.issuedAt.toString() : null,
      },
    });
  } catch (err: any) {
    console.error('verifyGrant error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

/**
 * Revokes a document on-chain with a permanent reason (Contract v2).
 */
export const revokeDocument = async (req: AuthRequest, res: Response) => {
  try {
    const rawParam = req.params.id || req.body.documentHash || req.body.id;
    const documentIdentifier = Array.isArray(rawParam) ? rawParam[0] : rawParam;
    const reason = req.body.reason || 'REVOKED_BY_ISSUER';

    if (!documentIdentifier) {
      return res.status(400).json({ success: false, message: 'Document ID or documentHash is required' });
    }

    const document = await prisma.documentMetadata.findFirst({
      where: {
        OR: [{ id: documentIdentifier }, { documentHash: documentIdentifier }],
      },
    });

    if (!document) {
      return res.status(404).json({ success: false, message: 'Document not found' });
    }

    const callerAddress = req.user?.address ? ethers.getAddress(req.user.address) : '';
    if (callerAddress.toLowerCase() !== document.issuerAddress.toLowerCase()) {
      return res.status(403).json({
        success: false,
        message: 'Forbidden: Only the original issuer can revoke this document',
      });
    }

    if (document.isRevoked) {
      return res.status(400).json({ success: false, message: 'Document is already revoked' });
    }

    // Call on-chain revocation on Sepolia
    const receipt = await relayerService.revokeDocument(document.documentHash, reason);

    // Synchronize PostgreSQL and invalidate active grants
    await prisma.$transaction([
      prisma.documentMetadata.update({
        where: { id: document.id },
        data: {
          isRevoked: true,
          revokedAt: new Date(),
          revokedTxHash: receipt.hash,
          revocationReason: reason,
        },
      }),
      prisma.verificationGrant.updateMany({
        where: { documentId: document.id, isRevoked: false },
        data: { isRevoked: true },
      }),
    ]);

    res.json({
      success: true,
      txHash: receipt.hash,
      documentHash: document.documentHash,
      isRevoked: true,
      revocationReason: reason,
    });
  } catch (err: any) {
    console.error('revokeDocument error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

/**
 * Supersedes an old document with a new document hash, establishing an on-chain provenance chain.
 */
export const supersedeDocument = async (req: AuthRequest, res: Response) => {
  try {
    const oldIdentifier = req.params.id || req.body.oldDocumentId || req.body.oldDocumentHash;
    const newIdentifier = req.body.newDocumentId || req.body.newDocumentHash;

    if (!oldIdentifier || !newIdentifier) {
      return res.status(400).json({ success: false, message: 'Both old and new document identifiers are required' });
    }

    const oldDoc = await prisma.documentMetadata.findFirst({
      where: { OR: [{ id: oldIdentifier }, { documentHash: oldIdentifier }] },
    });

    const newDoc = await prisma.documentMetadata.findFirst({
      where: { OR: [{ id: newIdentifier }, { documentHash: newIdentifier }] },
    });

    if (!oldDoc || !newDoc) {
      return res.status(404).json({ success: false, message: 'Old or new document record not found' });
    }

    const callerAddress = req.user?.address ? ethers.getAddress(req.user.address) : '';
    if (
      callerAddress.toLowerCase() !== oldDoc.issuerAddress.toLowerCase() ||
      callerAddress.toLowerCase() !== newDoc.issuerAddress.toLowerCase()
    ) {
      return res.status(403).json({
        success: false,
        message: 'Forbidden: Only the issuing organization can supersede documents',
      });
    }

    // Call on-chain supersede
    const receipt = await relayerService.supersedeDocument(oldDoc.documentHash, newDoc.documentHash);

    // Update DB
    await prisma.$transaction([
      prisma.documentMetadata.update({
        where: { id: oldDoc.id },
        data: {
          isRevoked: true,
          revokedAt: new Date(),
          revocationReason: 'SUPERSEDED',
          supersededByHash: newDoc.documentHash,
          revokedTxHash: receipt.hash,
        },
      }),
      prisma.verificationGrant.updateMany({
        where: { documentId: oldDoc.id, isRevoked: false },
        data: { isRevoked: true },
      }),
    ]);

    res.json({
      success: true,
      txHash: receipt.hash,
      oldDocumentHash: oldDoc.documentHash,
      supersededByHash: newDoc.documentHash,
      message: 'Document successfully superseded on-chain',
    });
  } catch (err: any) {
    console.error('supersedeDocument error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

/**
 * Downloads the official, stamped document (Authorized citizen or issuer only).
 */
export const downloadDocument = async (req: AuthRequest, res: Response) => {
  try {
    const rawParam = req.params.id;
    const documentIdentifier = Array.isArray(rawParam) ? rawParam[0] : rawParam;

    const document = await prisma.documentMetadata.findFirst({
      where: { OR: [{ id: documentIdentifier }, { documentHash: documentIdentifier }] },
    });

    if (!document) {
      return res.status(404).json({ success: false, message: 'Document not found' });
    }

    const callerAddress = req.user?.address ? ethers.getAddress(req.user.address) : '';
    const isCitizen = callerAddress.toLowerCase() === document.citizenAddress.toLowerCase();
    const isIssuer = callerAddress.toLowerCase() === document.issuerAddress.toLowerCase();

    if (!isCitizen && !isIssuer) {
      return res.status(403).json({ success: false, message: 'Forbidden: Unauthorized to download this document' });
    }

    if (!document.kmsEncryptedSessionKey || !document.sessionKeyIv || !document.sessionKeyAuthTag) {
      return res.status(400).json({ success: false, message: 'KMS session key unavailable for server-side download' });
    }

    const ipfsBundle = await PinataService.fetchFromIPFS(document.ipfsCid);
    const sessionKey = CryptoService.decryptSessionKeyWithKms(
      document.kmsEncryptedSessionKey,
      document.sessionKeyIv,
      document.sessionKeyAuthTag
    );

    const ciphertext = Buffer.from(ipfsBundle.ciphertext, 'base64');
    const iv = Buffer.from(ipfsBundle.iv, 'base64');
    const authTag = Buffer.from(ipfsBundle.authTag, 'base64');

    const fileBuffer = CryptoService.decryptFile(ciphertext, sessionKey, iv, authTag);

    res.setHeader('Content-Type', document.mimeType || 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${document.fileName || 'document.pdf'}"`);
    res.send(fileBuffer);
  } catch (err: any) {
    console.error('downloadDocument error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

/**
 * Public document verification & zero-hint tamper forensics endpoint.
 */
export const verifyDocument = async (req: Request, res: Response) => {
  try {
    const file = req.file;
    let uploadedBuffer: Buffer | null = file ? file.buffer : null;
    let uploadedHash: string | undefined;

    if (uploadedBuffer) {
      uploadedHash = ethers.keccak256(uploadedBuffer);
    } else if (req.body?.documentHash) {
      const rawHash = req.body.documentHash.trim();
      uploadedHash = rawHash.startsWith('0x') ? rawHash : `0x${rawHash}`;
    }

    if (!uploadedHash) {
      return res.status(400).json({
        success: false,
        isValid: false,
        verificationStatus: 'UNREGISTERED_DOCUMENT',
        message: 'A file upload or documentHash is required for verification',
      });
    }

    // Zero-Hint Watermark Extraction from uploaded buffer
    let embeddedId: string | null = null;
    if (uploadedBuffer) {
      embeddedId = CryptoService.extractDocumentWatermark(uploadedBuffer);
    }

    // Check explicit request hints
    const claimedId = req.body.documentId || req.body.claimedDocumentId || embeddedId;
    const citizenAddressHint = req.body.citizenAddress || req.body.citizenWalletAddress;
    const docTypeHint = req.body.docType;

    // Locate target document
    let targetDoc: any = null;

    if (claimedId) {
      targetDoc = await prisma.documentMetadata.findUnique({
        where: { id: claimedId },
      });
    }

    if (!targetDoc && citizenAddressHint && docTypeHint) {
      targetDoc = await prisma.documentMetadata.findFirst({
        where: {
          citizenAddress: ethers.getAddress(citizenAddressHint),
          docType: docTypeHint,
        },
        orderBy: { createdAt: 'desc' },
      });
    }

    if (!targetDoc) {
      targetDoc = await prisma.documentMetadata.findUnique({
        where: { documentHash: uploadedHash },
      });
    }

    // Branch 1: Unregistered Document
    if (!targetDoc) {
      return res.json({
        success: true,
        isValid: false,
        verificationStatus: 'UNREGISTERED_DOCUMENT',
        documentHash: uploadedHash,
        onChain: { exists: false, isRevoked: false },
        metadata: null,
      });
    }

    // Read live Sepolia contract status
    const readOnlyContract = getReadOnlyContract();
    const onChainRecord = await readOnlyContract.documents(targetDoc.documentHash);

    const onChainExists = Boolean(onChainRecord && onChainRecord.issuedAt > 0n);
    const onChainRevoked = onChainExists && Boolean(onChainRecord.isRevoked);
    const onChainExpired =
      onChainExists &&
      onChainRecord.expiresAt > 0n &&
      BigInt(Math.floor(Date.now() / 1000)) > onChainRecord.expiresAt;

    // Branch 2: Authentic Match
    if (uploadedHash === targetDoc.documentHash) {
      const isAuthentic = onChainExists && !onChainRevoked && !onChainExpired;
      const verificationStatus = isAuthentic
        ? 'AUTHENTIC'
        : onChainRevoked
        ? 'REVOKED_ON_CHAIN'
        : onChainExpired
        ? 'EXPIRED'
        : 'UNREGISTERED_DOCUMENT';

      return res.json({
        success: true,
        isValid: isAuthentic,
        verificationStatus,
        tampered: false,
        documentHash: uploadedHash,
        onChain: {
          exists: onChainExists,
          isRevoked: onChainRevoked,
          revocationReason: onChainExists ? onChainRecord.revocationReason : null,
          supersededBy: onChainExists ? onChainRecord.supersededBy : null,
          expiresAt: onChainExists && onChainRecord.expiresAt > 0n ? onChainRecord.expiresAt.toString() : null,
          issuedAt: onChainExists ? onChainRecord.issuedAt.toString() : null,
          issuer: onChainExists ? onChainRecord.issuer : null,
          citizen: onChainExists ? onChainRecord.citizen : null,
        },
        document: {
          id: targetDoc.id,
          ipfsCid: targetDoc.ipfsCid,
          citizenAddress: targetDoc.citizenAddress,
          issuerAddress: targetDoc.issuerAddress,
          docType: targetDoc.docType,
          createdAt: targetDoc.createdAt,
        },
        metadata: {
          id: targetDoc.id,
          ipfsCid: targetDoc.ipfsCid,
          citizenAddress: targetDoc.citizenAddress,
          issuerAddress: targetDoc.issuerAddress,
          docType: targetDoc.docType,
          createdAt: targetDoc.createdAt,
        },
      });
    }

    // Branch 3: TAMPER / FORGERY DETECTED
    // Uploaded hash diverges from the expected authentic document
    const ipfsBundle = await PinataService.fetchFromIPFS(targetDoc.ipfsCid);

    let forensicsResult: any = {};

    if (
      uploadedBuffer &&
      targetDoc.kmsEncryptedSessionKey &&
      targetDoc.sessionKeyIv &&
      targetDoc.sessionKeyAuthTag
    ) {
      // Full in-memory AES-GCM Decryption
      let originalBuffer: Buffer | null = null;
      let sessionKey: Buffer | null = null;

      try {
        sessionKey = CryptoService.decryptSessionKeyWithKms(
          targetDoc.kmsEncryptedSessionKey,
          targetDoc.sessionKeyIv,
          targetDoc.sessionKeyAuthTag
        );

        const ciphertext = Buffer.from(ipfsBundle.ciphertext, 'base64');
        const iv = Buffer.from(ipfsBundle.iv, 'base64');
        const authTag = Buffer.from(ipfsBundle.authTag, 'base64');

        originalBuffer = CryptoService.decryptFile(ciphertext, sessionKey, iv, authTag);

        const originalSizeBytes = originalBuffer.length;
        const uploadedSizeBytes = uploadedBuffer.length;
        const sizeDifferenceBytes = uploadedSizeBytes - originalSizeBytes;

        // Byte scan for divergence
        let firstDivergentByteOffset = -1;
        let diffBytes = 0;
        const commonLen = Math.min(originalSizeBytes, uploadedSizeBytes);

        for (let i = 0; i < commonLen; i++) {
          if (originalBuffer[i] !== uploadedBuffer[i]) {
            if (firstDivergentByteOffset === -1) {
              firstDivergentByteOffset = i;
            }
            diffBytes++;
          }
        }

        if (firstDivergentByteOffset === -1 && sizeDifferenceBytes !== 0) {
          firstDivergentByteOffset = commonLen;
        }

        // 16-byte forensic hex slice (Refinement 3)
        let uploadedDivergentHexSlice = '';
        if (firstDivergentByteOffset !== -1) {
          const sliceStart = Math.max(0, firstDivergentByteOffset - 4);
          const sliceEnd = Math.min(uploadedSizeBytes, firstDivergentByteOffset + 12);
          uploadedDivergentHexSlice = uploadedBuffer.subarray(sliceStart, sliceEnd).toString('hex');
        }

        // Chunk block comparison (Upgrade 3)
        const authenticChunkHashes = ipfsBundle.chunkHashes || [];
        const chunkComparison = authenticChunkHashes.length > 0
          ? CryptoService.compareChunkHashes(authenticChunkHashes, uploadedBuffer, 4096)
          : null;

        // Determine verdict
        let verdict = 'CONTENT_MODIFIED';
        if (firstDivergentByteOffset >= 0 && firstDivergentByteOffset < 1024) {
          verdict = 'HEADER_ALTERED';
        } else if (sizeDifferenceBytes < 0 && diffBytes === 0) {
          verdict = 'TRUNCATED';
        } else if (sizeDifferenceBytes > 0 && diffBytes === 0) {
          verdict = 'APPENDED_DATA';
        } else if (diffBytes > commonLen * 0.7) {
          verdict = 'TOTAL_MISMATCH';
        }

        const maxLen = Math.max(originalSizeBytes, uploadedSizeBytes);
        const divergencePercentage = `${(((diffBytes + Math.abs(sizeDifferenceBytes)) / maxLen) * 100).toFixed(2)}%`;

        forensicsResult = {
          decryptionMode: 'FULL_IN_MEMORY_AES_GCM',
          verdict,
          originalSizeBytes,
          uploadedSizeBytes,
          sizeDifferenceBytes,
          firstDivergentByteOffset,
          uploadedDivergentHexSlice,
          divergencePercentage,
          chunkForensics: chunkComparison,
          detectedEmbeddedId: embeddedId,
        };
      } finally {
        // Strict in-memory purge
        if (originalBuffer) originalBuffer.fill(0);
        if (sessionKey) sessionKey.fill(0);
      }
    } else {
      // Graceful Legacy Fallback (Refinement 1)
      const originalSizeBytes = Buffer.from(ipfsBundle.ciphertext, 'base64').length;
      const uploadedSizeBytes = uploadedBuffer ? uploadedBuffer.length : 0;
      const sizeDifferenceBytes = uploadedSizeBytes - originalSizeBytes;

      forensicsResult = {
        decryptionMode: 'METADATA_AND_CIPHERTEXT_LENGTH',
        verdict: sizeDifferenceBytes === 0 ? 'CONTENT_MODIFIED' : 'SIZE_AND_CONTENT_DIVERGENCE',
        originalSizeBytes,
        uploadedSizeBytes,
        sizeDifferenceBytes,
        detectedEmbeddedId: embeddedId,
      };
    }

    res.json({
      success: true,
      isValid: false,
      verificationStatus: 'TAMPERED_FORGERY_DETECTED',
      tampered: true,
      documentHash: {
        expectedOnChain: targetDoc.documentHash,
        uploadedFileHash: uploadedHash,
      },
      forensics: forensicsResult,
      onChain: {
        exists: onChainExists,
        isRevoked: onChainRevoked,
        revocationReason: onChainExists ? onChainRecord.revocationReason : null,
        supersededBy: onChainExists ? onChainRecord.supersededBy : null,
      },
      metadata: {
        id: targetDoc.id,
        ipfsCid: targetDoc.ipfsCid,
        citizenAddress: targetDoc.citizenAddress,
        issuerAddress: targetDoc.issuerAddress,
        docType: targetDoc.docType,
        createdAt: targetDoc.createdAt,
      },
    });
  } catch (err: any) {
    console.error('verifyDocument error:', err);
    res.status(500).json({
      success: false,
      isValid: false,
      verificationStatus: 'ERROR',
      error: err.message,
    });
  }
};

/**
 * Returns documents owned by the calling citizen (PostgreSQL + IPFS CIDs).
 */
export const getMyDocuments = async (req: AuthRequest, res: Response) => {
  try {
    const citizenAddress = req.user?.address;
    if (!citizenAddress) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const checksummed = ethers.getAddress(citizenAddress);

    const documents = await prisma.documentMetadata.findMany({
      where: { citizenAddress: checksummed },
      orderBy: { createdAt: 'desc' },
      include: {
        grants: {
          orderBy: { createdAt: 'desc' },
        },
      },
    });

    const onChainHashes = await relayerService.getCitizenDocuments(checksummed);

    res.json({
      success: true,
      documents,
      onChainHashes,
    });
  } catch (err: any) {
    console.error('getMyDocuments error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

/**
 * Fetches document metadata and IPFS CID by document hash or ID.
 */
export const getDocumentByHash = async (req: AuthRequest, res: Response) => {
  try {
    const rawParam = req.params.documentHash;
    const documentIdentifier = Array.isArray(rawParam) ? rawParam[0] : rawParam;

    if (!documentIdentifier) {
      return res.status(400).json({ success: false, message: 'Document identifier parameter is required' });
    }

    const metadata = await prisma.documentMetadata.findFirst({
      where: {
        OR: [{ id: documentIdentifier }, { documentHash: documentIdentifier }],
      },
      include: {
        grants: true,
      },
    });

    if (!metadata) {
      return res.status(404).json({ success: false, message: 'Document not found' });
    }

    const onChainRecord = await relayerService.getDocument(metadata.documentHash);

    res.json({
      success: true,
      metadata,
      onChain: {
        documentHash: onChainRecord.documentHash,
        issuer: onChainRecord.issuer,
        citizen: onChainRecord.citizen,
        docType: onChainRecord.docType,
        issuedAt: onChainRecord.issuedAt?.toString(),
        isRevoked: onChainRecord.isRevoked,
        revocationReason: onChainRecord.revocationReason,
        supersededBy: onChainRecord.supersededBy,
        expiresAt: onChainRecord.expiresAt?.toString(),
      },
    });
  } catch (err: any) {
    console.error('getDocumentByHash error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

// Aliases for backwards compatibility
export const issue = issueDocument;
export const myDocuments = getMyDocuments;
export const revoke = revokeDocument;

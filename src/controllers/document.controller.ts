import type { Response } from 'express';
import { ethers } from 'ethers';
import { prisma } from '../db';
import { CryptoService } from '../services/crypto.service';
import { PinataService } from '../services/pinata.service';
import { RelayerService } from '../services/relayer.service';
import type { AuthRequest } from '../middlewares/auth.middleware';

const relayerService = new RelayerService();

/**
 * Issues an encrypted document to a citizen:
 * 1. Multer processes PDF upload.
 * 2. Encrypts document with symmetric AES-256-GCM session key.
 * 3. Wraps session key with citizen's public key using ECIES.
 * 4. Pins encrypted payload to IPFS via Pinata.
 * 5. Calls Sepolia contract via Relayer to anchor bytes32 hash.
 * 6. Records metadata in PostgreSQL.
 */
export const issueDocument = async (req: AuthRequest, res: Response) => {
  try {
    const file = req.file;
    const citizenWalletInput = req.body.citizenAddress || req.body.citizenWalletAddress;
    const docType = req.body.docType;

    if (!file) {
      return res.status(400).json({ success: false, message: 'PDF document file is required' });
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

    // 1. Generate 256-bit symmetric session key
    const sessionKey = CryptoService.generateSessionKey();

    // 2. Encrypt file buffer with AES-256-GCM
    const { ciphertext, iv, authTag } = CryptoService.encryptFile(file.buffer, sessionKey);

    // 3. Wrap session key with citizen's public key via ECIES
    const encryptedKey = await CryptoService.wrapSessionKey(sessionKey, citizenPublicKey);

    // 4. Bundle payload and pin to IPFS
    const payload = {
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      encryptedKey,
      docType,
      fileName: file.originalname,
      mimeType: file.mimetype,
      issuedAt: new Date().toISOString(),
    };

    const ipfsCid = await PinataService.pinJSONToIPFS(
      payload,
      `${docType}_${citizenAddress}_${Date.now()}`
    );

    // 5. Derive bytes32 document hash (Keccak-256 of original PDF buffer or provided hash)
    const documentHash = req.body.documentHash && req.body.documentHash.startsWith('0x')
      ? req.body.documentHash
      : ethers.keccak256(file.buffer);

    // 6. Anchor on Sepolia blockchain via Relayer
    const receipt = await relayerService.issueDocument(documentHash, citizenAddress, docType);

    // 7. Persist metadata in PostgreSQL
    const docRecord = await prisma.documentMetadata.create({
      data: {
        documentHash,
        ipfsCid,
        docType,
        issuerAddress,
        citizenAddress,
      },
    });

    res.json({
      success: true,
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
 * Returns documents owned by the calling citizen (PostgreSQL + IPFS CIDs).
 */
export const getMyDocuments = async (req: AuthRequest, res: Response) => {
  try {
    const citizenAddress = req.user?.address;
    if (!citizenAddress) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const checksummed = ethers.getAddress(citizenAddress);

    // Fetch from Postgres
    const documents = await prisma.documentMetadata.findMany({
      where: { citizenAddress: checksummed },
      orderBy: { createdAt: 'desc' },
    });

    // Also fetch on-chain hashes
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
 * Revokes a document on-chain (Issuer only).
 */
export const revokeDocument = async (req: AuthRequest, res: Response) => {
  try {
    const { documentHash } = req.body;
    if (!documentHash) {
      return res.status(400).json({ success: false, message: 'documentHash is required' });
    }

    const receipt = await relayerService.revokeDocument(documentHash);
    res.json({
      success: true,
      txHash: receipt.hash,
      documentHash,
    });
  } catch (err: any) {
    console.error('revokeDocument error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

/**
 * Fetches document metadata and IPFS CID by document hash.
 */
export const getDocumentByHash = async (req: AuthRequest, res: Response) => {
  try {
    const rawParam = req.params.documentHash;
    const documentHash = Array.isArray(rawParam) ? rawParam[0] : rawParam;

    if (!documentHash) {
      return res.status(400).json({ success: false, message: 'documentHash parameter is required' });
    }

    const metadata = await prisma.documentMetadata.findUnique({
      where: { documentHash },
    });

    const onChainRecord = await relayerService.getDocument(documentHash);

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

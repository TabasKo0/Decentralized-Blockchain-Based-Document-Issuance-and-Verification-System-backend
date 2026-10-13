import type { Request, Response } from 'express';
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
  const contractAddress = process.env.CONTRACT_ADDRESS || '0xAdba445e10E6d95fc1FA8914DaA8E0E5Ec5cEB9A';
  const isSepolia = rpcUrl.includes('sepolia');
  const provider = isSepolia
    ? new ethers.JsonRpcProvider(rpcUrl, 11155111, { staticNetwork: true })
    : new ethers.JsonRpcProvider(rpcUrl);

  const ABI = [
    'function documents(bytes32) external view returns (bytes32 documentHash, address issuer, address citizen, string docType, uint256 issuedAt, bool isRevoked)',
    'function isIssuer(address) external view returns (bool)',
  ];

  return new ethers.Contract(contractAddress, ABI, provider);
};

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
 * Public document verification endpoint:
 * 1. Takes uploaded file buffer (via upload.single('file')) or documentHash.
 * 2. Recalculates exact cryptographic hash (Keccak-256 of file buffer) used in issuance.
 * 3. Connects to DocumentIssuanceConsortium via read-only ethers provider.
 * 4. Queries on-chain document status via documents(bytes32).
 * 5. Queries PostgreSQL Prisma database for DocumentMetadata matching the hash.
 * 6. Returns JSON payload with isValid, onChain status, and database metadata.
 */
export const verifyDocument = async (req: Request, res: Response) => {
  try {
    const file = req.file;
    let documentHash: string | undefined;

    if (file && file.buffer) {
      documentHash = ethers.keccak256(file.buffer);
    } else if (req.body?.documentHash) {
      const rawHash = req.body.documentHash.trim();
      documentHash = rawHash.startsWith('0x') ? rawHash : `0x${rawHash}`;
    }

    if (!documentHash) {
      return res.status(400).json({
        success: false,
        isValid: false,
        message: 'A file upload or documentHash is required for verification',
      });
    }

    // Connect to contract using read-only provider (no signer/relayer needed)
    const readOnlyContract = getReadOnlyContract();
    const onChainRecord = await readOnlyContract.documents(documentHash);

    const exists = Boolean(onChainRecord && onChainRecord.issuedAt > 0n);
    const isRevoked = exists && Boolean(onChainRecord.isRevoked);
    const isValid = exists && !isRevoked;

    // Query Prisma database for matching document metadata
    const dbMetadata = await prisma.documentMetadata.findUnique({
      where: { documentHash },
    });

    res.json({
      success: true,
      isValid,
      documentHash,
      onChain: {
        exists,
        isRevoked,
        issuer: exists ? onChainRecord.issuer : null,
        citizen: exists ? onChainRecord.citizen : null,
        docType: exists ? onChainRecord.docType : null,
        issuedAt: exists ? onChainRecord.issuedAt.toString() : null,
      },
      metadata: dbMetadata
        ? {
            id: dbMetadata.id,
            ipfsCid: dbMetadata.ipfsCid,
            citizenAddress: dbMetadata.citizenAddress,
            issuerAddress: dbMetadata.issuerAddress,
            docType: dbMetadata.docType,
            createdAt: dbMetadata.createdAt,
          }
        : null,
    });
  } catch (err: any) {
    console.error('verifyDocument error:', err);
    res.status(500).json({
      success: false,
      isValid: false,
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

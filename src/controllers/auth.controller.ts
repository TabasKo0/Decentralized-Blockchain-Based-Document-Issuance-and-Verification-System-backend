import type { Request, Response } from 'express';
import { generateNonce, SiweMessage } from 'siwe';
import jwt from 'jsonwebtoken';
import { ethers } from 'ethers';
import EthCrypto from 'eth-crypto';
import { Role } from '@prisma/client';
import { prisma } from '../db';
import { CryptoService } from '../services/crypto.service';
import { KmsService } from '../services/kms.service';
import { RelayerService } from '../services/relayer.service';
import type { AuthRequest } from '../middlewares/auth.middleware';

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key-for-dev';
const relayerService = new RelayerService();

// In-memory store for active nonces with 5-minute TTL
const nonceStore = new Map<string, number>();

// Clean expired nonces periodically
setInterval(() => {
  const now = Date.now();
  for (const [nonce, expiry] of nonceStore.entries()) {
    if (expiry < now) {
      nonceStore.delete(nonce);
    }
  }
}, 60 * 1000);

/**
 * Generates an EIP-4361 compliant nonce for SIWE.
 */
export const getNonce = async (req: Request, res: Response) => {
  try {
    const nonce = generateNonce();
    nonceStore.set(nonce, Date.now() + 5 * 60 * 1000); // 5 minutes validity
    res.json({ success: true, nonce });
  } catch (err: any) {
    console.error('getNonce error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

/**
 * Verifies an EIP-4361 SIWE signature, provisions the user, and returns a session JWT.
 */
export const verifySiwe = async (req: Request, res: Response) => {
  try {
    const { message, signature } = req.body;

    if (!message || !signature) {
      return res.status(400).json({ success: false, message: 'Message and signature are required' });
    }

    const siweMessage = new SiweMessage(message);
    const { data: fields } = await siweMessage.verify({ signature });

    const nonceExpiry = nonceStore.get(fields.nonce);
    if (!nonceExpiry || nonceExpiry < Date.now()) {
      return res.status(400).json({ success: false, message: 'Invalid or expired nonce' });
    }
    // Consume nonce (one-time use)
    nonceStore.delete(fields.nonce);

    const checksumAddress = ethers.getAddress(fields.address);

    // Check if the address has ISSUER_ROLE on-chain
    const isChainIssuer = await relayerService.isIssuer(checksumAddress);
    const resolvedRole: Role = isChainIssuer ? Role.ISSUER : Role.CITIZEN;

    // Provision or update user in PostgreSQL
    const user = await prisma.user.upsert({
      where: { address: checksumAddress },
      update: {
        role: resolvedRole,
      },
      create: {
        address: checksumAddress,
        role: resolvedRole,
      },
    });

    const token = jwt.sign(
      {
        id: user.id,
        address: user.address,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        address: user.address,
        role: user.role,
      },
    });
  } catch (err: any) {
    console.error('verifySiwe error:', err);
    res.status(400).json({ success: false, error: err.message || 'Signature verification failed' });
  }
};

/**
 * Citizen Registration Endpoint:
 * 1. Generates 256-bit key pair.
 * 2. Splits private key via strict 2-of-2 Shamir.
 * 3. KMS-encrypts Share B and persists it to ShareRecord.
 * 4. Returns ephemeral Share C and public identity to citizen.
 * 5. Immediately purges raw private key and Share C from server memory.
 */
export const registerCitizen = async (req: Request, res: Response) => {
  let rawPrivateKey: string | null = null;
  let ephemeralShareC: string | null = null;

  try {
    // Generate Web3 Identity (256-bit key pair)
    const identity = EthCrypto.createIdentity();
    rawPrivateKey = identity.privateKey;
    const publicKey = identity.publicKey;
    const checksumAddress = ethers.getAddress(identity.address);

    // Strict 2-of-2 Shamir split
    const { shareB, shareC } = CryptoService.splitKey(rawPrivateKey);
    ephemeralShareC = shareC;

    // KMS-encrypt Share B with MASTER_KMS_KEY
    const { encryptedShareB, iv, authTag } = KmsService.encryptShareB(shareB);

    // Persist user and ShareRecord in PostgreSQL
    const user = await prisma.user.upsert({
      where: { address: checksumAddress },
      update: {
        role: Role.CITIZEN,
        publicKey,
      },
      create: {
        address: checksumAddress,
        role: Role.CITIZEN,
        publicKey,
      },
    });

    await prisma.shareRecord.upsert({
      where: { userAddress: checksumAddress },
      update: {
        encryptedShareB,
        iv,
        authTag,
      },
      create: {
        userAddress: checksumAddress,
        encryptedShareB,
        iv,
        authTag,
      },
    });

    // Prepare response with ephemeral Share C
    const responsePayload = {
      success: true,
      address: checksumAddress,
      publicKey,
      shareC: ephemeralShareC,
      message:
        'Citizen registered successfully. Ephemeral Share C generated. Please store Share C securely offline.',
    };

    // Respond to user
    res.json(responsePayload);
  } catch (err: any) {
    console.error('registerCitizen error:', err);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    // Zero-out / purge raw private key and ephemeral share from server memory
    if (rawPrivateKey) {
      rawPrivateKey = '0'.repeat(rawPrivateKey.length);
      rawPrivateKey = null;
    }
    if (ephemeralShareC) {
      ephemeralShareC = '0'.repeat(ephemeralShareC.length);
      ephemeralShareC = null;
    }
  }
};

/**
 * Returns decrypted Share B for an authenticated citizen to perform
 * client-side zero-knowledge decryption with their local Share C.
 */
export const getShareB = async (req: AuthRequest, res: Response) => {
  try {
    const userAddress = req.user?.address;
    if (!userAddress) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const shareRecord = await prisma.shareRecord.findUnique({
      where: { userAddress },
    });

    if (!shareRecord) {
      return res.status(404).json({ success: false, message: 'Share record not found for user' });
    }

    const shareB = KmsService.decryptShareB(
      shareRecord.encryptedShareB,
      shareRecord.iv,
      shareRecord.authTag
    );

    res.json({
      success: true,
      shareB,
    });
  } catch (err: any) {
    console.error('getShareB error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

/**
 * Server-assisted key reconstruction endpoint using Share C.
 */
export const recoverKey = async (req: Request, res: Response) => {
  let reconstructedKey: string | null = null;
  try {
    const { address, shareC } = req.body;

    if (!address || !shareC) {
      return res.status(400).json({ success: false, message: 'Address and shareC are required' });
    }

    const checksumAddress = ethers.getAddress(address);
    const shareRecord = await prisma.shareRecord.findUnique({
      where: { userAddress: checksumAddress },
    });

    if (!shareRecord) {
      return res.status(404).json({ success: false, message: 'Share record not found for address' });
    }

    const shareB = KmsService.decryptShareB(
      shareRecord.encryptedShareB,
      shareRecord.iv,
      shareRecord.authTag
    );

    reconstructedKey = CryptoService.combineShares(shareB, shareC);

    res.json({
      success: true,
      reconstructedPrivateKey: `0x${reconstructedKey}`,
    });
  } catch (err: any) {
    console.error('recoverKey error:', err);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    if (reconstructedKey) {
      reconstructedKey = '0'.repeat(reconstructedKey.length);
      reconstructedKey = null;
    }
  }
};

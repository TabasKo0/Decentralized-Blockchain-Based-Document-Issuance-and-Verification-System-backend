import type { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { prisma } from '../db';
import { CryptoService } from '../services/crypto.service';
import EthCrypto from 'eth-crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key-for-dev';

export const register = async (req: Request, res: Response) => {
  try {
    const { email, password, isIssuer } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password required' });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    
    // Generate Web3 Identity
    const identity = EthCrypto.createIdentity();
    const { privateKey, publicKey, address: walletAddress } = identity;

    // SSS Split
    const shares = CryptoService.splitKey(privateKey);
    const encryptedShareB = CryptoService.encryptShareB(shares.shareB);

    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        walletAddress,
        publicKey,
        encryptedShareB,
        isIssuer: !!isIssuer
      }
    });

    const token = jwt.sign({ id: user.id, email: user.email, isIssuer: user.isIssuer, walletAddress }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      success: true,
      token,
      user: { id: user.id, email: user.email, walletAddress, publicKey, isIssuer: user.isIssuer },
      shareA: shares.shareA,
      shareC: shares.shareC
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password required' });
    }
    
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, isIssuer: user.isIssuer, walletAddress: user.walletAddress }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      success: true,
      token,
      user: { id: user.id, email: user.email, walletAddress: user.walletAddress, publicKey: user.publicKey, isIssuer: user.isIssuer },
      encryptedShareB: user.encryptedShareB
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
};

export const recoverKey = async (req: Request, res: Response) => {
  try {
    const { email, shareC } = req.body;

    if (!email || !shareC) {
      return res.status(400).json({ success: false, message: 'Email and shareC required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const shareB = CryptoService.decryptShareB(user.encryptedShareB);
    const privateKeyHex = CryptoService.combineShares(shareB, shareC);

    res.json({
      success: true,
      reconstructedPrivateKey: privateKeyHex
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
};

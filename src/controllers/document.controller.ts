import type { Response } from 'express';
import type { AuthRequest } from '../middlewares/auth.middleware';
import { prisma } from '../db';
import { CryptoService } from '../services/crypto.service';
import { IpfsService } from '../services/ipfs.service';
import { RelayService } from '../services/relay.service';
import { ethers } from 'ethers';

export const issue = async (req: AuthRequest, res: Response) => {
  try {
    const { citizenWalletAddress, docType } = req.body;
    const file = req.file;

    if (!file || !citizenWalletAddress || !docType) {
      return res.status(400).json({ success: false, message: 'Missing parameters' });
    }

    const citizen = await prisma.user.findUnique({ where: { walletAddress: citizenWalletAddress } });
    if (!citizen) return res.status(404).json({ success: false, message: 'Citizen not found' });

    const sessionKey = CryptoService.generateSessionKey();
    const { ciphertext, iv, authTag } = CryptoService.encryptFile(file.buffer, sessionKey);
    const encryptedKey = await CryptoService.wrapSessionKey(sessionKey, citizen.publicKey);

    const payload = {
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      encryptedKey
    };

    const ipfsCID = await IpfsService.uploadPayload(payload);
    
    // Hash IPFS CID to act as documentHash on chain
    const documentHash = ethers.id(ipfsCID);

    const relayService = new RelayService(process.env.RPC_URL, process.env.RELAYER_PRIVATE_KEY, process.env.CONTRACT_ADDRESS);
    const tx = await relayService.issueDocumentOnChain(documentHash, citizenWalletAddress, docType);

    res.json({ success: true, txHash: tx.hash, ipfsCID, documentHash });
  } catch (err: any) {
    console.error('issue error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

export const uploadPersonal = async (req: AuthRequest, res: Response) => {
  try {
    const { docType } = req.body;
    const file = req.file;
    const citizenWalletAddress = req.user.walletAddress;

    if (!file || !docType) return res.status(400).json({ success: false, message: 'Missing parameters' });

    const citizen = await prisma.user.findUnique({ where: { walletAddress: citizenWalletAddress } });
    if (!citizen) return res.status(404).json({ success: false, message: 'Citizen not found' });

    const sessionKey = CryptoService.generateSessionKey();
    const { ciphertext, iv, authTag } = CryptoService.encryptFile(file.buffer, sessionKey);
    const encryptedKey = await CryptoService.wrapSessionKey(sessionKey, citizen.publicKey);

    const payload = {
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      encryptedKey
    };

    const ipfsCID = await IpfsService.uploadPayload(payload);
    const documentHash = ethers.id(ipfsCID);

    const relayService = new RelayService(process.env.RPC_URL, process.env.RELAYER_PRIVATE_KEY, process.env.CONTRACT_ADDRESS);
    const tx = await relayService.uploadPersonalDocumentOnChain(documentHash, docType);

    res.json({ success: true, txHash: tx.hash, ipfsCID, documentHash });
  } catch (err: any) {
    console.error('myDocuments error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

export const myDocuments = async (req: AuthRequest, res: Response) => {
  try {
    const relayService = new RelayService(process.env.RPC_URL, process.env.RELAYER_PRIVATE_KEY, process.env.CONTRACT_ADDRESS);
    const hashes = await relayService.getCitizenDocuments(req.user.walletAddress);
    res.json({ success: true, documentHashes: hashes });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
};

export const revoke = async (req: AuthRequest, res: Response) => {
  try {
    const { documentHash } = req.body;
    if (!documentHash) return res.status(400).json({ success: false, message: 'Missing documentHash' });

    const relayService = new RelayService(process.env.RPC_URL, process.env.RELAYER_PRIVATE_KEY, process.env.CONTRACT_ADDRESS);
    const tx = await relayService.revokeDocumentOnChain(documentHash);
    res.json({ success: true, txHash: tx.hash });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
};

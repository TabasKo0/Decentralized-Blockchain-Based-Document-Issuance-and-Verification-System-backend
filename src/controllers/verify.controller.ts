import type { Request, Response } from 'express';
import { ethers } from 'ethers';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const verifyDocument = async (req: Request, res: Response) => {
  try {
    const { documentHash } = req.params;
    const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8545';
    const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS || '0x0000000000000000000000000000000000000000';

    const provider = new ethers.JsonRpcProvider(RPC_URL);
    
    let abi: any[] = [];
    const artifactPath = path.resolve(__dirname, '../../artifacts/contracts/DocumentIssuanceConsortium.sol/DocumentIssuanceConsortium.json');
    if (fs.existsSync(artifactPath)) {
      abi = JSON.parse(fs.readFileSync(artifactPath, 'utf8')).abi;
    }

    const contract = new ethers.Contract(CONTRACT_ADDRESS, abi, provider);
    
    const record = await contract.documents(documentHash);

    if (record.issuedAt === 0n) {
      return res.status(404).json({ success: false, message: 'Document not found' });
    }

    res.json({
      success: true,
      exists: true,
      issuer: record.issuer,
      citizen: record.citizen,
      docType: record.docType,
      issuedAt: record.issuedAt.toString(), // Convert BigInt
      isRevoked: record.isRevoked
    });
  } catch (err: any) {
    console.error('verifyDocument error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

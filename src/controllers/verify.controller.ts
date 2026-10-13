import type { Request, Response } from 'express';
import { RelayerService } from '../services/relayer.service';

const relayerService = new RelayerService();

export const verifyDocument = async (req: Request, res: Response) => {
  try {
    const rawParam = req.params.documentHash;
    const documentHash = Array.isArray(rawParam) ? rawParam[0] : rawParam;

    if (!documentHash) {
      return res.status(400).json({ success: false, message: 'Document hash is required' });
    }

    const record = await relayerService.getDocument(documentHash);

    if (!record || record.issuedAt === 0n) {
      return res.status(404).json({ success: false, message: 'Document not found on-chain' });
    }

    res.json({
      success: true,
      exists: true,
      documentHash: record.documentHash,
      issuer: record.issuer,
      citizen: record.citizen,
      docType: record.docType,
      issuedAt: record.issuedAt.toString(),
      isRevoked: record.isRevoked,
    });
  } catch (err: any) {
    console.error('verifyDocument error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

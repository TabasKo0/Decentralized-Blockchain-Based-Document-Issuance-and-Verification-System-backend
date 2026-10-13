import { Router } from 'express';
import {
  issueDocument,
  getMyDocuments,
  revokeDocument,
  getDocumentByHash,
} from '../controllers/document.controller';
import { authenticateJWT } from '../middlewares/auth.middleware';
import { requireIssuer } from '../middlewares/role.middleware';
import { upload } from '../middlewares/upload.middleware';

const router = Router();

// Citizen Route: retrieve all documents assigned to authenticated citizen
router.get('/my-documents', authenticateJWT, getMyDocuments);

// Document details by hash
router.get('/:documentHash', authenticateJWT, getDocumentByHash);

// Issuer Routes
router.post('/issue', authenticateJWT, requireIssuer, upload.single('file'), issueDocument);
router.post('/revoke', authenticateJWT, requireIssuer, revokeDocument);

export default router;

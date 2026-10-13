import { Router } from 'express';
import {
  issueDocument,
  verifyDocument,
  createGrant,
  verifyGrant,
  revokeDocument,
  supersedeDocument,
  downloadDocument,
  getMyDocuments,
  getDocumentByHash,
} from '../controllers/document.controller';
import { authenticateJWT } from '../middlewares/auth.middleware';
import { requireIssuer } from '../middlewares/role.middleware';
import { upload } from '../middlewares/upload.middleware';

const router = Router();

// Public Routes (No JWT required)
router.post('/verify', upload.single('file'), verifyDocument);
router.get('/verify-grant/:token', verifyGrant);

// Citizen & Common Authenticated Routes
router.get('/my-documents', authenticateJWT, getMyDocuments);
router.get('/:id/download', authenticateJWT, downloadDocument);
router.post('/:id/grant', authenticateJWT, createGrant);

// Issuer Authenticated Routes
router.post('/issue', authenticateJWT, requireIssuer, upload.single('file'), issueDocument);
router.post('/:id/revoke', authenticateJWT, requireIssuer, revokeDocument);
router.post('/:id/supersede', authenticateJWT, requireIssuer, supersedeDocument);
router.post('/revoke', authenticateJWT, requireIssuer, revokeDocument); // backwards compatibility

// Catch-all document lookup by hash or ID
router.get('/:documentHash', authenticateJWT, getDocumentByHash);

export default router;

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
  getIssuedDocuments,
  getDocumentById,
  revokeGrant,
} from '../controllers/document.controller';
import { authenticateJWT } from '../middlewares/auth.middleware';
import { requireIssuer } from '../middlewares/role.middleware';
import { upload } from '../middlewares/upload.middleware';

const router = Router();

// Public Routes (No JWT required)
router.post('/verify', upload.single('file'), verifyDocument);
router.get('/verify-grant/:token', verifyGrant);

// Specific Named Authenticated Routes (Registered BEFORE /:id to avoid param capture)
router.get('/my-documents', authenticateJWT, getMyDocuments);
router.get('/issued', authenticateJWT, requireIssuer, getIssuedDocuments);
router.post('/grants/:grantId/revoke', authenticateJWT, revokeGrant);

// Issuer Authenticated Specific Actions
router.post('/issue', authenticateJWT, requireIssuer, upload.single('file'), issueDocument);
router.post('/revoke', authenticateJWT, requireIssuer, revokeDocument); // backwards compatibility

// Parameterized Document Routes (with :id)
router.get('/:id/download', authenticateJWT, downloadDocument);
router.post('/:id/grant', authenticateJWT, createGrant);
router.post('/:id/revoke', authenticateJWT, requireIssuer, revokeDocument);
router.post('/:id/supersede', authenticateJWT, requireIssuer, supersedeDocument);
router.get('/:id', authenticateJWT, getDocumentById);

export default router;

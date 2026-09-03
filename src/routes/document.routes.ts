import { Router } from 'express';
import { issue, myDocuments, revoke } from '../controllers/document.controller';
import { authenticateJWT } from '../middlewares/auth.middleware';
import { requireIssuer } from '../middlewares/role.middleware';
import { upload } from '../middlewares/upload.middleware';

const router = Router();

// Citizen Routes

router.get('/my-documents', authenticateJWT, myDocuments);

// Issuer Routes
router.post('/issue', authenticateJWT, requireIssuer, upload.single('file'), issue);
router.post('/revoke', authenticateJWT, requireIssuer, revoke);

export default router;

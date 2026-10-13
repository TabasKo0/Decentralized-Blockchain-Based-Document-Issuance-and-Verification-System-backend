import { Router } from 'express';
import {
  getNonce,
  verifySiwe,
  registerCitizen,
  getShareB,
  recoverKey,
} from '../controllers/auth.controller';
import { authenticateJWT } from '../middlewares/auth.middleware';

const router = Router();

// EIP-4361 SIWE Endpoints
router.get('/nonce', getNonce);
router.post('/verify', verifySiwe);

// Citizen Registration Endpoint
router.post('/register-citizen', registerCitizen);

// Decrypted Share B endpoint for client-side ZK decryption
router.get('/share-b', authenticateJWT, getShareB);

// Key recovery
router.post('/recover-key', recoverKey);

export default router;

import { Router } from 'express';
import { verifyDocument } from '../controllers/verify.controller';

const router = Router();

router.get('/:documentHash', verifyDocument);

export default router;

import { Router } from 'express';
import { register, login, recoverKey } from '../controllers/auth.controller';

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.post('/recover-key', recoverKey);

export default router;

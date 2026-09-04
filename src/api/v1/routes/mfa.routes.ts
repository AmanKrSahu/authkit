import { authenticateJWT } from '@core/common/strategies/jwt.strategy';
import { Router } from 'express';

import { MfaController } from '../controllers/mfa.controller';
import { authRateLimiter } from '../middlewares/rate-limiter.middleware';

const mfaController = new MfaController();

const mfaRoutes = Router();

mfaRoutes.post('/setup', authenticateJWT, mfaController.generateMFASetup);
mfaRoutes.post('/verify-setup', authenticateJWT, authRateLimiter, mfaController.verifyMFASetup);

mfaRoutes.post('/revoke', authenticateJWT, mfaController.revokeMFA);

mfaRoutes.post('/verify-login', authRateLimiter, mfaController.verifyMFAForLogin);

export default mfaRoutes;

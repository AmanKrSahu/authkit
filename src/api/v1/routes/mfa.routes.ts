import { authenticateJWT } from '@core/common/strategies/jwt.strategy';
import { Router } from 'express';

import { authRateLimiter } from '../middlewares/rate-limiter.middleware';
import { mfaController } from '../modules/mfa.module';

const mfaRoutes = Router();

mfaRoutes.post('/setup', authenticateJWT, mfaController.generateMFASetup);
mfaRoutes.post('/verify-setup', authenticateJWT, authRateLimiter, mfaController.verifyMFASetup);

mfaRoutes.post('/revoke', authenticateJWT, mfaController.revokeMFA);

mfaRoutes.post('/verify-login', authRateLimiter, mfaController.verifyMFAForLogin);

export default mfaRoutes;

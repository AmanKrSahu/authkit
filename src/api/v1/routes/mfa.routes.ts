import { authenticateJWT } from '@core/common/strategies/jwt.strategy';
import { Router } from 'express';

import { mfaController } from '../modules/mfa.module';

const mfaRoutes = Router();

mfaRoutes.post('/setup', authenticateJWT, mfaController.generateMFASetup);
mfaRoutes.post('/verify-setup', authenticateJWT, mfaController.verifyMFASetup);

mfaRoutes.post('/revoke', authenticateJWT, mfaController.revokeMFA);

mfaRoutes.post('/verify-login', mfaController.verifyMFAForLogin);

export default mfaRoutes;

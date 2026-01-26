import { Router } from 'express';

import { mfaController } from '../modules/mfa.module';

const mfaRoutes = Router();

mfaRoutes.post('/setup', mfaController.generateMFASetup);
mfaRoutes.post('/verify-setup', mfaController.verifyMFASetup);

mfaRoutes.post('/revoke', mfaController.revokeMFA);

mfaRoutes.post('/verify-login', mfaController.verifyMFAForLogin);

export default mfaRoutes;

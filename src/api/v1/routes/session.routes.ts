import { Router } from 'express';

import { sessionController } from '../modules/session.module';

const sessionRoutes = Router();

sessionRoutes.get('/', sessionController.getSessions);
sessionRoutes.get('/:sessionId', sessionController.getSessionById);
sessionRoutes.delete('/', sessionController.revokeSessions);
sessionRoutes.delete('/:sessionId', sessionController.revokeSessionById);

export default sessionRoutes;

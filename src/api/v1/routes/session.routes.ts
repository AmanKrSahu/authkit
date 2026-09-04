import { Router } from 'express';

import { SessionController } from '../controllers/session.controller';

const sessionController = new SessionController();

const sessionRoutes = Router();

sessionRoutes.get('/', sessionController.getSessions);
sessionRoutes.get('/:sessionId', sessionController.getSessionById);

sessionRoutes.delete('/', sessionController.revokeSessions);
sessionRoutes.delete('/:sessionId', sessionController.revokeSessionById);

export default sessionRoutes;

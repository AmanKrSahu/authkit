import { Router } from 'express';

import { oidcController } from '../modules/oidc.module';

const oidcRoutes = Router();

oidcRoutes.get('/interaction/:uid', oidcController.interaction);
oidcRoutes.post('/interaction/:uid/login', oidcController.loginInteraction);
oidcRoutes.post('/interaction/:uid/mfa', oidcController.mfaInteraction);
oidcRoutes.post('/interaction/:uid/confirm', oidcController.confirmInteraction);
oidcRoutes.get('/interaction/:uid/abort', oidcController.abortInteraction);

export default oidcRoutes;

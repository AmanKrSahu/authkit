import { Router } from 'express';

import { OidcController } from '../controllers/oidc.controller';

const oidcController = new OidcController();

const oidcRoutes = Router();

oidcRoutes.get('/interaction/:uid', oidcController.interaction);
oidcRoutes.post('/interaction/:uid/login', oidcController.loginInteraction);
oidcRoutes.post('/interaction/:uid/mfa', oidcController.mfaInteraction);
oidcRoutes.post('/interaction/:uid/webauthn/options', oidcController.webAuthnOptionsInteraction);
oidcRoutes.post('/interaction/:uid/webauthn/verify', oidcController.webAuthnVerifyInteraction);
oidcRoutes.post('/interaction/:uid/webauthn/mfa', oidcController.webAuthnMfaInteraction);
oidcRoutes.post('/interaction/:uid/confirm', oidcController.confirmInteraction);
oidcRoutes.get('/interaction/:uid/abort', oidcController.abortInteraction);

export default oidcRoutes;

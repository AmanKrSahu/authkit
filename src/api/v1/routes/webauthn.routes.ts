import { authenticateJWT } from '@core/common/strategies/jwt.strategy';
import { Router } from 'express';

import { WebAuthnController } from '../controllers/webauthn.controller';
import { authRateLimiter } from '../middlewares/rate-limiter.middleware';

const webAuthnController = new WebAuthnController();
const webAuthnRoutes = Router();

// Registration Ceremony
webAuthnRoutes.post(
  '/register/options',
  authenticateJWT,
  authRateLimiter,
  webAuthnController.generateRegistrationOptions
);
webAuthnRoutes.post(
  '/register/verify',
  authenticateJWT,
  authRateLimiter,
  webAuthnController.verifyRegistration
);

// Authentication Ceremony (Passwordless / Discoverable Passkey Login)
webAuthnRoutes.post(
  '/authenticate/options',
  authRateLimiter,
  webAuthnController.generateAuthenticationOptions
);
webAuthnRoutes.post(
  '/authenticate/verify',
  authRateLimiter,
  webAuthnController.verifyAuthentication
);

// Secondary Factor MFA Verification via Passkey
webAuthnRoutes.post(
  '/authenticate/verify-mfa',
  authRateLimiter,
  webAuthnController.verifyAuthenticationForMfa
);

// Authenticator Management
webAuthnRoutes.get('/authenticators', authenticateJWT, webAuthnController.listAuthenticators);
webAuthnRoutes.delete(
  '/authenticators/:id',
  authenticateJWT,
  webAuthnController.deleteAuthenticator
);
webAuthnRoutes.patch(
  '/authenticators/:id',
  authenticateJWT,
  webAuthnController.updateAuthenticatorName
);

export default webAuthnRoutes;

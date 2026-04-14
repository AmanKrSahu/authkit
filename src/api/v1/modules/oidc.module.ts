import { OidcController } from '../controllers/oidc.controller';
import { OidcService } from '../services/oidc.service';
import { authService } from './auth.module';
import { mfaService } from './mfa.module';
import { sessionService } from './session.module';

export const oidcService = new OidcService();
export const oidcController = new OidcController(
  oidcService,
  authService,
  mfaService,
  sessionService
);

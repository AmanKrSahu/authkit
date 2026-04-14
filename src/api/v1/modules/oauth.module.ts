import { EmailService } from '@core/mailers/resend';

import { OAuthController } from '../controllers/oauth.controller';
import { OAuthService } from '../services/oauth.service';
import { oidcService } from './oidc.module';

const emailService = new EmailService();
const oauthService = new OAuthService(emailService);
const oauthController = new OAuthController(oauthService, oidcService);

export { oauthController, oauthService };

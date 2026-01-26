import { EmailService } from '@core/mailers/resend';

import { OAuthController } from '../controllers/oauth.controller';
import { OAuthService } from '../services/oauth.service';

const emailService = new EmailService();
const oauthService = new OAuthService(emailService);
const oauthController = new OAuthController(oauthService);

export { oauthController, oauthService };

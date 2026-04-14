import { EmailService } from '@core/mailers/resend';

import { MagicLinkController } from '../controllers/magic-link.controller';
import { MagicLinkService } from '../services/magic-link.service';
import { oidcService } from './oidc.module';

const emailService = new EmailService();
const magicLinkService = new MagicLinkService(emailService);
const magicLinkController = new MagicLinkController(magicLinkService, oidcService);

export { magicLinkController, magicLinkService };

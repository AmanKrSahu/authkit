import { EmailService } from '@core/mailers/resend';

import { AuthController } from '../controllers/auth.controller';
import { AuthService } from '../services/auth.service';

const emailService = new EmailService();
const authService = new AuthService(emailService);
const authController = new AuthController(authService);

export { authController, authService };

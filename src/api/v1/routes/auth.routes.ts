import { authenticateJWT } from '@core/common/strategies/jwt.strategy';
import { Router } from 'express';

import { authController } from '../modules/auth.module';

const authRoutes = Router();

authRoutes.post('/register', authController.register);
authRoutes.post('/login', authController.login);
authRoutes.post('/logout', authenticateJWT, authController.logout);

authRoutes.post('/refresh-token', authController.refreshAccessToken);

authRoutes.post('/verify-email', authController.verifyEmail);
authRoutes.post('/resend-verification', authController.resendVerification);

authRoutes.post('/forgot-password', authController.forgotPassword);
authRoutes.post('/verify-otp', authController.verifyOtp);
authRoutes.post('/reset-password', authController.resetPassword);
authRoutes.post('/change-password', authenticateJWT, authController.changePassword);

export default authRoutes;

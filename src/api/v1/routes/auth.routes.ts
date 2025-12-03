import { authenticateJWT } from '@core/common/strategies/jwt.strategy';
import { config } from '@core/config/app.config';
import { Router } from 'express';
import passport from 'passport';

import { authController } from '../modules/auth.module';

const authRoutes = Router();

authRoutes.post('/register', authController.register);
authRoutes.post('/login', authController.login);
authRoutes.post('/logout', authenticateJWT, authController.logout);

authRoutes.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false,
  })
);

// Construct success and failure URLs for Google OAuth callbacks
const failedUrl = `${config.FRONTEND_ORIGINS[0]}/auth/sign-in?status=failure`;

authRoutes.get(
  '/google/callback',
  passport.authenticate('google', {
    session: false,
    failureRedirect: failedUrl,
  }),
  authController.googleCallback
);

authRoutes.post('/refresh-token', authController.refreshAccessToken);

authRoutes.post('/verify-email', authController.verifyEmail);
authRoutes.post('/resend-verification', authController.resendVerification);

authRoutes.post('/forgot-password', authController.forgotPassword);
authRoutes.post('/verify-otp', authController.verifyOtp);
authRoutes.post('/reset-password', authController.resetPassword);
authRoutes.post('/change-password', authenticateJWT, authController.changePassword);

export default authRoutes;

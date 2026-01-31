import { config } from '@core/config/app.config';
import { Router } from 'express';
import passport from 'passport';

import { oauthController } from '../modules/oauth.module';

const oauthRoutes = Router();

/**
 * @openapi
 * /oauth/google:
 *   get:
 *     tags:
 *       - OAuth
 *     summary: Initiate Google OAuth
 *     description: Redirects the user to Google for authentication.
 *     security: []
 *     responses:
 *       302:
 *         description: Redirects to Google
 *       400:
 *         description: Bad request
 *       500:
 *         description: Internal server error
 */
oauthRoutes.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false,
  })
);

const failedUrl = `${config.FRONTEND_ORIGINS[0]}/auth/sign-in?status=failure`;

oauthRoutes.get(
  '/google/callback',
  passport.authenticate('google', {
    session: false,
    failureRedirect: failedUrl,
  }),
  oauthController.googleCallback
);

export default oauthRoutes;

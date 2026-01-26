import { config } from '@core/config/app.config';
import { Router } from 'express';
import passport from 'passport';

import { oauthController } from '../modules/oauth.module';

const oauthRoutes = Router();

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

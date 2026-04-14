import { config } from '@core/config/app.config';
import { Router } from 'express';
import passport from 'passport';

import { oauthController } from '../modules/oauth.module';

const oauthRoutes = Router();

oauthRoutes.get('/google', (req, res, next) => {
  const state = req.query.uid ? JSON.stringify({ uid: req.query.uid }) : undefined;

  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false,
    state,
  })(req, res, next);
});

// It assumes that the sign-in page is at the first origin
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

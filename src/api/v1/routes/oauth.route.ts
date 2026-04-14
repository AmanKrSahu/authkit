import { getValidRedirectUrl } from '@core/common/utils/url.util';
import { Router } from 'express';
import passport from 'passport';

import { oauthController } from '../modules/oauth.module';

const oauthRoutes = Router();

oauthRoutes.get('/google', (req, res, next) => {
  const { uid, redirectUrl } = req.query;
  const statePayload: Record<string, string> = {};
  if (typeof uid === 'string') statePayload.uid = uid;
  if (typeof redirectUrl === 'string') statePayload.redirectUrl = redirectUrl;

  const state = Object.keys(statePayload).length > 0 ? JSON.stringify(statePayload) : undefined;

  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false,
    state,
  })(req, res, next);
});

oauthRoutes.get(
  '/google/callback',
  (req, res, next) => {
    let redirectUrl;
    try {
      if (req.query.state) {
        const parsedState = JSON.parse(req.query.state as string);
        redirectUrl = parsedState.redirectUrl;
      }
    } catch {
      // Ignore JSON parse errors
    }

    const baseUrl = getValidRedirectUrl(redirectUrl);
    const failureRedirect = `${baseUrl}/auth/sign-in?status=failure`;

    passport.authenticate('google', {
      session: false,
      failureRedirect,
    })(req, res, next);
  },
  oauthController.googleCallback
);

export default oauthRoutes;

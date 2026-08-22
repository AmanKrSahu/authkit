import crypto from 'node:crypto';

import { deleteCache, getCache, setCache } from '@core/common/utils/redis-helpers';
import { getValidRedirectUrl } from '@core/common/utils/url.util';
import { Router } from 'express';
import passport from 'passport';

import { OAuthController } from '../controllers/oauth.controller';

const oauthController = new OAuthController();

const oauthRoutes = Router();

oauthRoutes.get('/google', async (req, res, next) => {
  try {
    const { uid, redirectUrl } = req.query;
    const statePayload: Record<string, string> = {};
    if (typeof uid === 'string') statePayload.uid = uid;
    if (typeof redirectUrl === 'string') statePayload.redirectUrl = redirectUrl;

    const stateId = crypto.randomUUID();
    const data = JSON.stringify(statePayload);
    // Cache the OAuth state for 10 minutes
    await setCache(`oauth_state:${stateId}`, data, 600);

    passport.authenticate('google', {
      scope: ['profile', 'email'],
      session: false,
      state: stateId,
    })(req, res, next);
  } catch (error) {
    next(error);
  }
});

oauthRoutes.get(
  '/google/callback',
  async (req, res, next) => {
    try {
      const stateId = req.query.state as string;
      if (!stateId) {
        const failureRedirect = `${getValidRedirectUrl()}/auth/sign-in?status=failure`;
        return res.redirect(failureRedirect);
      }

      const cachedData = await getCache(`oauth_state:${stateId}`);
      if (!cachedData) {
        const failureRedirect = `${getValidRedirectUrl()}/auth/sign-in?status=failure`;
        return res.redirect(failureRedirect);
      }

      // Delete the state cache immediately to prevent replay attacks
      await deleteCache(`oauth_state:${stateId}`);

      // Overwrite req.query.state with the validated JSON string so downstream code remains secure
      req.query.state = cachedData;

      let redirectUrl;
      try {
        const parsedState = JSON.parse(cachedData);
        redirectUrl = parsedState.redirectUrl;
      } catch {
        // Ignore JSON parse errors
      }

      const baseUrl = getValidRedirectUrl(redirectUrl);
      const failureRedirect = `${baseUrl}/auth/sign-in?status=failure`;

      passport.authenticate('google', {
        session: false,
        failureRedirect,
      })(req, res, next);
    } catch (error) {
      next(error);
    }
  },
  oauthController.googleCallback
);

export default oauthRoutes;

import { GoogleProfile } from '@core/common/interface/oauth.interface';
import { setAuthenticationCookies, setCsrfCookie } from '@core/common/utils/cookie';
import { getClientIP, getUserAgent } from '@core/common/utils/metadata';
import { config } from '@core/config/app.config';
import { AsyncHandler } from '@core/decorator/async-handler.decorator';
import type { Request, Response } from 'express';

import { OAuthService } from '../services/oauth.service';

export class OAuthController {
  private oauthService: OAuthService;

  constructor(oauthService: OAuthService) {
    this.oauthService = oauthService;
  }

  /**
   * @openapi
   * /oauth/google/callback:
   *   get:
   *     tags:
   *       - OAuth
   *     summary: Google OAuth callback
   *     description: Handles the callback from Google OAuth authentication.
   *     responses:
   *       200:
   *         description: OAuth login successful, redirects to frontend
   *       401:
   *         description: Authentication failed
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public googleCallback = async (req: Request, res: Response) => {
    const userAgent = getUserAgent(req);
    const ipAddress = getClientIP(req);
    const profile = req.user as GoogleProfile;

    const { refreshToken } = await this.oauthService.loginWithGoogle({
      profile,
      userAgent,
      ipAddress,
    });

    // Generate random CSRF token
    const csrfToken = crypto.randomUUID();

    setAuthenticationCookies({
      res,
      refreshToken,
    });
    setCsrfCookie({ res, csrfToken });

    return res.redirect(`${config.FRONTEND_ORIGINS[1]}?status=success`);
  };
}

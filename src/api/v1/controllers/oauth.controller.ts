import { OidcService } from '@api/v1/services/oidc.service';
import { GoogleProfile } from '@core/common/interface/oauth.interface';
import { setAuthenticationCookies, setCsrfCookie } from '@core/common/utils/cookie';
import { getClientIP, getUserAgent } from '@core/common/utils/metadata';
import { config } from '@core/config/app.config';
import { AsyncHandler } from '@core/decorator/async-handler.decorator';
import type { Request, Response } from 'express';

import { OAuthService } from '../services/oauth.service';

export class OAuthController {
  private oauthService: OAuthService;
  private oidcService: OidcService;

  constructor(oauthService: OAuthService, oidcService: OidcService) {
    this.oauthService = oauthService;
    this.oidcService = oidcService;
  }

  @AsyncHandler
  public googleCallback = async (req: Request, res: Response) => {
    const userAgent = getUserAgent(req);
    const ipAddress = getClientIP(req);
    const profile = req.user as GoogleProfile;

    const { refreshToken, user } = await this.oauthService.loginWithGoogle({
      profile,
      userAgent,
      ipAddress,
    });

    // Check if we are in an OIDC interaction
    const state = req.query.state as string;
    if (state) {
      try {
        const { uid } = JSON.parse(state);
        if (uid) {
          await this.oidcService.submitLogin(req, res, user.id);
          return;
        }
      } catch {
        // Ignore JSON parse errors, treat as normal flow
      }
    }

    const csrfToken = crypto.randomUUID();

    setAuthenticationCookies({
      res,
      refreshToken,
    });
    setCsrfCookie({ res, csrfToken });

    // It assumes that the dashboard is at the second origin
    return res.redirect(`${config.FRONTEND_ORIGINS[1]}?status=success`);
  };
}

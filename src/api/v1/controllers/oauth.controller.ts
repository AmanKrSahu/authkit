import { OidcService } from '@api/v1/services/oidc.service';
import { GoogleProfile } from '@core/common/interface/oauth.interface';
import { setAuthenticationCookies, setCsrfCookie } from '@core/common/utils/cookie';
import { getClientIP, getUserAgent } from '@core/common/utils/metadata';
import { getValidRedirectUrl } from '@core/common/utils/url.util';
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
    let redirectUrl;
    if (state) {
      try {
        const parsed = JSON.parse(state);
        if (parsed.uid) {
          await this.oidcService.submitLogin(req, res, user.id);
          return;
        }
        redirectUrl = parsed.redirectUrl;
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

    const baseUrl = getValidRedirectUrl(redirectUrl);
    return res.redirect(`${baseUrl}?status=success`);
  };
}

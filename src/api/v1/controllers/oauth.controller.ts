import { GoogleProfile } from '@core/common/interface/oauth.interface';
import { setAuthenticationCookies } from '@core/common/utils/cookie';
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

  @AsyncHandler
  public googleCallback = async (req: Request, res: Response) => {
    const userAgent = getUserAgent(req);
    const ipAddress = getClientIP(req);
    const profile = req.user as GoogleProfile;

    const { accessToken, refreshToken } = await this.oauthService.loginWithGoogle({
      profile,
      userAgent,
      ipAddress,
    });

    return setAuthenticationCookies({
      res,
      accessToken,
      refreshToken,
    }).redirect(`${config.FRONTEND_ORIGINS[1]}?status=success`);
  };
}

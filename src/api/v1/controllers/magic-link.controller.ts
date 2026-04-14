import { OidcService } from '@api/v1/services/oidc.service';
import { AppError } from '@core/common/utils/app-error';
import {
  setAuthenticationCookies,
  setCsrfCookie,
  setMfaLoginCookie,
} from '@core/common/utils/cookie';
import { getClientIP, getUserAgent } from '@core/common/utils/metadata';
import {
  loginMagicLinkSchema,
  verifyMagicLinkSchema,
} from '@core/common/validators/magic-link.validator';
import { HTTPSTATUS } from '@core/config/http.config';
import { AsyncHandler } from '@core/decorator/async-handler.decorator';
import type { Request, Response } from 'express';

import { MagicLinkService } from '../services/magic-link.service';

export class MagicLinkController {
  private magicLinkService: MagicLinkService;
  private oidcService: OidcService;

  constructor(magicLinkService: MagicLinkService, oidcService: OidcService) {
    this.magicLinkService = magicLinkService;
    this.oidcService = oidcService;
  }

  @AsyncHandler
  public login = async (req: Request, res: Response) => {
    const body = loginMagicLinkSchema.parse({ ...req.body });

    await this.magicLinkService.login(body);

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'If an account exists with this email, a magic link has been sent.',
    });
  };

  @AsyncHandler
  public verify = async (req: Request, res: Response) => {
    const userAgent = getUserAgent(req);
    const ipAddress = getClientIP(req);

    const body = verifyMagicLinkSchema.parse({ ...req.body });

    const { user, mfaRequired, accessToken, refreshToken, mfaLoginToken, uid } =
      await this.magicLinkService.verify({
        ...body,
        userAgent,
        ipAddress,
      });

    if (mfaRequired) {
      if (!mfaLoginToken) {
        throw new AppError(
          'An error occurred during login. Please try again.',
          HTTPSTATUS.INTERNAL_SERVER_ERROR
        );
      }

      return setMfaLoginCookie({ res, mfaLoginToken }).status(HTTPSTATUS.OK).json({
        success: true,
        message: 'MFA verification required',
        data: { user },
        uid,
      });
    }

    if (uid) {
      await this.oidcService.submitLogin(req, res, user.id);
      return;
    }

    const csrfToken = crypto.randomUUID();

    setAuthenticationCookies({ res, refreshToken });
    setCsrfCookie({ res, csrfToken });

    res.setHeader('Cache-Control', 'no-store');

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'User signed in successfully',
      data: { user, accessToken },
    });
  };
}

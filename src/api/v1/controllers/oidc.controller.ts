import { AuthService } from '@api/v1/services/auth.service';
import { MfaService } from '@api/v1/services/mfa.service';
import { OidcService } from '@api/v1/services/oidc.service';
import { SessionService } from '@api/v1/services/session.service';
import { AppError } from '@core/common/utils/app-error';
import { setMfaLoginCookie } from '@core/common/utils/cookie';
import { getClientIP, getUserAgent } from '@core/common/utils/metadata';
import { loginSchema } from '@core/common/validators/auth.validator';
import { HTTPSTATUS } from '@core/config/http.config';
import { AsyncHandler } from '@core/decorator/async-handler.decorator';
import type { Request, Response } from 'express';

export class OidcController {
  private oidcService: OidcService;
  private authService: AuthService;
  private mfaService: MfaService;
  private sessionService: SessionService;

  constructor(
    oidcService: OidcService,
    authService: AuthService,
    mfaService: MfaService,
    sessionService: SessionService
  ) {
    this.oidcService = oidcService;
    this.authService = authService;
    this.mfaService = mfaService;
    this.sessionService = sessionService;
  }

  @AsyncHandler
  public interaction = async (req: Request, res: Response) => {
    const { details, client } = await this.oidcService.getInteractionContext(req, res);
    const { uid, prompt } = details;

    if (prompt.name === 'login') {
      // SESSION BRIDGE: Check for existing Direct API session
      const refreshToken = req.cookies.refreshToken;
      if (refreshToken) {
        const user = await this.sessionService.validateSession(refreshToken);
        if (user) {
          // Found valid Direct API session, automatically login to OIDC
          return await this.oidcService.submitLogin(req, res, user.id);
        }
      }

      return res.status(HTTPSTATUS.OK).json({
        uid,
        prompt,
        client,
        redirectTo: `/login?uid=${uid}`,
      });
    }

    if (prompt.name === 'consent') {
      return res.status(HTTPSTATUS.OK).json({
        uid,
        prompt,
        client,
        redirectTo: `/consent?uid=${uid}`,
      });
    }

    throw new AppError('Unknown interaction prompt', HTTPSTATUS.BAD_REQUEST);
  };

  @AsyncHandler
  public loginInteraction = async (req: Request, res: Response) => {
    const userAgent = getUserAgent(req);
    const ipAddress = getClientIP(req);

    const body = loginSchema.parse({
      ...req.body,
    });

    const { user, mfaRequired, mfaLoginToken } = await this.authService.login({
      ...body,
      ipAddress,
      userAgent,
    });

    if (mfaRequired) {
      if (!mfaLoginToken) {
        throw new AppError(
          'An error occurred during login. Please try again.',
          HTTPSTATUS.INTERNAL_SERVER_ERROR
        );
      }

      setMfaLoginCookie({ res, mfaLoginToken }).status(HTTPSTATUS.OK).json({
        success: true,
        mfaRequired: true,
        message: 'MFA verification required',
        uid: req.params.uid,
      });
    }

    await this.oidcService.submitLogin(req, res, user.id);
  };

  @AsyncHandler
  public confirmInteraction = async (req: Request, res: Response) => {
    await this.oidcService.submitConsent(req, res);
  };

  @AsyncHandler
  public abortInteraction = async (req: Request, res: Response) => {
    await this.oidcService.abortSession(req, res);
  };

  @AsyncHandler
  public mfaInteraction = async (req: Request, res: Response) => {
    const userAgent = getUserAgent(req);
    const ipAddress = getClientIP(req);
    const { code } = req.body;
    const mfaLoginToken = req.cookies.mfaLoginToken;

    if (!mfaLoginToken) {
      throw new AppError('MFA session expired', HTTPSTATUS.UNAUTHORIZED);
    }

    const { user } = await this.mfaService.verifyMFAForLogin({
      code,
      mfaLoginToken,
      userAgent,
      ipAddress,
    });

    await this.oidcService.submitLogin(req, res, user.id);
  };
}

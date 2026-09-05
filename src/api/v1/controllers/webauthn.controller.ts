import crypto from 'node:crypto';

import { WebAuthnService } from '@api/v1/services/webauthn.service';
import { UnauthorizedException } from '@core/common/utils/app-error';
import { setAuthenticationCookies, setCsrfCookie } from '@core/common/utils/cookie';
import { getClientIP, getUserAgent } from '@core/common/utils/metadata';
import {
  generateAuthOptionsSchema,
  updateAuthenticatorNameSchema,
  verifyAuthenticationSchema,
  verifyRegistrationSchema,
} from '@core/common/validators/webauthn.validator';
import { HTTPSTATUS } from '@core/config/http.config';
import { AsyncHandler } from '@core/decorator/async-handler.decorator';
import type { User } from '@prisma/client';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import type { Request, Response } from 'express';

export class WebAuthnController {
  private webAuthnService: WebAuthnService;

  constructor(webAuthnService: WebAuthnService = new WebAuthnService()) {
    this.webAuthnService = webAuthnService;
  }

  @AsyncHandler
  public generateRegistrationOptions = async (req: Request, res: Response) => {
    const userId = (req.user as User)?.id;
    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    const options = await this.webAuthnService.generateRegistrationOptions({ userId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      data: { options },
    });
  };

  @AsyncHandler
  public verifyRegistration = async (req: Request, res: Response) => {
    const userId = (req.user as User)?.id;
    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    const userAgent = getUserAgent(req);
    const ipAddress = getClientIP(req);
    const body = verifyRegistrationSchema.parse(req.body);

    const result = await this.webAuthnService.verifyRegistration({
      userId,
      response: body.response as unknown as RegistrationResponseJSON,
      name: body.name,
      userAgent,
      ipAddress,
    });

    return res.status(HTTPSTATUS.CREATED).json({
      success: true,
      message: 'Passkey registered successfully',
      data: result,
    });
  };

  @AsyncHandler
  public generateAuthenticationOptions = async (req: Request, res: Response) => {
    const body = generateAuthOptionsSchema.parse(req.body ?? {});

    const options = await this.webAuthnService.generateAuthenticationOptions({
      email: body.email,
    });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      data: { options },
    });
  };

  @AsyncHandler
  public verifyAuthentication = async (req: Request, res: Response) => {
    const userAgent = getUserAgent(req);
    const ipAddress = getClientIP(req);
    const body = verifyAuthenticationSchema.parse(req.body);

    const { user, accessToken, refreshToken } = await this.webAuthnService.verifyAuthentication({
      response: body.response as unknown as AuthenticationResponseJSON,
      userAgent,
      ipAddress,
    });

    const csrfToken = crypto.randomUUID();
    setAuthenticationCookies({ res, refreshToken });
    setCsrfCookie({ res, csrfToken });
    res.setHeader('Cache-Control', 'no-store');

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'User signed in successfully via passkey',
      data: { user, accessToken },
    });
  };

  @AsyncHandler
  public verifyAuthenticationForMfa = async (req: Request, res: Response) => {
    const userAgent = getUserAgent(req);
    const ipAddress = getClientIP(req);
    const mfaLoginToken = req.cookies.mfaLoginToken;

    if (!mfaLoginToken) {
      throw new UnauthorizedException('MFA session expired');
    }

    const body = verifyAuthenticationSchema.parse(req.body);

    const { user, accessToken, refreshToken } =
      await this.webAuthnService.verifyAuthenticationForMfa({
        response: body.response as unknown as AuthenticationResponseJSON,
        mfaLoginToken,
        userAgent,
        ipAddress,
      });

    const csrfToken = crypto.randomUUID();
    setAuthenticationCookies({ res, refreshToken });
    setCsrfCookie({ res, csrfToken });
    res.setHeader('Cache-Control', 'no-store');

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'MFA verified successfully via passkey',
      data: { user, accessToken },
    });
  };

  @AsyncHandler
  public listAuthenticators = async (req: Request, res: Response) => {
    const userId = (req.user as User)?.id;
    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    const authenticators = await this.webAuthnService.listAuthenticators({ userId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      data: { authenticators },
    });
  };

  @AsyncHandler
  public deleteAuthenticator = async (req: Request, res: Response) => {
    const userId = (req.user as User)?.id;
    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    const authenticatorId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    await this.webAuthnService.deleteAuthenticator({ userId, authenticatorId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Passkey deleted successfully',
    });
  };

  @AsyncHandler
  public updateAuthenticatorName = async (req: Request, res: Response) => {
    const userId = (req.user as User)?.id;
    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    const authenticatorId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const body = updateAuthenticatorNameSchema.parse(req.body);

    const authenticator = await this.webAuthnService.updateAuthenticatorName({
      userId,
      authenticatorId,
      name: body.name,
    });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Passkey name updated successfully',
      data: { authenticator },
    });
  };
}

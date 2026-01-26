import { clearMfaLoginCookie, setAuthenticationCookies } from '@core/common/utils/cookie';
import { getClientIP, getUserAgent } from '@core/common/utils/metadata';
import { verifyMfaForLoginSchema, verifyMfaSchema } from '@core/common/validators/mfa.validator';
import { HTTPSTATUS } from '@core/config/http.config';
import { AsyncHandler } from '@core/decorator/async-handler.decorator';
import { User } from '@prisma/client';
import { Request, Response } from 'express';

import { MfaService } from '../services/mfa.service';

export class MfaController {
  private mfaService: MfaService;

  constructor(mfaService: MfaService) {
    this.mfaService = mfaService;
  }

  @AsyncHandler
  public generateMFASetup = async (req: Request, res: Response) => {
    const userId = (req.user as User).id;

    const { qrImageUrl } = await this.mfaService.generateMFASetup({ userId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Scan the QR code or use the setup key.',
      data: {
        qrImageUrl,
      },
    });
  };

  @AsyncHandler
  public verifyMFASetup = async (req: Request, res: Response) => {
    const userId = (req.user as User).id;
    const { code } = verifyMfaSchema.parse({
      ...req.body,
    });

    const { backupCodes } = await this.mfaService.verifyMFASetup({ userId, code });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'MFA setup completed successfully',
      data: {
        backupCodes,
      },
    });
  };

  @AsyncHandler
  public revokeMFA = async (req: Request, res: Response) => {
    const userId = (req.user as User).id;

    await this.mfaService.revokeMFA({ userId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'MFA revoked successfully',
    });
  };

  @AsyncHandler
  public verifyMFAForLogin = async (req: Request, res: Response) => {
    const userAgent = getUserAgent(req);
    const ipAddress = getClientIP(req);

    const { code, mfaLoginToken } = verifyMfaForLoginSchema.parse({
      ...req.body,
    });

    const { accessToken, refreshToken, user } = await this.mfaService.verifyMFAForLogin({
      code,
      userAgent,
      ipAddress,
      mfaLoginToken,
    });

    clearMfaLoginCookie(res);

    return setAuthenticationCookies({
      res,
      accessToken,
      refreshToken,
    })
      .status(HTTPSTATUS.OK)
      .json({
        message: 'Verified & login successfully',
        data: { user },
      });
  };
}

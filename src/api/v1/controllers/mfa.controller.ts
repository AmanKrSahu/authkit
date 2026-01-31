import { UnauthorizedException } from '@core/common/utils/app-error';
import {
  clearMfaLoginCookie,
  setAuthenticationCookies,
  setCsrfCookie,
} from '@core/common/utils/cookie';
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

  /**
   * @openapi
   * /mfa/setup:
   *   post:
   *     tags:
   *       - Multi-factor Authentication
   *     summary: Generate MFA setup
   *     description: Generates a QR code for setting up Multi-Factor Authentication.
   *     responses:
   *       200:
   *         description: MFA setup generated successfully
   *       401:
   *         description: User not authenticated
   *       500:
   *         description: Internal server error
   */
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

  /**
   * @openapi
   * /mfa/verify-setup:
   *   post:
   *     tags:
   *       - Multi-factor Authentication
   *     summary: Verify MFA setup
   *     description: Verifies the MFA setup using a code and returns backup codes.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - code
   *             properties:
   *               code:
   *                 type: string
   *     responses:
   *       200:
   *         description: MFA setup verified successfully
   *       400:
   *         description: Invalid code
   *       401:
   *         description: User not authenticated
   *       500:
   *         description: Internal server error
   */
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

  /**
   * @openapi
   * /mfa/revoke:
   *   post:
   *     tags:
   *       - Multi-factor Authentication
   *     summary: Revoke MFA
   *     description: Revokes the MFA setup for the user.
   *     responses:
   *       200:
   *         description: MFA revoked successfully
   *       401:
   *         description: User not authenticated
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public revokeMFA = async (req: Request, res: Response) => {
    const userId = (req.user as User).id;

    await this.mfaService.revokeMFA({ userId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'MFA revoked successfully',
    });
  };

  /**
   * @openapi
   * /mfa/verify-login:
   *   post:
   *     tags:
   *       - Multi-factor Authentication
   *     summary: Verify MFA for login
   *     description: Verifies MFA code during login process.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - code
   *             properties:
   *               code:
   *                 type: string
   *     responses:
   *       200:
   *         description: Login completed successfully
   *       401:
   *         description: Invalid code or token or User not authenticated
   *       403:
   *         description: MFA token expired
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public verifyMFAForLogin = async (req: Request, res: Response) => {
    const userAgent = getUserAgent(req);
    const ipAddress = getClientIP(req);

    const mfaLoginToken = req.cookies.mfaLoginToken;

    if (!mfaLoginToken) {
      throw new UnauthorizedException('Missing MFA login token');
    }

    const { code } = verifyMfaForLoginSchema.parse({
      ...req.body,
    });

    const { accessToken, refreshToken, user } = await this.mfaService.verifyMFAForLogin({
      code,
      userAgent,
      ipAddress,
      mfaLoginToken,
    });

    // Generate random CSRF token
    const csrfToken = crypto.randomUUID();

    clearMfaLoginCookie(res);

    setAuthenticationCookies({
      res,
      refreshToken,
    });
    setCsrfCookie({ res, csrfToken });

    // Set No-Store Header
    res.setHeader('Cache-Control', 'no-store');

    return res.status(HTTPSTATUS.OK).json({
      message: 'Verified & login successfully',
      data: { user, accessToken },
    });
  };
}

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

  constructor(magicLinkService: MagicLinkService) {
    this.magicLinkService = magicLinkService;
  }

  /**
   * @openapi
   * /magic-link/login:
   *   post:
   *     tags:
   *       - Magic Link
   *     summary: Login with Magic Link
   *     description: Sends a magic link to the user's email address.
   *     security: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - email
   *             properties:
   *               email:
   *                 type: string
   *                 format: email
   *     responses:
   *       200:
   *         description: Magic link sent successfully
   *       400:
   *         description: Invalid input data
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public login = async (req: Request, res: Response) => {
    const body = loginMagicLinkSchema.parse({ ...req.body });

    await this.magicLinkService.login(body);

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'If an account exists with this email, a magic link has been sent.',
    });
  };

  /**
   * @openapi
   * /magic-link/verify:
   *   post:
   *     tags:
   *       - Magic Link
   *     summary: Verify Magic Link
   *     description: Verifies the magic link token and authenticates the user.
   *     security: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - token
   *             properties:
   *               token:
   *                 type: string
   *     responses:
   *       200:
   *         description: Login successful
   *       400:
   *         description: Invalid or expired token
   *       404:
   *         description: User not found
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public verify = async (req: Request, res: Response) => {
    const userAgent = getUserAgent(req);
    const ipAddress = getClientIP(req);

    const body = verifyMagicLinkSchema.parse({ ...req.body });

    const { user, mfaRequired, accessToken, refreshToken, mfaLoginToken } =
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
      });
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

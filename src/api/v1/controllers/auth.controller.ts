import { AppError, NotFoundException, UnauthorizedException } from '@core/common/utils/app-error';
import {
  clearAuthenticationCookies,
  clearCsrfCookie,
  clearResetTokenCookie,
  setAuthenticationCookies,
  setCsrfCookie,
  setMfaLoginCookie,
  setResetTokenCookie,
} from '@core/common/utils/cookie';
import { getClientIP, getUserAgent } from '@core/common/utils/metadata';
import {
  changePasswordSchema,
  forgotPasswordSchema,
  loginSchema,
  registerSchema,
  resendVerificationSchema,
  resetPasswordSchema,
  verifyEmailSchema,
  verifyOtpSchema,
} from '@core/common/validators/auth.validator';
import { HTTPSTATUS } from '@core/config/http.config';
import { AsyncHandler } from '@core/decorator/async-handler.decorator';
import { User } from '@prisma/client';
import type { Request, Response } from 'express';

import { AuthService } from '../services/auth.service';

export class AuthController {
  private authService: AuthService;

  constructor(authService: AuthService) {
    this.authService = authService;
  }

  /**
   * @openapi
   * /auth/register:
   *   post:
   *     tags:
   *       - Auth
   *     summary: Register a new user
   *     description: Creates a new user account and sends a verification email.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - name
   *               - email
   *               - password
   *               - confirmPassword
   *             properties:
   *               name:
   *                 type: string
   *               email:
   *                 type: string
   *                 format: email
   *               password:
   *                 type: string
   *                 format: password
   *               confirmPassword:
   *                 type: string
   *                 format: password
   *     responses:
   *       201:
   *         description: User registered successfully
   *       400:
   *         description: Bad request - Invalid input data
   *       409:
   *         description: Conflict - Email already exists
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public register = async (req: Request, res: Response) => {
    const body = registerSchema.parse({
      ...req.body,
    });

    const { user } = await this.authService.register(body);

    return res.status(HTTPSTATUS.CREATED).json({
      success: true,
      message: 'User registered successfully. Please check your email to verify your account.',
      data: { user },
    });
  };

  /**
   * @openapi
   * /auth/verify-email:
   *   post:
   *     tags:
   *       - Auth
   *     summary: Verify email address
   *     description: Verifies the user's email address using a code.
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
   *       201:
   *         description: Email verified successfully
   *       400:
   *         description: Invalid or missing token
   *       404:
   *         description: User not found or already verified
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public verifyEmail = async (req: Request, res: Response) => {
    const body = verifyEmailSchema.parse({ ...req.body });

    await this.authService.verifyEmail(body);

    return res.status(HTTPSTATUS.CREATED).json({
      success: true,
      message: 'Email verified successfully',
    });
  };

  /**
   * @openapi
   * /auth/resend-verification:
   *   post:
   *     tags:
   *       - Auth
   *     summary: Resend verification email
   *     description: Resends the verification email to the user's email address.
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
   *       201:
   *         description: Verification email sent successfully
   *       400:
   *         description: Invalid email address
   *       404:
   *         description: User not found
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public resendVerification = async (req: Request, res: Response) => {
    const body = resendVerificationSchema.parse({ ...req.body });

    await this.authService.resendVerification(body);

    return res.status(HTTPSTATUS.CREATED).json({
      success: true,
      message: 'Verification email sent successfully',
    });
  };

  /**
   * @openapi
   * /auth/login:
   *   post:
   *     tags:
   *       - Auth
   *     summary: Login user
   *     description: Authenticates a user and returns access/refresh tokens.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - email
   *               - password
   *             properties:
   *               email:
   *                 type: string
   *                 format: email
   *               password:
   *                 type: string
   *                 format: password
   *     responses:
   *       200:
   *         description: Login successful
   *       401:
   *         description: Invalid credentials
   *       403:
   *         description: Account not verified
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public login = async (req: Request, res: Response) => {
    const userAgent = getUserAgent(req);
    const ipAddress = getClientIP(req);

    const body = loginSchema.parse({
      ...req.body,
    });

    const { user, mfaRequired, accessToken, refreshToken, mfaLoginToken } =
      await this.authService.login({
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

    // Generate random CSRF token
    const csrfToken = crypto.randomUUID();

    // Set Cookies
    setAuthenticationCookies({ res, refreshToken });
    setCsrfCookie({ res, csrfToken });

    // Set No-Store Header
    res.setHeader('Cache-Control', 'no-store');

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'User signed in successfully',
      data: { user, accessToken },
    });
  };

  /**
   * @openapi
   * /auth/logout:
   *   post:
   *     tags:
   *       - Auth
   *     summary: Logout user
   *     description: Logs out the authenticated user and clears session.
   *     responses:
   *       200:
   *         description: Logged out successfully
   *       401:
   *         description: User not authenticated
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public logout = async (req: Request, res: Response) => {
    const sessionId = req.sessionId;

    if (!sessionId) {
      throw new NotFoundException('Session is invalid.');
    }

    await this.authService.logout({ sessionId });

    clearAuthenticationCookies(res);
    clearCsrfCookie(res);

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Logged out successfully',
    });
  };

  /**
   * @openapi
   * /auth/refresh-token:
   *   post:
   *     tags:
   *       - Auth
   *     summary: Refresh access token
   *     description: Generates a new access token using a refresh token.
   *     responses:
   *       200:
   *         description: Token refreshed successfully
   *       401:
   *         description: Invalid or missing refresh token
   *       403:
   *         description: Refresh token expired or reused
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public refreshAccessToken = async (req: Request, res: Response) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      throw new UnauthorizedException('Missing refresh token');
    }

    const { newAccessToken, newRefreshToken } = await this.authService.refreshAccessToken({
      refreshToken,
    });

    // Rotate CSRF Token
    const csrfToken = crypto.randomUUID();

    setAuthenticationCookies({ res, refreshToken: newRefreshToken });
    setCsrfCookie({ res, csrfToken });

    res.setHeader('Cache-Control', 'no-store');

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Token refreshed successfully',
      data: { accessToken: newAccessToken },
    });
  };

  /**
   * @openapi
   * /auth/forgot-password:
   *   post:
   *     tags:
   *       - Auth
   *     summary: Forgot password
   *     description: Sends a password reset OTP to the user's email.
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
   *         description: OTP sent successfully
   *       400:
   *         description: Invalid email or user not found
   *       429:
   *         description: Too many requests
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public forgotPassword = async (req: Request, res: Response) => {
    const ipAddress = getClientIP(req);

    const body = forgotPasswordSchema.parse({ ...req.body });

    await this.authService.forgotPassword({ ...body, ipAddress });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'OTP sent to your email for password reset',
    });
  };

  /**
   * @openapi
   * /auth/verify-otp:
   *   post:
   *     tags:
   *       - Auth
   *     summary: Verify OTP
   *     description: Verifies the OTP sent to the user's email.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - email
   *               - otp
   *             properties:
   *               email:
   *                 type: string
   *                 format: email
   *               otp:
   *                 type: string
   *     responses:
   *       200:
   *         description: OTP verified successfully
   *       400:
   *         description: Invalid OTP or email
   *       410:
   *         description: OTP expired
   *       500:
   *         description: Internal server error
   */

  @AsyncHandler
  public verifyOtp = async (req: Request, res: Response) => {
    const body = verifyOtpSchema.parse({ ...req.body });

    const { resetToken } = await this.authService.verifyOtp(body);

    const csrfToken = crypto.randomUUID();
    setCsrfCookie({ res, csrfToken });

    return setResetTokenCookie({
      res,
      resetToken,
    })
      .status(HTTPSTATUS.OK)
      .json({
        success: true,
        message: 'OTP verified successfully',
      });
  };

  /**
   * @openapi
   * /auth/reset-password:
   *   post:
   *     tags:
   *       - Auth
   *     summary: Reset password
   *     description: Resets the user's password using the verified token.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - email
   *               - password
   *               - confirmPassword
   *             properties:
   *               email:
   *                 type: string
   *                 format: email
   *               password:
   *                 type: string
   *                 format: password
   *               confirmPassword:
   *                 type: string
   *                 format: password
   *     responses:
   *       200:
   *         description: Password reset successfully
   *       400:
   *         description: Passwords do not match or invalid input
   *       401:
   *         description: Invalid or expired reset token
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public resetPassword = async (req: Request, res: Response) => {
    const resetToken = req.cookies.resetToken;

    if (!resetToken) {
      throw new UnauthorizedException('Missing reset token');
    }

    const body = resetPasswordSchema.parse({ ...req.body });

    await this.authService.resetPassword({ ...body, resetToken });

    return clearResetTokenCookie(res).status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Password reset successfully',
    });
  };

  /**
   * @openapi
   * /auth/change-password:
   *   post:
   *     tags:
   *       - Auth
   *     summary: Change password
   *     description: Changes the user's password.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - currentPassword
   *               - newPassword
   *             properties:
   *               currentPassword:
   *                 type: string
   *                 format: password
   *               newPassword:
   *                 type: string
   *                 format: password
   *     responses:
   *       200:
   *         description: Password changed successfully
   *       400:
   *         description: Invalid current password
   *       401:
   *         description: User not authenticated
   *       500:
   *         description: Internal server error
   */

  @AsyncHandler
  public changePassword = async (req: Request, res: Response) => {
    const userId = (req.user as User)?.id;

    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    const body = changePasswordSchema.parse({ ...req.body });

    await this.authService.changePassword({ userId, ...body });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Password changed successfully',
    });
  };
}

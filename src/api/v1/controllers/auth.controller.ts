import { AppError, NotFoundException, UnauthorizedException } from '@core/common/utils/app-error';
import {
  clearAuthenticationCookies,
  clearResetTokenCookie,
  setAuthenticationCookies,
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

  @AsyncHandler
  public verifyEmail = async (req: Request, res: Response) => {
    const body = verifyEmailSchema.parse({ ...req.body });

    await this.authService.verifyEmail(body);

    return res.status(HTTPSTATUS.CREATED).json({
      success: true,
      message: 'Email verified successfully',
    });
  };

  @AsyncHandler
  public resendVerification = async (req: Request, res: Response) => {
    const body = resendVerificationSchema.parse({ ...req.body });

    await this.authService.resendVerification(body);

    return res.status(HTTPSTATUS.CREATED).json({
      success: true,
      message: 'Verification email sent successfully',
    });
  };

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

    return setAuthenticationCookies({
      res,
      accessToken,
      refreshToken,
    })
      .status(HTTPSTATUS.OK)
      .json({
        success: true,
        message: 'User signed in successfully',
        data: { user },
      });
  };

  @AsyncHandler
  public logout = async (req: Request, res: Response) => {
    const sessionId = req.sessionId;

    if (!sessionId) {
      throw new NotFoundException('Session is invalid.');
    }

    await this.authService.logout({ sessionId });

    return clearAuthenticationCookies(res).status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Logged out successfully',
    });
  };

  @AsyncHandler
  public refreshAccessToken = async (req: Request, res: Response) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      throw new UnauthorizedException('Missing refresh token');
    }

    const { newAccessToken, newRefreshToken } = await this.authService.refreshAccessToken({
      refreshToken,
    });

    return setAuthenticationCookies({
      res,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    })
      .status(HTTPSTATUS.OK)
      .json({
        success: true,
        message: 'Token refreshed successfully',
      });
  };

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

  @AsyncHandler
  public verifyOtp = async (req: Request, res: Response) => {
    const body = verifyOtpSchema.parse({ ...req.body });

    const { resetToken } = await this.authService.verifyOtp(body);

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

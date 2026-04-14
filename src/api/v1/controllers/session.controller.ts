import { AppError, UnauthorizedException } from '@core/common/utils/app-error';
import { HTTPSTATUS } from '@core/config/http.config';
import { AsyncHandler } from '@core/decorator/async-handler.decorator';
import { User } from '@prisma/client';
import type { Request, Response } from 'express';

import { SessionService } from '../services/session.service';

export class SessionController {
  private sessionService: SessionService;

  constructor(sessionService: SessionService) {
    this.sessionService = sessionService;
  }

  @AsyncHandler
  public getSessions = async (req: Request, res: Response) => {
    const userId = (req.user as User)?.id;
    const currentSessionId = req.sessionId;

    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    const sessions = await this.sessionService.getSessions({ userId });

    const modifiedSessions = sessions.map(session => ({
      ...session,
      isCurrent: session.id === currentSessionId,
      token: undefined,
    }));

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Sessions retrieved successfully',
      data: { session: modifiedSessions },
    });
  };

  @AsyncHandler
  public getSessionById = async (req: Request, res: Response) => {
    const sessionId = req.params.sessionId as string;
    const userId = (req.user as User)?.id;

    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    if (!sessionId) {
      throw new AppError('Session ID is required', HTTPSTATUS.BAD_REQUEST);
    }

    const session = await this.sessionService.getSessionById({ sessionId, userId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Session retrieved successfully',
      data: {
        session: {
          ...session,
          token: undefined,
          isCurrent: session.id === req.sessionId,
        },
      },
    });
  };

  @AsyncHandler
  public revokeSessions = async (req: Request, res: Response) => {
    const userId = (req.user as User)?.id;
    const currentSessionId = req.sessionId;

    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    await this.sessionService.revokeSessions({ userId, currentSessionId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'All other sessions revoked successfully',
    });
  };

  @AsyncHandler
  public revokeSessionById = async (req: Request, res: Response) => {
    const userId = (req.user as User)?.id;
    const sessionId = req.params.sessionId as string;
    const currentSessionId = req.sessionId;

    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    if (!sessionId) {
      throw new AppError('Session ID is required', HTTPSTATUS.BAD_REQUEST);
    }

    if (sessionId === currentSessionId) {
      throw new AppError(
        'Cannot revoke current session. Use logout instead.',
        HTTPSTATUS.BAD_REQUEST
      );
    }

    await this.sessionService.revokeSessionById({ userId, sessionId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Session revoked successfully',
    });
  };
}

import { UnauthorizedException } from '@core/common/utils/app-error';
import { HTTPSTATUS } from '@core/config/http.config';
import { AsyncHandler } from '@core/decorator/async-handler.decorator';
import { User } from '@prisma/client';
import type { Request, Response } from 'express';

import { UserService } from '../services/user.service';

export class UserController {
  private userService: UserService;

  constructor(userService: UserService) {
    this.userService = userService;
  }

  @AsyncHandler
  public currentUser = async (req: Request, res: Response) => {
    const userId = (req.user as User)?.id;

    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    const user = await this.userService.currentUser({ userId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'User retrieved successfully',
      data: { user: user },
    });
  };
}

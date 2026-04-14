import {
  createOidcClientSchema,
  deleteUserSchema,
  getUserByIdSchema,
  getUserSessionsSchema,
  promoteUserSchema,
  revokeSessionByIdSchema,
  revokeSessionsByUserIdSchema,
} from '@core/common/validators/admin.validator';
import { HTTPSTATUS } from '@core/config/http.config';
import { AsyncHandler } from '@core/decorator/async-handler.decorator';
import type { Request, Response } from 'express';

import { AdminService } from '../services/admin.service';

export class AdminController {
  private adminService: AdminService;

  constructor(adminService: AdminService) {
    this.adminService = adminService;
  }

  @AsyncHandler
  public promoteUserToAdmin = async (req: Request, res: Response) => {
    const body = promoteUserSchema.parse({ ...req.body });

    const user = await this.adminService.promoteUserToAdmin(body);

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'User promoted to Admin successfully',
      data: { user },
    });
  };

  @AsyncHandler
  public deleteUser = async (req: Request, res: Response) => {
    const { userId } = deleteUserSchema.parse({ ...req.params });

    await this.adminService.deleteUser({ userId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'User deleted successfully',
    });
  };

  @AsyncHandler
  public revokeSessionById = async (req: Request, res: Response) => {
    const { sessionId } = revokeSessionByIdSchema.parse({ ...req.params });

    await this.adminService.revokeSessionById({ sessionId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Session revoked successfully',
    });
  };

  @AsyncHandler
  public revokeSessionsByUserId = async (req: Request, res: Response) => {
    const { userId } = revokeSessionsByUserIdSchema.parse({ ...req.params });

    await this.adminService.revokeSessionsByUserId({ userId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'User sessions revoked successfully',
    });
  };

  @AsyncHandler
  public registerOidcClient = async (req: Request, res: Response) => {
    const body = createOidcClientSchema.parse({ ...req.body });

    const client = await this.adminService.createOidcClient(body);

    return res.status(HTTPSTATUS.CREATED).json({
      success: true,
      message: 'OIDC Client registered successfully',
      data: { client },
    });
  };

  @AsyncHandler
  public getAllUsers = async (_req: Request, res: Response) => {
    const users = await this.adminService.getAllUsers();

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Users retrieved successfully',
      data: { users },
    });
  };

  @AsyncHandler
  public getUserById = async (req: Request, res: Response) => {
    const { userId } = getUserByIdSchema.parse({ ...req.params });

    const user = await this.adminService.getUserById({ userId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'User retrieved successfully',
      data: { user },
    });
  };

  @AsyncHandler
  public getUserSessions = async (req: Request, res: Response) => {
    const { userId } = getUserSessionsSchema.parse({ ...req.params });

    const sessions = await this.adminService.getUserSessions({ userId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'User sessions retrieved successfully',
      data: { sessions },
    });
  };
}

import {
  deleteUserSchema,
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

  /**
   * @openapi
   * /admin/users/promote:
   *   post:
   *     tags:
   *       - Admin
   *     summary: Promote a user to Admin
   *     description: Promotes an existing user to the ADMIN role.
   *     security:
   *       - bearerAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - userId
   *             properties:
   *               userId:
   *                 type: string
   *     responses:
   *       200:
   *         description: User promoted successfully
   *       400:
   *         description: Invalid input or user not found
   *       403:
   *         description: Forbidden (Non-admin access)
   *       500:
   *         description: Internal server error
   */
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

  /**
   * @openapi
   * /admin/users/{userId}:
   *   delete:
   *     tags:
   *       - Admin
   *     summary: Delete a user
   *     description: Deletes a user account and all associated data.
   *     security:
   *       - bearerAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - userId
   *             properties:
   *               userId:
   *                 type: string
   *     responses:
   *       200:
   *         description: User deleted successfully
   *       400:
   *         description: Invalid User ID
   *       403:
   *         description: Forbidden
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public deleteUser = async (req: Request, res: Response) => {
    const { userId } = deleteUserSchema.parse({ ...req.body });

    await this.adminService.deleteUser({ userId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'User deleted successfully',
    });
  };

  /**
   * @openapi
   * /admin/sessions/{sessionId}:
   *   delete:
   *     tags:
   *       - Admin
   *     summary: Revoke session by ID
   *     description: Revokes a specific session.
   *     security:
   *       - bearerAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - sessionId
   *             properties:
   *               sessionId:
   *                 type: string
   *     responses:
   *       200:
   *         description: Session revoked successfully
   *       400:
   *         description: Invalid Session ID
   *       403:
   *         description: Forbidden
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public revokeSessionById = async (req: Request, res: Response) => {
    const { sessionId } = revokeSessionByIdSchema.parse({ ...req.body });

    await this.adminService.revokeSessionById({ sessionId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Session revoked successfully',
    });
  };

  /**
   * @openapi
   * /admin/sessions/user/{userId}:
   *   delete:
   *     tags:
   *       - Admin
   *     summary: Revoke all sessions for a user
   *     description: Revokes all active sessions for a specific user.
   *     security:
   *       - bearerAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - userId
   *             properties:
   *               userId:
   *                 type: string
   *     responses:
   *       200:
   *         description: User sessions revoked successfully
   *       400:
   *         description: Invalid User ID
   *       403:
   *         description: Forbidden
   *       500:
   *         description: Internal server error
   */
  @AsyncHandler
  public revokeSessionsByUserId = async (req: Request, res: Response) => {
    const { userId } = revokeSessionsByUserIdSchema.parse({ ...req.body });

    await this.adminService.revokeSessionsByUserId({ userId });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'User sessions revoked successfully',
    });
  };
}

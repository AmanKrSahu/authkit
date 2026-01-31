import { HTTPSTATUS } from '@core/config/http.config';
import { AsyncHandler } from '@core/decorator/async-handler.decorator';
import type { Request, Response } from 'express';

import type { HealthService } from '../services/health.service';

export class HealthController {
  private healthService: HealthService;

  constructor(healthService: HealthService) {
    this.healthService = healthService;
  }

  /**
   * @openapi
   * /:
   *   get:
   *     tags:
   *       - Health
   *     summary: Check system status
   *     description: Returns a simple message indicating the server is running.
   *     security: []
   *     responses:
   *       200:
   *         description: Server started successfully
   *       500:
   *         description: Internal server error
   *       503:
   *         description: Service unavailable
   */
  @AsyncHandler
  public initialise = async (_req: Request, res: Response) => {
    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Server started successfully',
      timestamp: new Date().toISOString(),
    });
  };

  /**
   * @openapi
   * /health:
   *   get:
   *     tags:
   *       - Health
   *     summary: Basic health check
   *     description: Checks the basic health of the application services.
   *     security: []
   *     responses:
   *       200:
   *         description: Server is healthy
   *       500:
   *         description: Internal server error
   *       503:
   *         description: Service unavailable
   */
  @AsyncHandler
  public health = async (_req: Request, res: Response) => {
    const healthData = await this.healthService.getBasicHealth();

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Server is healthy',
      data: { health: healthData },
    });
  };

  /**
   * @openapi
   * /health/detailed:
   *   get:
   *     tags:
   *       - Health
   *     summary: Detailed health check
   *     description: Provides a detailed health report including external dependencies.
   *     security: []
   *     responses:
   *       200:
   *         description: Detailed health check completed
   *       500:
   *         description: Internal server error
   *       503:
   *         description: Service unavailable
   */
  @AsyncHandler
  public detailedHealth = async (_req: Request, res: Response) => {
    const detailedHealthData = await this.healthService.getDetailedHealth();

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Detailed health check completed',
      data: { health: detailedHealthData },
    });
  };
}

import { HTTPSTATUS } from '@core/config/http.config';
import { AsyncHandler } from '@core/decorator/async-handler.decorator';
import type { Request, Response } from 'express';

import type { HealthService } from '../services/health.service';

export class HealthController {
  private healthService: HealthService;

  constructor(healthService: HealthService) {
    this.healthService = healthService;
  }

  @AsyncHandler
  public initialise = async (_req: Request, res: Response) => {
    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Server started successfully',
      timestamp: new Date().toISOString(),
    });
  };

  @AsyncHandler
  public health = async (_req: Request, res: Response) => {
    const healthData = await this.healthService.getBasicHealth();

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Server is healthy',
      data: { health: healthData },
    });
  };

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

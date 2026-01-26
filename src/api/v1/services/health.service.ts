import type { DetailedHealthData, HealthData } from '@core/common/interface/health.interface';
import { getAppVersion } from '@core/common/utils/metadata';

export class HealthService {
  public async getBasicHealth(): Promise<HealthData> {
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: await getAppVersion(),
    };
  }

  public async getDetailedHealth(): Promise<DetailedHealthData> {
    const memoryUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: await getAppVersion(),
      environment: process.env.NODE_ENV ?? 'development',
      memory: {
        used: memoryUsage.heapUsed,
        total: memoryUsage.heapTotal,
        percentage: Math.round((memoryUsage.heapUsed / memoryUsage.heapTotal) * 100 * 100) / 100,
        external: memoryUsage.external,
        arrayBuffers: memoryUsage.arrayBuffers,
      },
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      cpuUsage,
    };
  }
}

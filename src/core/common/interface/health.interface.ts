export interface HealthData {
  status: string;
  timestamp: string;
  uptime: number;
  version: string;
}

export interface DetailedHealthData extends HealthData {
  environment: string;
  memory: {
    used: number;
    total: number;
    percentage: number;
    external: number;
    arrayBuffers: number;
  };
  nodeVersion: string;
  platform: string;
  arch: string;
  cpuUsage: NodeJS.CpuUsage;
}

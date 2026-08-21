/**
 * Unit tests for HealthService.
 * Target: HealthService (system status endpoints)
 */
import { describe, expect, it } from 'vitest';
import { HealthService } from '@api/v1/services/health.service';

describe('HealthService Unit Tests', () => {
  const healthService = new HealthService();

  describe('getBasicHealth', () => {
    it('should return basic health status data', async () => {
      // Given: A request for basic system health
      // When: Querying basic health status
      const result = await healthService.getBasicHealth();

      // Then: A valid payload with 'healthy' status and version details should be returned
      expect(result.status).toBe('healthy');
      expect(result.version).toBeDefined();
      expect(result.timestamp).toBeDefined();
      expect(result.uptime).toBeGreaterThan(0);
    });
  });

  describe('getDetailedHealth', () => {
    it('should return detailed system diagnostic statistics', async () => {
      // Given: A request for detailed system health
      // When: Querying detailed metrics
      const result = await healthService.getDetailedHealth();

      // Then: Comprehensive system details (memory, CPU, platform) should be returned
      expect(result.status).toBe('healthy');
      expect(result.environment).toBeDefined();
      expect(result.memory).toBeDefined();
      expect(result.memory.used).toBeGreaterThan(0);
      expect(result.nodeVersion).toBeDefined();
      expect(result.platform).toBe(process.platform);
    });
  });
});

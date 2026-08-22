/**
 * Mock implementation of AuditService for unit and integration tests.
 * Prevents real DB writes for audit logs and provides spyable mocks.
 */
import { vi } from 'vitest';

export class MockAuditService {
  public log = vi.fn().mockResolvedValue({ id: 'mock-audit-id' });
  public getAuditLogs = vi.fn().mockResolvedValue({
    logs: [],
    meta: {
      total: 0,
      limit: 10,
      hasNextPage: false,
      hasPreviousPage: false,
      nextCursor: null,
    },
  });
  public getAuditLogById = vi.fn().mockResolvedValue(null);
}

import { AuditAction, AuditStatus } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import { AuditService } from '../../src/api/v1/services/audit.service';

describe('AuditService Unit Tests', () => {
  const auditService = new AuditService();

  it('should recursively sanitize sensitive keys in metadata', () => {
    const rawMetadata = {
      username: 'john_doe',
      password: 'SuperSecretPassword123!',
      nested: {
        accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        apiKey: 'secret_key_123',
        publicVal: 'allowed',
      },
      backupCodes: ['1234-5678', '9012-3456'],
    };

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const clean: any = auditService.sanitizeMetadata(rawMetadata);

    expect(clean.username).toBe('john_doe');
    expect(clean.password).toBe('[REDACTED]');
    expect(clean.nested.accessToken).toBe('[REDACTED]');
    expect(clean.nested.apiKey).toBe('[REDACTED]');
    expect(clean.nested.publicVal).toBe('allowed');
    expect(clean.backupCodes).toBe('[REDACTED]');
  });

  it('should log audit events and query paginated audit logs', async () => {
    await auditService.log({
      userId: 'user_123',
      action: AuditAction.LOGIN,
      entityType: 'User',
      entityId: 'user_123',
      description: 'User logged in successfully',
      status: AuditStatus.SUCCESS,
      ipAddress: '127.0.0.1',
      userAgent: 'Mozilla/5.0',
    });

    const { auditLogs, pagination } = await auditService.getAuditLogs({
      userId: 'user_123',
      limit: 10,
    });

    expect(auditLogs).toHaveLength(1);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const firstLog: any = auditLogs[0];
    expect(firstLog.action).toBe(AuditAction.LOGIN);
    expect(firstLog.userId).toBe('user_123');
    expect(pagination.totalCount).toBeGreaterThanOrEqual(1);

    const logDetail: any = await auditService.getAuditLogById(firstLog.id);
    expect(logDetail.id).toBe(firstLog.id);
    expect(logDetail.description).toBe('User logged in successfully');
  });

  it('should filter audit logs by action and status', async () => {
    await auditService.log({
      action: AuditAction.FAILED_LOGIN,
      entityType: 'User',
      description: 'Failed login attempt',
      status: AuditStatus.FAILURE,
    });

    const failedLogs = await auditService.getAuditLogs({
      action: AuditAction.FAILED_LOGIN,
      status: AuditStatus.FAILURE,
    });

    expect(failedLogs.auditLogs.length).toBeGreaterThanOrEqual(1);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const firstFailedLog: any = failedLogs.auditLogs[0];
    expect(firstFailedLog.status).toBe('FAILURE');
  });
});

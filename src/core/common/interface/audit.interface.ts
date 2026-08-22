import type { AuditAction, AuditStatus } from '@prisma/client';

export interface CreateAuditLogData {
  userId?: string | null;
  action: AuditAction;
  entityType: string;
  entityId?: string | null;
  description: string;
  status?: AuditStatus;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown> | null;
}

export interface GetAuditLogsData {
  cursor?: string;
  limit?: number;
  userId?: string;
  action?: AuditAction;
  entityType?: string;
  entityId?: string;
  status?: AuditStatus;
  startDate?: string;
  endDate?: string;
}

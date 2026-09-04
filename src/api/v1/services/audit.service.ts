import type { CreateAuditLogData, GetAuditLogsData } from '@core/common/interface/audit.interface';
import { AppError } from '@core/common/utils/app-error';
import { paginateWithCursor } from '@core/common/utils/pagination';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';
import { eventBus } from '@core/events/event-bus';
import { AUDIT_ACTION_TO_EVENT_MAP } from '@core/events/event-catalog';
import type { AuditLog, Prisma } from '@prisma/client';

const SENSITIVE_KEYS = new Set([
  'password',
  'passwordconfirm',
  'secret',
  'token',
  'accesstoken',
  'refreshtoken',
  'idtoken',
  'twofactorsecret',
  'backupcodes',
  'authorization',
  'apikey',
  'cookie',
]);

export class AuditService {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public sanitizeMetadata(metadata: any): any {
    if (!metadata || typeof metadata !== 'object') {
      return metadata;
    }
    if (Array.isArray(metadata)) {
      return metadata.map(item => this.sanitizeMetadata(item));
    }
    const clean: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(metadata)) {
      if (SENSITIVE_KEYS.has(key.toLowerCase())) {
        clean[key] = '[REDACTED]';
      } else if (val && typeof val === 'object') {
        clean[key] = this.sanitizeMetadata(val);
      } else {
        clean[key] = val;
      }
    }
    return clean;
  }

  public async log(data: CreateAuditLogData): Promise<void> {
    try {
      const sanitizedMetadata = data.metadata
        ? (this.sanitizeMetadata(data.metadata) as Prisma.InputJsonValue)
        : undefined;

      const auditLog = await prisma.auditLog.create({
        data: {
          userId: data.userId ?? null,
          action: data.action,
          entityType: data.entityType,
          entityId: data.entityId ?? null,
          description: data.description,
          status: data.status ?? 'SUCCESS',
          ipAddress: data.ipAddress ?? null,
          userAgent: data.userAgent ?? null,
          metadata: sanitizedMetadata ?? undefined,
        },
      });

      const mappedEventType = AUDIT_ACTION_TO_EVENT_MAP[data.action];
      if (mappedEventType && data.status !== 'FAILURE') {
        eventBus.publish(
          mappedEventType,
          {
            userId: data.userId ?? null,
            entityType: data.entityType,
            entityId: data.entityId ?? null,
            description: data.description,
            metadata: sanitizedMetadata ?? null,
          },
          `evt_${auditLog.id}`
        );
      }
    } catch {
      // Non-blocking log failure; avoid crashing main business transactions
    }
  }

  public async getAuditLogs(params: GetAuditLogsData) {
    try {
      const { cursor, limit, userId, action, entityType, entityId, status, startDate, endDate } =
        params;

      const where: Prisma.AuditLogWhereInput = {};
      if (userId) where.userId = userId;
      if (action) where.action = action;
      if (entityType) where.entityType = entityType;
      if (entityId) where.entityId = entityId;
      if (status) where.status = status;

      if (startDate || endDate) {
        where.createdAt = {};
        if (startDate) where.createdAt.gte = new Date(startDate);
        if (endDate) where.createdAt.lte = new Date(endDate);
      }

      const result = await paginateWithCursor<AuditLog>(
        args =>
          prisma.auditLog.findMany({
            where,
            orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
            ...args,
          }),
        () => prisma.auditLog.count({ where }),
        { cursor, limit }
      );

      const auditLogs = result.data.map(log => ({
        ...log,
        metadata: this.sanitizeMetadata(log.metadata),
      }));

      return {
        auditLogs,
        pagination: result.pagination,
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to fetch audit logs', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async getAuditLogById(id: string) {
    try {
      const auditLog = await prisma.auditLog.findUnique({
        where: { id },
      });

      if (!auditLog) {
        throw new AppError('Audit log entry not found', HTTPSTATUS.NOT_FOUND);
      }

      return {
        ...auditLog,
        metadata: this.sanitizeMetadata(auditLog.metadata),
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to fetch audit log details', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }
}

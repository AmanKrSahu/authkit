/* eslint-disable unicorn/no-useless-undefined */
import { AuditAction, AuditStatus } from '@prisma/client';
import { z } from 'zod';

export const getAuditLogsQuerySchema = z.object({
  cursor: z.string().optional(),
  limit: z
    .string()
    .optional()
    .transform(val => {
      if (!val) return undefined;
      const num = Number.parseInt(val, 10);
      return Number.isNaN(num) ? undefined : num;
    }),
  userId: z.string().optional(),
  action: z.nativeEnum(AuditAction).optional(),
  entityType: z.string().optional(),
  entityId: z.string().optional(),
  status: z.nativeEnum(AuditStatus).optional(),
  startDate: z
    .string()
    .optional()
    .refine(val => !val || !Number.isNaN(Date.parse(val)), {
      message: 'Invalid startDate ISO format',
    }),
  endDate: z
    .string()
    .optional()
    .refine(val => !val || !Number.isNaN(Date.parse(val)), {
      message: 'Invalid endDate ISO format',
    }),
});

export const getAuditLogByIdSchema = z.object({
  id: z.string().min(1, 'Audit log ID is required'),
});

export type GetAuditLogsQueryInput = z.infer<typeof getAuditLogsQuerySchema>;
export type GetAuditLogByIdInput = z.infer<typeof getAuditLogByIdSchema>;

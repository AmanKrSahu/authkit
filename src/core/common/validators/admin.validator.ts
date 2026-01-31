import { z } from 'zod';

export const promoteUserSchema = z.object({
  userId: z.string().min(1, 'User ID is required'),
});

export const deleteUserSchema = z.object({
  userId: z.string().min(1, 'User ID is required'),
});

export const revokeSessionByIdSchema = z.object({
  sessionId: z.string().min(1, 'Session ID is required'),
});

export const revokeSessionsByUserIdSchema = z.object({
  userId: z.string().min(1, 'User ID is required'),
});

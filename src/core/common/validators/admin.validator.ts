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

export const createOidcClientSchema = z.object({
  clientName: z.string().min(1, 'Client name is required'),
  redirectUrls: z
    .array(z.string().url('Invalid redirect URL'))
    .min(1, 'At least one redirect URL is required'),
  grantTypes: z.array(z.string()).optional().default(['authorization_code', 'refresh_token']),
  scope: z.string().optional().default('openid profile email'),
});

export const getUserByIdSchema = z.object({
  userId: z.string().min(1, 'User ID is required'),
});

export const getUserSessionsSchema = z.object({
  userId: z.string().min(1, 'User ID is required'),
});

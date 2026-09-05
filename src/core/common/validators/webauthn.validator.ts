import { z } from 'zod';

export const verifyRegistrationSchema = z.object({
  response: z.record(z.string(), z.unknown()),
  name: z.string().trim().min(1).max(100).optional(),
});

export const generateAuthOptionsSchema = z.object({
  email: z.string().trim().email().optional(),
});

export const verifyAuthenticationSchema = z.object({
  response: z.record(z.string(), z.unknown()),
});

export const updateAuthenticatorNameSchema = z.object({
  name: z.string().trim().min(1, 'Authenticator name is required').max(100),
});

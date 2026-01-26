import { z } from 'zod';

export const verifyMfaSchema = z.object({
  code: z.string().trim().min(1).max(6),
});

export const verifyMfaForLoginSchema = z.object({
  code: z.string().trim().min(1).max(6),
  mfaLoginToken: z.string().trim().min(1),
});

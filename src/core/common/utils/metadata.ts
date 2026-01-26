import { BadRequestException } from '@core/common/utils/app-error';
import prisma from '@core/database/prisma';
import type { Request } from 'express';

import { ONE_HOUR } from './date-time';
import { getCache, incrementCache } from './redis-helpers';

/* ============================================================================
 * Application Metadata Utilities
 * ============================================================================ */

/**
 * Retrieves the current application version from package.json.
 * Falls back to a default version if the file cannot be read.
 */
export const getAppVersion = async (): Promise<string> => {
  try {
    const packageJson = await import('../../../../package.json');
    return packageJson.version ?? '1.0.0';
  } catch {
    return '1.0.0';
  }
};

/* ============================================================================
 * Request Context Utilities
 * ============================================================================ */

/**
 * Extracts the User-Agent string from the incoming HTTP request.
 */
export const getUserAgent = (req: Request): string => {
  return req.headers['user-agent'] ?? 'Unknown';
};

/**
 * Determines the client IP address, accounting for reverse proxies.
 */
export const getClientIP = (req: Request): string => {
  return (
    ((req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.connection?.remoteAddress) ??
    req.socket?.remoteAddress ??
    'Unknown'
  );
};

/* ============================================================================
 * Device & Session Security Utilities
 * ============================================================================ */

/**
 * Checks whether the current login attempt is coming from a new device
 * by matching the device fingerprint against active user sessions.
 */
export const checkForNewDevice = async (
  userId: string,
  deviceFingerprint: string
): Promise<boolean> => {
  const existingSession = await prisma.session.findFirst({
    where: {
      userId,
      deviceFingerprint,
      isRevoked: false,
    },
  });

  return !existingSession;
};

/* ============================================================================
 * Rate Limiting & Abuse Prevention Utilities (Redis)
 * ============================================================================ */

/**
 * Enforces rate limits based on a key derived from email and IP.
 * Uses Redis increment and expiry.
 */
export const checkRateLimit = async (
  email: string,
  ipAddress: string,
  limit: number,
  type: string = 'PASSWORD_RESET'
): Promise<void> => {
  const key = `rate_limit:${type}:${email}:${ipAddress}`;
  const attempts = await incrementCache(key, ONE_HOUR);

  if (attempts > limit) {
    throw new BadRequestException('Too many attempts. Please try again later.');
  }
};

/* ============================================================================
 * MFA Rate Limiting (Redis)
 * ============================================================================ */

/**
 * Checks MFA rate limit using Redis.
 * Returns the current attempt count.
 */
export const checkMfaRateLimit = async (
  email: string,
  ipAddress: string,
  limit: number
): Promise<number> => {
  const key = `mfa_limit:${email}:${ipAddress}`;
  // We just get the value, increment happens separately if failed
  const val = await getCache(key);
  const attempts = val ? Number.parseInt(val, 10) : 0;

  if (attempts >= limit) {
    throw new BadRequestException('Too many MFA attempts. Please try again later.');
  }
  return attempts;
};

/**
 * Increments the MFA attempt counter in Redis.
 */
export const incrementMfaRateLimit = async (email: string, ipAddress: string): Promise<void> => {
  const key = `mfa_limit:${email}:${ipAddress}`;
  await incrementCache(key, ONE_HOUR);
};

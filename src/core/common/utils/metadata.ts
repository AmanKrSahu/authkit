import { BadRequestException } from '@core/common/utils/app-error';
import prisma from '@core/database/prisma';
import type { Request } from 'express';

import { RATE_LIMIT } from '../constants/rate-limit.constant';
import { deleteCache, getCache, incrementCache, setCache } from './redis-helpers';

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
  return req.ip ?? '127.0.0.1';
};

/**
 * Checks if a user is temporarily locked out due to too many failed login attempts.
 */
export const checkLoginLockout = async (email: string): Promise<void> => {
  const normalizedEmail = email.trim().toLowerCase();
  const lockoutKey = `lockout:${normalizedEmail}`;

  const isLocked = await getCache(lockoutKey);
  if (isLocked) {
    throw new BadRequestException(
      'Too many failed login attempts. This account is temporarily locked. Please try again later.'
    );
  }
};

/**
 * Increments the failed login attempts counter and applies a lockout if it exceeds the limit.
 */
export const incrementLoginFailedAttempts = async (email: string): Promise<void> => {
  const normalizedEmail = email.trim().toLowerCase();
  const lockoutKey = `lockout:${normalizedEmail}`;
  const attemptsKey = `failed_attempts:${normalizedEmail}`;

  const attempts = await incrementCache(attemptsKey, RATE_LIMIT.AUTH.WINDOW_MS / 1000);
  if (attempts >= RATE_LIMIT.AUTH.MAX_REQUESTS) {
    await setCache(lockoutKey, 'true', RATE_LIMIT.AUTH.WINDOW_MS / 1000);
    await deleteCache(attemptsKey);
  }
};

/**
 * Clears any active failed login attempts and lockout counters.
 */
export const clearLoginLockout = async (email: string): Promise<void> => {
  const normalizedEmail = email.trim().toLowerCase();
  const lockoutKey = `lockout:${normalizedEmail}`;
  const attemptsKey = `failed_attempts:${normalizedEmail}`;

  await deleteCache(lockoutKey);
  await deleteCache(attemptsKey);
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
  limit: number = RATE_LIMIT.OTP.MAX_REQUESTS,
  type: string = 'OTP_RESEND'
): Promise<void> => {
  const key = `rate_limit:${type}:${email}:${ipAddress}`;
  const attempts = await incrementCache(key, RATE_LIMIT.OTP.WINDOW_MS / 1000);

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
  limit: number = RATE_LIMIT.MFA.MAX_ATTEMPTS
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
  await incrementCache(key, RATE_LIMIT.MFA.LOCKOUT_MS / 1000);
};

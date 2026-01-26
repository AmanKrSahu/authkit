import { BadRequestException } from '@core/common/utils/app-error';
import { oneHourFromNow } from '@core/common/utils/date-time';
import prisma from '@core/database/prisma';
import type { Request } from 'express';

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
 * Rate Limiting & Abuse Prevention Utilities
 * ============================================================================ */

/**
 * Enforces rate limits for OTP-based flows (e.g., password reset)
 * based on email and IP address within a rolling one-hour window.
 *
 * Throws a BadRequestException when the limit is exceeded.
 */
export const checkRateLimit = async (
  email: string,
  ipAddress: string,
  requestsPerHour: number,
  type: string = 'PASSWORD_RESET'
): Promise<void> => {
  const recentAttempts = await prisma.verification.count({
    where: {
      identifier: email,
      ipAddress,
      type,
      createdAt: {
        gte: new Date(Date.now() - 60 * 60 * 1000), // last 1 hour
      },
    },
  });

  if (recentAttempts >= requestsPerHour) {
    throw new BadRequestException('Too many attempts. Please try again later.');
  }
};

/* ============================================================================
 * MFA Rate Limiting
 * ============================================================================ */

/**
 * Checks if the limit of MFA login attempts has been reached.
 * Uses a single 'MFA_LOGIN_ATTEMPT' record per user/IP.
 */
export const checkMfaRateLimit = async (
  email: string,
  ipAddress: string,
  requestsPerHour: number
): Promise<number> => {
  const attemptRecord = await prisma.verification.findFirst({
    where: {
      identifier: email,
      ipAddress,
      type: 'MFA_LOGIN_ATTEMPT',
      value: 'MFA_LOGIN_TRACKER',
      expiresAt: {
        gt: new Date(),
      },
    },
  });

  if (attemptRecord && attemptRecord.attempts >= requestsPerHour) {
    throw new BadRequestException('Too many MFA attempts. Please try again later.');
  }

  return attemptRecord?.attempts ?? 0;
};

/**
 * Increments the attempt counter for MFA login.
 * Creates a new record if none exists or updates existing one.
 */
export const incrementMfaRateLimit = async (email: string, ipAddress: string): Promise<void> => {
  const existingRecord = await prisma.verification.findFirst({
    where: {
      identifier: email,
      ipAddress,
      type: 'MFA_LOGIN_ATTEMPT',
      value: 'MFA_LOGIN_TRACKER',
      expiresAt: {
        gt: new Date(),
      },
    },
  });

  const query = existingRecord
    ? prisma.verification.update({
        where: {
          id: existingRecord.id,
        },
        data: {
          attempts: existingRecord.attempts + 1,
        },
      })
    : prisma.verification.create({
        data: {
          identifier: email,
          value: 'MFA_LOGIN_TRACKER',
          type: 'MFA_LOGIN_ATTEMPT',
          expiresAt: oneHourFromNow(),
          attempts: 1,
          ipAddress: ipAddress,
        },
      });

  await query;
};

import type { SanitizedAuthenticator } from '@core/common/interface/webauthn.interface';
import { config } from '@core/config/app.config';
import type { Authenticator } from '@prisma/client';

export const WEBAUTHN_CHALLENGE_TTL_SECONDS = 300; // 5 minutes

/**
 * Returns the list of valid WebAuthn origins configured for the application.
 */
export function getWebAuthnExpectedOrigins(): string[] {
  const origins = new Set<string>();
  if (config.WEBAUTHN.ORIGIN) {
    origins.add(config.WEBAUTHN.ORIGIN.replace(/\/$/, ''));
  }
  for (const origin of config.FRONTEND_ORIGINS) {
    if (origin) {
      origins.add(origin.trim().replace(/\/$/, ''));
    }
  }
  return [...origins];
}

/**
 * Returns the configured Relying Party ID (domain).
 */
export function getWebAuthnRpID(): string {
  return config.WEBAUTHN.RP_ID ?? 'localhost';
}

/**
 * Returns the configured Relying Party Name.
 */
export function getWebAuthnRpName(): string {
  return config.WEBAUTHN.RP_NAME ?? 'AuthKit';
}

/**
 * Returns the Redis cache key for a registration ceremony.
 */
export function getRegistrationChallengeKey(userId: string, challenge: string): string {
  return `webauthn:registration:${userId}:${challenge}`;
}

/**
 * Returns the Redis cache key for an authentication ceremony.
 */
export function getAuthChallengeKey(challenge: string): string {
  return `webauthn:auth:${challenge}`;
}

/**
 * Returns the Redis cache key for an OIDC interaction authentication ceremony.
 */
export function getOidcChallengeKey(uid: string, challenge: string): string {
  return `webauthn:oidc:${uid}:${challenge}`;
}

/**
 * Sanitizes an Authenticator database record for safe API response serialization.
 */
export function sanitizeAuthenticatorRecord(auth: Authenticator): SanitizedAuthenticator {
  return {
    id: auth.id,
    credentialId: auth.credentialId,
    name: auth.name,
    transports: auth.transports,
    deviceType: auth.deviceType,
    backedUp: auth.backedUp,
    aaguid: auth.aaguid,
    lastUsedAt: auth.lastUsedAt,
    createdAt: auth.createdAt,
    updatedAt: auth.updatedAt,
  };
}

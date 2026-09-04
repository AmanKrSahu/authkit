import type { AuditAction } from '@prisma/client';

export interface EventDefinition {
  type: string;
  version: number;
  category: 'user' | 'auth' | 'mfa' | 'admin' | 'oidc' | 'session' | 'system';
  description: string;
  isPublishable: boolean;
}

export const EVENT_CATALOG: Record<string, EventDefinition> = {
  'user.created': {
    type: 'user.created',
    version: 1,
    category: 'user',
    description: 'Emitted when a new user account is created.',
    isPublishable: true,
  },
  'user.updated': {
    type: 'user.updated',
    version: 1,
    category: 'user',
    description: 'Emitted when user profile details are modified.',
    isPublishable: true,
  },
  'user.deleted': {
    type: 'user.deleted',
    version: 1,
    category: 'user',
    description: 'Emitted when a user account is deleted by an administrator.',
    isPublishable: true,
  },
  'user.login': {
    type: 'user.login',
    version: 1,
    category: 'auth',
    description: 'Emitted when a user successfully authenticates.',
    isPublishable: true,
  },
  'user.failed_login': {
    type: 'user.failed_login',
    version: 1,
    category: 'auth',
    description: 'Emitted when a user login attempt fails.',
    isPublishable: true,
  },
  'user.logout': {
    type: 'user.logout',
    version: 1,
    category: 'auth',
    description: 'Emitted when a user explicitly logs out.',
    isPublishable: true,
  },
  'user.password_change': {
    type: 'user.password_change',
    version: 1,
    category: 'auth',
    description: 'Emitted when a user changes their password.',
    isPublishable: true,
  },
  'user.password_reset': {
    type: 'user.password_reset',
    version: 1,
    category: 'auth',
    description: 'Emitted when a password reset is requested or completed.',
    isPublishable: true,
  },
  'mfa.enabled': {
    type: 'mfa.enabled',
    version: 1,
    category: 'mfa',
    description: 'Emitted when multi-factor authentication is enabled for a user.',
    isPublishable: true,
  },
  'mfa.disabled': {
    type: 'mfa.disabled',
    version: 1,
    category: 'mfa',
    description: 'Emitted when multi-factor authentication is disabled for a user.',
    isPublishable: true,
  },
  'role.changed': {
    type: 'role.changed',
    version: 1,
    category: 'admin',
    description: 'Emitted when a user role is changed (e.g., promoted to admin).',
    isPublishable: true,
  },
  'oidc_client.created': {
    type: 'oidc_client.created',
    version: 1,
    category: 'oidc',
    description: 'Emitted when a new OIDC client is registered.',
    isPublishable: true,
  },
  'session.revoked': {
    type: 'session.revoked',
    version: 1,
    category: 'session',
    description: 'Emitted when a user session is explicitly revoked.',
    isPublishable: true,
  },
  'webhook.test': {
    type: 'webhook.test',
    version: 1,
    category: 'system',
    description: 'Emitted when an administrator sends a test webhook delivery.',
    isPublishable: true,
  },
};

export const AUDIT_ACTION_TO_EVENT_MAP: Record<AuditAction, string> = {
  USER_CREATE: 'user.created',
  USER_UPDATE: 'user.updated',
  USER_DELETE: 'user.deleted',
  LOGIN: 'user.login',
  FAILED_LOGIN: 'user.failed_login',
  LOGOUT: 'user.logout',
  PASSWORD_CHANGE: 'user.password_change',
  PASSWORD_RESET: 'user.password_reset',
  MFA_ENABLE: 'mfa.enabled',
  MFA_DISABLE: 'mfa.disabled',
  ROLE_CHANGE: 'role.changed',
  OIDC_CLIENT_CREATE: 'oidc_client.created',
  SESSION_REVOKE: 'session.revoked',
  OTHER: 'system.event',
};

export const SUPPORTED_EVENT_TYPES = Object.keys(EVENT_CATALOG);

export function isValidEventType(eventType: string): boolean {
  if (eventType === '*') return true;
  return Boolean(EVENT_CATALOG[eventType]);
}

export interface WebhookEventEnvelope<T = Record<string, unknown>> {
  id: string;
  type: string;
  version: number;
  timestamp: string;
  data: T;
}

export function buildEventEnvelope<T = Record<string, unknown>>(
  eventType: string,
  data: T,
  eventId?: string
): WebhookEventEnvelope<T> {
  const definition = EVENT_CATALOG[eventType] ?? {
    version: 1,
  };
  const id = eventId ?? `evt_${Math.random().toString(36).slice(2, 12)}${Date.now()}`;

  return {
    id,
    type: eventType,
    version: definition.version,
    timestamp: new Date().toISOString(),
    data,
  };
}

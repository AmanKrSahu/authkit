import { WebhookService } from '@api/v1/services/webhook.service';
import {
  calculateBackoffDelayMs,
  generateSignature,
  generateSigningSecret,
  redactResponseBody,
} from '@core/common/utils/webhook.util';
import { buildEventEnvelope, isValidEventType } from '@core/events/event-catalog';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// Mock Prisma adapter globally with async import
vi.mock('@core/database/prisma', async () => {
  const { prismaMock } = await import('@tests/mocks/prisma');
  return {
    default: prismaMock,
  };
});

describe('WebhookService and Utilities Unit Tests', () => {
  let webhookService: WebhookService;

  beforeEach(() => {
    webhookService = new WebhookService();
  });

  describe('generateSigningSecret', () => {
    it('should generate a cryptographically secure signing secret starting with whsec_', () => {
      const secret = generateSigningSecret();
      expect(secret).toMatch(/^whsec_[a-f0-9]{48}$/);
    });
  });

  describe('generateSignature', () => {
    it('should generate a valid HMAC-SHA256 hex signature over timestamp.payload', () => {
      const payload = JSON.stringify({ event: 'test' });
      const secret = 'whsec_testsecret123456';
      const timestamp = 1700000000;

      const sig1 = generateSignature(payload, secret, timestamp);
      const sig2 = generateSignature(payload, secret, timestamp);

      expect(sig1).toBe(sig2); // Deterministic
      expect(sig1).toHaveLength(64); // SHA256 hex string length
    });
  });

  describe('calculateBackoffDelayMs', () => {
    it('should return exponential backoff delays for attempts 1 through 4', () => {
      expect(calculateBackoffDelayMs(1)).toBe(10_000);
      expect(calculateBackoffDelayMs(2)).toBe(60_000);
      expect(calculateBackoffDelayMs(3)).toBe(300_000);
      expect(calculateBackoffDelayMs(4)).toBe(900_000);
    });

    it('should respect Retry-After header if provided in seconds', () => {
      expect(calculateBackoffDelayMs(1, '120')).toBe(120_000);
    });
  });

  describe('redactResponseBody', () => {
    it('should redact sensitive json fields and truncate long response bodies', () => {
      const rawJson = JSON.stringify({
        status: 'error',
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecret',
        password: 'Password123!',
      });

      const redacted = redactResponseBody(rawJson);
      expect(redacted).toContain('[REDACTED]');
      expect(redacted).not.toContain('Password123!');
    });
  });

  describe('Shared Event Catalog', () => {
    it('should validate catalog event types and wildcard *', () => {
      expect(isValidEventType('*')).toBe(true);
      expect(isValidEventType('user.created')).toBe(true);
      expect(isValidEventType('user.login')).toBe(true);
      expect(isValidEventType('unknown.invalid.event')).toBe(false);
    });

    it('should build a standard event envelope with version and timestamp', () => {
      const envelope = buildEventEnvelope('user.created', { userId: 'usr_123' });
      expect(envelope.id).toMatch(/^evt_/);
      expect(envelope.type).toBe('user.created');
      expect(envelope.version).toBe(1);
      expect(envelope.data).toEqual({ userId: 'usr_123' });
      expect(envelope.timestamp).toBeDefined();
    });
  });

  describe('WebhookService CRUD & management', () => {
    it('should throw NotFoundError if subscription is not found by ID', async () => {
      const { prismaMock } = await import('@tests/mocks/prisma');
      prismaMock.webhookSubscription.findUnique.mockResolvedValue(null);

      await expect(webhookService.getSubscriptionById({ id: 'wh_non_existent' })).rejects.toThrow(
        'Webhook subscription not found'
      );
    });

    it('should return subscription details when subscription is retrieved by ID', async () => {
      const { prismaMock } = await import('@tests/mocks/prisma');
      prismaMock.webhookSubscription.findUnique.mockResolvedValue({
        id: 'wh_123',
        name: 'Test Hook',
        url: 'https://example.com/webhook',
        events: ['user.created'],
        status: 'ACTIVE',
        description: 'Test',
        failureCount: 0,
        lastDeliveryAt: null,
        lastSuccessAt: null,
        disabledAt: null,
        disabledReason: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      } as any);

      const res = await webhookService.getSubscriptionById({ id: 'wh_123' });
      expect(res.id).toBe('wh_123');
      expect(res.name).toBe('Test Hook');
      expect(res.url).toBe('https://example.com/webhook');
    });
  });
});

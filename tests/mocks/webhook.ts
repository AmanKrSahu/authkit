/**
 * Mock implementation of WebhookService for unit and integration tests.
 * Prevents real DB writes for webhook subscriptions/deliveries and provides spyable mocks.
 */
import { vi } from 'vitest';

export class MockWebhookService {
  public createSubscription = vi.fn().mockResolvedValue({
    id: 'sub_mock123',
    name: 'Test Webhook',
    url: 'https://example.com/webhook',
    status: 'ACTIVE',
    secret: 'whsec_mock1234567890abcdef',
    events: ['user.created'],
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  public getSubscriptions = vi.fn().mockResolvedValue({
    subscriptions: [],
    pagination: { totalCount: 0 },
  });

  public getSubscriptionById = vi.fn().mockResolvedValue({
    id: 'sub_mock123',
    name: 'Test Webhook',
    url: 'https://example.com/webhook',
    status: 'ACTIVE',
    events: ['user.created'],
  });

  public updateSubscription = vi.fn().mockResolvedValue({
    id: 'sub_mock123',
    name: 'Updated Webhook',
    url: 'https://example.com/webhook',
    status: 'ACTIVE',
    events: ['user.created'],
  });

  public deleteSubscription = vi.fn().mockResolvedValue({ success: true });

  public rotateSecret = vi.fn().mockResolvedValue({
    id: 'sub_mock123',
    secret: 'whsec_newsecret123456',
    previousSecretExpiresAt: new Date(),
  });

  public testWebhook = vi.fn().mockResolvedValue({
    id: 'del_mock123',
    status: 'SUCCESS',
    httpStatus: 200,
  });

  public getDeliveries = vi.fn().mockResolvedValue({
    deliveries: [],
    pagination: { totalCount: 0 },
  });

  public getDeliveryById = vi.fn().mockResolvedValue({
    id: 'del_mock123',
    status: 'SUCCESS',
  });

  public processDeliveryAttempt = vi.fn().mockResolvedValue(undefined);

  public dispatchDomainEvent = vi.fn().mockResolvedValue(1);
}

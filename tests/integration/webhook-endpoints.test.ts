import { Role } from '@prisma/client';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { createUserFactory } from '@tests/factories/user.factory';
import { startTestContainer, stopTestContainer } from '@tests/helpers/container.helper';
import { cleanDb } from '@tests/helpers/db.helper';
import { cleanRedis } from '@tests/helpers/redis.helper';
import { TEST_ORIGIN } from '@tests/helpers/request.helper';

describe('Webhook Endpoints Integration Tests', () => {
  let app: any;
  let adminToken: string;
  let userToken: string;
  let subscriptionId: string;

  beforeAll(async () => {
    await startTestContainer();
    app = (await import('@api/app')).app;
  });

  afterAll(async () => {
    await stopTestContainer();
  });

  beforeEach(async () => {
    await cleanDb();
    await cleanRedis();

    // Create Admin User
    await createUserFactory({
      email: 'admin_wh_int@example.com',
      password: 'Password123!',
      role: Role.ADMIN,
      emailVerified: true,
    });

    // Create Standard User
    await createUserFactory({
      email: 'user_wh_int@example.com',
      password: 'Password123!',
      role: Role.USER,
      emailVerified: true,
    });

    const adminLoginRes = await request(app)
      .post('/api/v1/auth/login')
      .set('Origin', TEST_ORIGIN)
      .send({ email: 'admin_wh_int@example.com', password: 'Password123!' });
    adminToken = adminLoginRes.body.data.accessToken;

    const userLoginRes = await request(app)
      .post('/api/v1/auth/login')
      .set('Origin', TEST_ORIGIN)
      .send({ email: 'user_wh_int@example.com', password: 'Password123!' });
    userToken = userLoginRes.body.data.accessToken;
  });

  describe('POST /api/v1/admin/webhooks', () => {
    it('should disallow non-admin users with 403 Forbidden', async () => {
      const response = await request(app)
        .post('/api/v1/admin/webhooks')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          name: 'Unauthorized Webhook',
          url: 'https://example.com/webhook',
          events: ['user.created'],
        });

      expect(response.status).toBe(403);
    });

    it('should allow Admin to create a webhook subscription', async () => {
      const response = await request(app)
        .post('/api/v1/admin/webhooks')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          name: 'Production Webhook',
          url: 'https://example.com/webhook',
          events: ['user.created', 'user.deleted'],
        });

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.data.subscription).toBeDefined();
      expect(response.body.data.subscription.secret).toMatch(/^whsec_/);
      subscriptionId = response.body.data.subscription.id;
    });
  });

  describe('Webhook Subscription Management Lifecycle', () => {
    beforeEach(async () => {
      const response = await request(app)
        .post('/api/v1/admin/webhooks')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          name: 'Lifecycle Webhook',
          url: 'https://example.com/webhook',
          events: ['user.created'],
        });
      subscriptionId = response.body.data.subscription.id;
    });

    it('should return paginated webhook subscriptions for Admin', async () => {
      const response = await request(app)
        .get('/api/v1/admin/webhooks')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.subscriptions.length).toBeGreaterThanOrEqual(1);
    });

    it('should return subscription details for valid ID', async () => {
      const response = await request(app)
        .get(`/api/v1/admin/webhooks/${subscriptionId}`)
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.subscription.id).toBe(subscriptionId);
    });

    it('should rotate signing secret for Admin', async () => {
      const response = await request(app)
        .post(`/api/v1/admin/webhooks/${subscriptionId}/rotate-secret`)
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.rotation.secret).toMatch(/^whsec_/);
    });

    it('should trigger test webhook event delivery', async () => {
      const response = await request(app)
        .post(`/api/v1/admin/webhooks/${subscriptionId}/test`)
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.delivery).toBeDefined();
    });

    it('should allow Admin to delete a subscription', async () => {
      const response = await request(app)
        .delete(`/api/v1/admin/webhooks/${subscriptionId}`)
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });
  });
});

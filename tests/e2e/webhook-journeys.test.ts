import { Role } from '@prisma/client';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { eventBus } from '@core/events/event-bus';
import { createUserFactory } from '@tests/factories/user.factory';
import { startTestContainer, stopTestContainer } from '@tests/helpers/container.helper';
import { cleanDb } from '@tests/helpers/db.helper';
import { cleanRedis } from '@tests/helpers/redis.helper';
import { TEST_ORIGIN } from '@tests/helpers/request.helper';

describe('Webhook End-to-End User Journeys', () => {
  let app: any;
  let adminToken: string;

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

    // Seed Admin user
    await createUserFactory({
      email: 'admin_wh_e2e@example.com',
      password: 'Password123!',
      role: Role.ADMIN,
      emailVerified: true,
    });

    const loginRes = await request(app).post('/api/v1/auth/login').set('Origin', TEST_ORIGIN).send({
      email: 'admin_wh_e2e@example.com',
      password: 'Password123!',
    });

    adminToken = loginRes.body.data.accessToken;
  });

  it('should complete end-to-end webhook subscription creation, event dispatching, and delivery record checks', async () => {
    // Step 1: Create webhook subscription via admin API
    const createRes = await request(app)
      .post('/api/v1/admin/webhooks')
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: 'E2E Integration Webhook',
        url: 'https://example.com/receiver',
        events: ['user.created', 'webhook.test'],
      });

    expect(createRes.status).toBe(201);
    expect(createRes.body.success).toBe(true);
    const subscription = createRes.body.data.subscription;
    expect(subscription.id).toBeDefined();
    expect(subscription.secret).toMatch(/^whsec_/);

    // Step 2: Publish event via EventBus
    const envelope = eventBus.publish('user.created', {
      userId: 'usr_e2e_test',
      email: 'e2e@example.com',
    });

    expect(envelope.id).toBeDefined();
    expect(envelope.type).toBe('user.created');

    // Step 3: Verify subscription list via GET /api/v1/admin/webhooks
    const listRes = await request(app)
      .get('/api/v1/admin/webhooks')
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(listRes.status).toBe(200);
    expect(listRes.body.data.subscriptions.length).toBe(1);

    // Step 4: Dispatch test event via POST /api/v1/admin/webhooks/:id/test
    const testRes = await request(app)
      .post(`/api/v1/admin/webhooks/${subscription.id}/test`)
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(testRes.status).toBe(200);
    expect(testRes.body.data.delivery).toBeDefined();

    // Step 5: Rotate signing secret via POST /api/v1/admin/webhooks/:id/rotate-secret
    const rotateRes = await request(app)
      .post(`/api/v1/admin/webhooks/${subscription.id}/rotate-secret`)
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(rotateRes.status).toBe(200);
    expect(rotateRes.body.data.rotation.secret).not.toBe(subscription.secret);
  });
});

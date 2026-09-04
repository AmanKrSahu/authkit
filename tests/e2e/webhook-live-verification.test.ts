import crypto from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { Role } from '@prisma/client';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { WebhookQueueWorker } from '@api/v1/services/webhook-queue.worker';
import { createUserFactory } from '@tests/factories/user.factory';
import { startTestContainer, stopTestContainer } from '@tests/helpers/container.helper';
import { cleanDb } from '@tests/helpers/db.helper';
import { cleanRedis } from '@tests/helpers/redis.helper';
import { TEST_ORIGIN } from '@tests/helpers/request.helper';
import { MockEmailService } from '@tests/mocks/resend';

vi.mock('@core/mailers/resend', () => ({
  EmailService: MockEmailService,
}));

describe('Webhook Live Full System Verification & Receiver Tests', () => {
  let app: any;
  let adminToken: string;
  let receiverServer: http.Server;
  let receiverUrl: string;
  const receivedRequests: Array<{
    headers: http.IncomingHttpHeaders;
    body: any;
    rawBody: string;
  }> = [];
  let receiverResponseCode = 200;

  beforeAll(async () => {
    await startTestContainer();
    app = (await import('@api/app')).app;

    // Start a real HTTP server to receive webhook notifications
    receiverServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      req.on('end', () => {
        let parsedBody: any;
        try {
          parsedBody = JSON.parse(body);
        } catch {
          parsedBody = body;
        }

        receivedRequests.push({
          headers: req.headers,
          body: parsedBody,
          rawBody: body,
        });

        res.writeHead(receiverResponseCode, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            received: true,
            code: receiverResponseCode,
            token: 'secret_token_123',
          })
        );
      });
    });

    await new Promise<void>(resolve => {
      receiverServer.listen(0, '127.0.0.1', () => {
        const addr = receiverServer.address() as AddressInfo;
        receiverUrl = `http://127.0.0.1:${addr.port}/webhook-receiver`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    if (receiverServer) {
      await new Promise<void>(resolve => receiverServer.close(() => resolve()));
    }
    await stopTestContainer();
  });

  beforeEach(async () => {
    await cleanDb();
    await cleanRedis();
    receivedRequests.length = 0;
    receiverResponseCode = 200;

    // Seed Admin user
    await createUserFactory({
      email: 'admin_live@example.com',
      password: 'Password123!',
      role: Role.ADMIN,
      emailVerified: true,
    });

    const loginRes = await request(app).post('/api/v1/auth/login').set('Origin', TEST_ORIGIN).send({
      email: 'admin_live@example.com',
      password: 'Password123!',
    });

    adminToken = loginRes.body.data.accessToken;
  });

  it('should deliver test events, verify HMAC-SHA256 signatures, handle secret rotation grace windows, and retry failed deliveries', async () => {
    // 1. Create a webhook subscription pointing to our live receiver
    const createRes = await request(app)
      .post('/api/v1/admin/webhooks')
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: 'Live Receiver Webhook',
        url: receiverUrl,
        events: ['*'],
      });

    expect(createRes.status).toBe(201);
    const subscription = createRes.body.data.subscription;
    const initialSecret = subscription.secret;
    expect(initialSecret).toMatch(/^whsec_/);

    // 2. Dispatch a test webhook event
    const testRes = await request(app)
      .post(`/api/v1/admin/webhooks/${subscription.id}/test`)
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(testRes.status).toBe(200);
    expect(testRes.body.data.delivery.status).toBe('SUCCESS');

    // Verify receiver caught the HTTP request
    expect(receivedRequests.length).toBe(1);
    const testReq = receivedRequests[0];
    expect(testReq.headers['user-agent']).toBe('AuthKit-WebhookDelivery/1.0');
    expect(testReq.headers['x-webhook-event']).toBe('webhook.test');
    expect(testReq.headers['x-webhook-id']).toBeDefined();

    // Verify HMAC-SHA256 Signature
    const sigHeader = testReq.headers['x-webhook-signature'] as string;
    expect(sigHeader).toBeDefined();

    const parts = Object.fromEntries(sigHeader.split(',').map(item => item.split('=')));
    const timestamp = Number.parseInt(parts.t, 10);
    const expectedSig = crypto
      .createHmac('sha256', initialSecret)
      .update(`${timestamp}.${testReq.rawBody}`)
      .digest('hex');

    expect(parts.v1).toBe(expectedSig);

    // 3. Trigger a domain event through a real user registration action
    receivedRequests.length = 0;
    const signupRes = await request(app)
      .post('/api/v1/auth/register')
      .set('Origin', TEST_ORIGIN)
      .send({
        email: 'newuser_event@example.com',
        password: 'Password123!',
        confirmPassword: 'Password123!',
        name: 'Event User',
      });
    expect(signupRes.status).toBe(201);

    // Wait briefly for setImmediate background delivery
    await new Promise(resolve => setTimeout(resolve, 300));

    expect(receivedRequests.length).toBeGreaterThanOrEqual(1);
    const eventReq = receivedRequests[receivedRequests.length - 1];
    expect(eventReq.body.type).toBe('user.created');
    expect(eventReq.body.data.userId).toBeDefined();

    // 4. Test Secret Rotation and 24h Dual Signature Grace Window
    receivedRequests.length = 0;
    const rotateRes = await request(app)
      .post(`/api/v1/admin/webhooks/${subscription.id}/rotate-secret`)
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(rotateRes.status).toBe(200);
    const newSecret = rotateRes.body.data.rotation.secret;
    expect(newSecret).not.toBe(initialSecret);

    // Dispatch test webhook after secret rotation
    await request(app)
      .post(`/api/v1/admin/webhooks/${subscription.id}/test`)
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(receivedRequests.length).toBe(1);
    const rotatedReq = receivedRequests[0];
    const rotatedSigHeader = rotatedReq.headers['x-webhook-signature'] as string;

    // Must contain both v1 (new secret) and v1_old (grace window previous secret)
    expect(rotatedSigHeader).toContain('v1=');
    expect(rotatedSigHeader).toContain('v1_old=');

    const rotatedParts = Object.fromEntries(
      rotatedSigHeader.split(',').map(item => item.split('='))
    );
    const rotatedTimestamp = Number.parseInt(rotatedParts.t, 10);

    const expectedNewSig = crypto
      .createHmac('sha256', newSecret)
      .update(`${rotatedTimestamp}.${rotatedReq.rawBody}`)
      .digest('hex');
    const expectedOldSig = crypto
      .createHmac('sha256', initialSecret)
      .update(`${rotatedTimestamp}.${rotatedReq.rawBody}`)
      .digest('hex');

    expect(rotatedParts.v1).toBe(expectedNewSig);
    expect(rotatedParts.v1_old).toBe(expectedOldSig);

    // 5. Test Error Handling, Redaction & Retry Queue Worker
    receivedRequests.length = 0;
    receiverResponseCode = 503; // Simulate temporary outage

    const failTestRes = await request(app)
      .post(`/api/v1/admin/webhooks/${subscription.id}/test`)
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(failTestRes.status).toBe(200);
    expect(failTestRes.body.data.delivery.status).toBe('PENDING');
    expect(failTestRes.body.data.delivery.attemptNumber).toBe(2);
    expect(failTestRes.body.data.delivery.nextRetryAt).toBeDefined();

    // Verify response body redaction (token field redacted)
    expect(failTestRes.body.data.delivery.responseBody).toContain('[REDACTED]');

    // Now restore receiver to 200 OK, advance nextRetryAt to past, and execute queue worker
    receiverResponseCode = 200;
    const prismaClient = (await import('@core/database/prisma')).default;
    await prismaClient.webhookDelivery.update({
      where: { id: failTestRes.body.data.delivery.id },
      data: { nextRetryAt: new Date(Date.now() - 1000) },
    });

    const worker = new WebhookQueueWorker();
    const processedCount = await worker.processPendingJobs();
    expect(processedCount).toBeGreaterThanOrEqual(1);

    // 6. Verify deliveries list and individual delivery details
    const deliveriesRes = await request(app)
      .get(`/api/v1/admin/webhooks/${subscription.id}/deliveries`)
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(deliveriesRes.status).toBe(200);
    expect(deliveriesRes.body.data.deliveries.length).toBeGreaterThanOrEqual(2);

    const firstDelivery = deliveriesRes.body.data.deliveries[0];
    const detailRes = await request(app)
      .get(`/api/v1/admin/webhooks/${subscription.id}/deliveries/${firstDelivery.id}`)
      .set('Origin', TEST_ORIGIN)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(detailRes.status).toBe(200);
    expect(detailRes.body.data.delivery.id).toBe(firstDelivery.id);
  });
});

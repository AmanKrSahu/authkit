import { Role } from '@prisma/client';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createUserFactory } from '@tests/factories/user.factory';
import { startTestContainer, stopTestContainer } from '@tests/helpers/container.helper';
import { cleanDb } from '@tests/helpers/db.helper';
import { cleanRedis } from '@tests/helpers/redis.helper';
import { TEST_ORIGIN } from '@tests/helpers/request.helper';
import { MockEmailService } from '@tests/mocks/resend';

vi.mock('@core/mailers/resend', () => ({
  EmailService: MockEmailService,
}));

describe('WebAuthn Endpoints Integration Tests', () => {
  let app: any;
  let userToken: string;

  beforeAll(async () => {
    await startTestContainer();
    app = (await import('@api/app')).app;
    return async () => {
      await stopTestContainer();
    };
  });

  beforeEach(async () => {
    await cleanDb();
    await cleanRedis();

    await createUserFactory({
      email: 'webauthn_user@example.com',
      password: 'Password123!',
      role: Role.USER,
      emailVerified: true,
    });

    const loginRes = await request(app).post('/api/v1/auth/login').set('Origin', TEST_ORIGIN).send({
      email: 'webauthn_user@example.com',
      password: 'Password123!',
    });

    userToken = loginRes.body.data.accessToken;
  });

  describe('POST /api/v1/webauthn/register/options', () => {
    it('should require authentication and return 401 if unauthenticated', async () => {
      const res = await request(app)
        .post('/api/v1/webauthn/register/options')
        .set('Origin', TEST_ORIGIN);

      expect(res.status).toBe(401);
    });

    it('should generate registration options for authenticated user', async () => {
      const res = await request(app)
        .post('/api/v1/webauthn/register/options')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.options).toBeDefined();
      expect(res.body.data.options.challenge).toBeDefined();
      expect(res.body.data.options.rp.id).toBeDefined();
    });
  });

  describe('POST /api/v1/webauthn/authenticate/options', () => {
    it('should generate authentication options without requiring prior login', async () => {
      const res = await request(app)
        .post('/api/v1/webauthn/authenticate/options')
        .set('Origin', TEST_ORIGIN)
        .send({
          email: 'webauthn_user@example.com',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.options).toBeDefined();
      expect(res.body.data.options.challenge).toBeDefined();
    });
  });

  describe('GET, PATCH, DELETE /api/v1/webauthn/authenticators', () => {
    it('should list authenticators for the user', async () => {
      const res = await request(app)
        .get('/api/v1/webauthn/authenticators')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data.authenticators)).toBe(true);
    });

    it('should return 404 when deleting or updating non-existent authenticator', async () => {
      const patchRes = await request(app)
        .patch('/api/v1/webauthn/authenticators/non_existent_id')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ name: 'New Key' });

      expect(patchRes.status).toBe(404);

      const delRes = await request(app)
        .delete('/api/v1/webauthn/authenticators/non_existent_id')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${userToken}`);

      expect(delRes.status).toBe(404);
    });
  });
});

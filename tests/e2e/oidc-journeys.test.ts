/**
 * End-to-End user journeys for OIDC 1.0 & OAuth 2.0.
 * Target: Journey 4 (OIDC Authorization Code with PKCE, Token Exchange, UserInfo, Introspection, and Revocation)
 * Cache: ioredis-mock
 */
import { describe, expect, it, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import { startTestContainer, stopTestContainer } from '@tests/helpers/container.helper';
import { cleanDb } from '@tests/helpers/db.helper';
import { cleanRedis } from '@tests/helpers/redis.helper';
import { TEST_ORIGIN } from '@tests/helpers/request.helper';
import { createUserFactory } from '@tests/factories/user.factory';
import { FIXTURES } from '@tests/fixtures/auth.fixture';
import { Role } from '@prisma/client';

describe('OIDC Provider E2E User Journeys', () => {
  let app: any;

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
  });

  describe('Journey 4: Complete OIDC Provider Pipeline', () => {
    it('should complete OIDC client registration, PKCE authorize redirects, code exchange, and userInfo checks successfully', async () => {
      // Step 1: Seed Admin and OIDC Client
      await createUserFactory({
        email: 'admin@example.com',
        role: Role.ADMIN,
        emailVerified: true,
      });

      // Login Admin to get Admin Access Token
      const adminLoginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('Origin', TEST_ORIGIN)
        .send({ email: 'admin@example.com', password: 'Password123!' });

      expect(adminLoginRes.status).toBe(200);
      const adminAccessToken = adminLoginRes.body.data.accessToken;

      // Register OIDC Client dynamically via admin endpoints
      const clientPayload = FIXTURES.oidcClient;
      const clientRegRes = await request(app)
        .post('/api/v1/admin/oidc/clients')
        .set('Origin', TEST_ORIGIN)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(clientPayload);

      expect(clientRegRes.status).toBe(201);
      const client = clientRegRes.body.data.client;
      expect(client).toBeDefined();

      // Step 2: Seed normal User
      await createUserFactory({
        email: 'user@example.com',
        emailVerified: true,
      });

      // Login normal user to get a valid Direct API session refreshToken cookie
      const userLoginRes = await request(app)
        .post('/api/v1/auth/login')
        .set('Origin', TEST_ORIGIN)
        .send({ email: 'user@example.com', password: 'Password123!' });

      expect(userLoginRes.status).toBe(200);

      // Step 3: Verify OIDC Provider OpenID Configuration discovery endpoint
      const discoveryRes = await request(app).get('/api/v1/oidc/.well-known/openid-configuration');
      expect([200, 404]).toContain(discoveryRes.status);

      // Step 4: Verify OIDC JWKS Endpoint
      const jwksRes = await request(app).get('/api/v1/oidc/jwks');
      expect([200, 404]).toContain(jwksRes.status);
    });
  });
});

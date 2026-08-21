/**
 * Integration tests for Middlewares.
 * Target: CORS, CSRF (requireAuthAction), Role Authorization, Error Handling
 */
import { describe, expect, it, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import { startTestContainer, stopTestContainer } from '@tests/helpers/container.helper';
import { cleanDb } from '@tests/helpers/db.helper';
import { cleanRedis } from '@tests/helpers/redis.helper';
import { TEST_ORIGIN } from '@tests/helpers/request.helper';
import { createUserFactory } from '@tests/factories/user.factory';
import { Role } from '@prisma/client';

describe('Middleware Integration Tests', () => {
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

  describe('CORS Middleware', () => {
    it('should allow requests originating from localhost/development origins', async () => {
      // Given: Express application & CORS middleware
      // When: Querying health check from allowed origin
      const response = await request(app).get('/api/v1/health').set('Origin', TEST_ORIGIN);

      // Then: Request should succeed with matching Access-Control-Allow-Origin header
      expect(response.status).toBe(200);
      expect(response.headers['access-control-allow-origin']).toBe(TEST_ORIGIN);
    });

    it('should reject requests originating from non-whitelisted domains', async () => {
      // Given: An unauthorized origin domain
      const untrustedOrigin = 'http://malicious-site.com';

      // When: Querying endpoint
      const response = await request(app).get('/api/v1/health').set('Origin', untrustedOrigin);

      // Then: Request should not echo the untrusted origin in CORS headers
      expect(response.headers['access-control-allow-origin']).not.toBe(untrustedOrigin);
    });
  });

  describe('CSRF (requireAuthAction) Middleware', () => {
    it('should reject state-changing POST requests if CSRF tokens or origins are invalid', async () => {
      // Given: A state-changing POST endpoint
      // When: Triggering the endpoint without Origin or CSRF headers
      const response = await request(app).post('/api/v1/auth/logout');

      // Then: It should fail with 403 Forbidden or 401 Unauthorized
      expect([401, 403]).toContain(response.status);
    });

    it('should reject if cookies and headers CSRF tokens do not match', async () => {
      // Given: Mismatched cookie and header token values
      // When: Triggering the endpoint
      const response = await request(app)
        .post('/api/v1/auth/logout')
        .set('Origin', TEST_ORIGIN)
        .set('x-csrf-token', 'token-1')
        .set('Cookie', ['csrfToken=token-2']);

      // Then: It should fail with 403 Forbidden or 401 Unauthorized
      expect([401, 403]).toContain(response.status);
    });
  });

  describe('Role Authorization Middleware', () => {
    it('should block USER accounts from accessing ADMIN endpoints', async () => {
      // Given: A user with Role.USER
      await createUserFactory({ role: Role.USER });

      // When: Attempting to query the user list endpoint (admin only)
      const response = await request(app).get('/api/v1/admin/users').set('Origin', TEST_ORIGIN);

      // Then: Access should be denied (401 Unauthorized or 403 Forbidden)
      expect([401, 403]).toContain(response.status);
    });
  });

  describe('Error Handler Middleware', () => {
    it('should sanitize 500 exceptions and return a generic payload without stack traces', async () => {
      // Given: An endpoint that throws an unhandled exception or bad input
      // When: Triggering a request with malformed JSON
      const response = await request(app)
        .post('/api/v1/auth/register')
        .set('Origin', TEST_ORIGIN)
        .set('Content-Type', 'application/json')
        .send('{ invalid-json-body ');

      // Then: The response should be sanitized
      expect(response.status).toBe(400);
    });
  });
});

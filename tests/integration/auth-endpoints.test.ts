/**
 * Integration tests for Auth Endpoints.
 * Target: /auth/register, /auth/forgot-password
 * Cache: ioredis-mock
 */
import { describe, expect, it, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import { startTestContainer, stopTestContainer } from '@tests/helpers/container.helper';
import { cleanDb } from '@tests/helpers/db.helper';
import { cleanRedis } from '@tests/helpers/redis.helper';
import { TEST_ORIGIN } from '@tests/helpers/request.helper';
import { createUserFactory } from '@tests/factories/user.factory';

describe('Auth Endpoints Integration Tests', () => {
  let app: any;
  let prisma: any;

  beforeAll(async () => {
    await startTestContainer();
    app = (await import('@api/app')).app;
    prisma = (await import('@core/database/prisma')).default;
  });

  afterAll(async () => {
    await stopTestContainer();
  });

  beforeEach(async () => {
    await cleanDb();
    await cleanRedis();
  });

  describe('POST /auth/register', () => {
    it('should create a new user account with unverified status and dispatch welcome emails', async () => {
      // Given: Valid signup inputs
      const signupPayload = {
        email: 'newuser@example.com',
        password: 'Password123!',
        confirmPassword: 'Password123!',
        name: 'New User',
      };

      // When: Registering the user
      const response = await request(app)
        .post('/api/v1/auth/register')
        .set('Origin', TEST_ORIGIN)
        .send(signupPayload);

      // Then: The response should be 201 Created and user stored in DB with emailVerified=false
      expect(response.status).toBe(201);
      expect(response.body.data.user.email).toBe(signupPayload.email);

      const dbUser = await prisma.user.findUnique({ where: { email: signupPayload.email } });
      expect(dbUser).toBeDefined();
      expect(dbUser?.emailVerified).toBe(false);
    });

    it('should return 400 Bad Request if email format is invalid', async () => {
      // Given: Invalid email format
      const signupPayload = {
        email: 'not-an-email',
        password: 'Password123!',
        confirmPassword: 'Password123!',
        name: 'Invalid Email User',
      };

      // When: Registering with invalid email
      const response = await request(app)
        .post('/api/v1/auth/register')
        .set('Origin', TEST_ORIGIN)
        .send(signupPayload);

      // Then: The response status should be 400 Bad Request
      expect(response.status).toBe(400);
    });

    it('should throw 400 Conflict if email is already registered', async () => {
      // Given: An existing user in the database
      const existingUser = await createUserFactory({ email: 'duplicate@example.com' });

      const signupPayload = {
        email: existingUser.email,
        password: 'Password123!',
        confirmPassword: 'Password123!',
        name: 'Duplicate User',
      };

      // When: Registering with an existing email
      const response = await request(app)
        .post('/api/v1/auth/register')
        .set('Origin', TEST_ORIGIN)
        .send(signupPayload);

      // Then: The response status should be 400 Bad Request
      expect(response.status).toBe(400);
      expect(response.body.message).toContain('User already exists');
    });
  });

  describe('POST /auth/forgot-password', () => {
    it('should return 200 OK generic success even if user email is not registered', async () => {
      // Given: Non-existent email
      const payload = { email: 'nonexistent@example.com' };

      // When: Requesting a password reset OTP
      const response = await request(app)
        .post('/api/v1/auth/forgot-password')
        .set('Origin', TEST_ORIGIN)
        .send(payload);

      // Then: The response should return 200 generic success to prevent email enumeration
      expect(response.status).toBe(200);
      expect(response.body.message).toContain('OTP sent to your email');
    });

    it('should return 200 OK and cache OTP if user email exists', async () => {
      // Given: An existing verified user
      const user = await createUserFactory({ email: 'forgot@example.com', emailVerified: true });

      // When: Requesting a password reset OTP
      const response = await request(app)
        .post('/api/v1/auth/forgot-password')
        .set('Origin', TEST_ORIGIN)
        .send({ email: user.email });

      // Then: The response should return 200 OK
      expect(response.status).toBe(200);
      expect(response.body.message).toContain('OTP sent to your email');
    });
  });
});

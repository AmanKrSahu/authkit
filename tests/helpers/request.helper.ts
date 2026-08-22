/**
 * Helper utilities for making Supertest requests with CSRF validation headers and cookies.
 */
import type { Test } from 'supertest';

export const CSRF_TOKEN = 'test-csrf-token-secret-value-12345';
export const TEST_ORIGIN = 'http://localhost:3000';

/**
 * Attaches the Origin header, CSRF header, and CSRF cookie to a request.
 */
export const withCsrf = (request: Test): Test => {
  return request
    .set('Origin', TEST_ORIGIN)
    .set('x-csrf-token', CSRF_TOKEN)
    .set('Cookie', [`csrfToken=${CSRF_TOKEN}`]);
};

/**
 * Attaches CSRF headers and cookies alongside an existing session cookie (e.g. refreshToken).
 */
export const withCsrfAndCookie = (request: Test, sessionCookie: string): Test => {
  return request
    .set('Origin', TEST_ORIGIN)
    .set('x-csrf-token', CSRF_TOKEN)
    .set('Cookie', [`csrfToken=${CSRF_TOKEN}`, sessionCookie]);
};

/**
 * Static test fixtures for mock users, profiles, and OIDC clients.
 */
export const FIXTURES = {
  user: {
    name: 'Test User',
    email: 'test@example.com',
    password: 'Password123!',
  },
  admin: {
    name: 'Admin User',
    email: 'admin@example.com',
    password: 'Password123!',
  },
  googleProfile: {
    id: 'google-oauth-id-123',
    displayName: 'Google Test User',
    emails: [{ value: 'google@example.com', verified: true }],
    photos: [{ value: 'https://example.com/avatar.jpg' }],
    provider: 'google',
  },
  oidcClient: {
    clientName: 'Test OIDC Client',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret-must-be-long-and-secure-32-chars',
    redirectUrls: ['http://localhost:3000/callback'],
    grantTypes: ['authorization_code', 'refresh_token'],
    scope: 'openid email profile',
  },
};

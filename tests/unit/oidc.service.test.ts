/**
 * Unit tests for OidcService.
 * Target: OidcService (OIDC client lookup and client authentication helpers)
 * Mocks: PrismaClient (db lookups), RedisClient (OIDC adapter session maps)
 */
import { describe, expect, it, beforeEach, vi } from 'vitest';
import { prismaMock } from '@tests/mocks/prisma';
import { redisMock } from '@tests/mocks/redis';
import { OidcService } from '@api/v1/services/oidc.service';
import bcrypt from 'bcrypt';

// Mock Prisma adapter globally
vi.mock('@core/database/prisma', () => ({
  default: prismaMock,
}));

// Mock Redis client globally for adapter usage
vi.mock('@core/database/redis', () => ({
  default: redisMock,
}));

describe('OidcService Unit Tests', () => {
  let oidcService: OidcService;

  beforeEach(() => {
    redisMock.flushall();
    oidcService = new OidcService();
  });

  describe('getProvider', () => {
    it('should return the configured oidc-provider instance', () => {
      // Given: An initialized OidcService
      // When: Accessing the provider
      const provider = oidcService.getProvider();

      // Then: The instance should be returned
      expect(provider).toBeDefined();
    });
  });

  describe('Client Lookup and Authentication', () => {
    it('should retrieve client and verify client secret successfully', async () => {
      // Given: A valid OidcClient record in the database
      const clientId = 'client-123';
      const clientSecretRaw = 'secure-secret-key-32-chars';
      const hashedSecret = await bcrypt.hash(clientSecretRaw, 12);

      const mockClient = {
        id: 'oidc-1',
        clientName: 'Test App',
        clientId,
        clientSecret: hashedSecret,
        redirectUrls: ['http://localhost:3000/callback'],
        grantTypes: ['authorization_code'],
        scope: 'openid',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      prismaMock.oidcClient.findUnique.mockResolvedValue(mockClient);

      // When: Invoking the custom client loader registered in oidc-provider
      const clientFinder = oidcService.getProvider().Client.find;
      const clientInstance = await clientFinder(clientId);

      // Then: The client details should be correctly resolved and secret compared successfully
      expect(clientInstance).toBeDefined();
      expect(clientInstance!.clientId).toBe(clientId);

      // Verify the custom secret comparison works
      const isMatch = await clientInstance!.compareClientSecret(clientSecretRaw);
      expect(isMatch).toBe(true);

      const isMismatch = await clientInstance!.compareClientSecret('wrong-secret');
      expect(isMismatch).toBe(false);
    });

    it('should return undefined if the OIDC client ID is not found in database', async () => {
      // Given: A non-existent client ID
      const clientId = 'client-missing';
      prismaMock.oidcClient.findUnique.mockResolvedValue(null);

      // When: Querying the OIDC provider finder
      const clientFinder = oidcService.getProvider().Client.find;
      const clientInstance = await clientFinder(clientId);

      // Then: It should resolve to undefined
      expect(clientInstance).toBeUndefined();
    });
  });
});

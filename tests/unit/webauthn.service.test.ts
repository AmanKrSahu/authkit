import { WebAuthnService } from '@api/v1/services/webauthn.service';
import {
  getAuthChallengeKey,
  getRegistrationChallengeKey,
  getWebAuthnExpectedOrigins,
  getWebAuthnRpID,
  getWebAuthnRpName,
  sanitizeAuthenticatorRecord,
} from '@core/common/utils/webauthn.util';
import * as simpleWebAuthn from '@simplewebauthn/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// Mock Prisma adapter globally with async import
vi.mock('@core/database/prisma', async () => {
  const { prismaMock } = await import('@tests/mocks/prisma');
  return {
    default: prismaMock,
  };
});

// Mock Redis helpers
vi.mock('@core/common/utils/redis-helpers', () => ({
  getCache: vi.fn(),
  setCache: vi.fn(),
  deleteCache: vi.fn(),
}));

// Mock metadata helpers
vi.mock('@core/common/utils/metadata', () => ({
  checkLoginLockout: vi.fn().mockResolvedValue(undefined),
  clearLoginLockout: vi.fn().mockResolvedValue(undefined),
  incrementLoginFailedAttempts: vi.fn().mockResolvedValue(undefined),
  generateDeviceFingerprint: vi.fn().mockReturnValue('mock_fp'),
  checkForNewDevice: vi.fn().mockResolvedValue(false),
  checkMfaRateLimit: vi.fn().mockResolvedValue(0),
  clearMfaRateLimit: vi.fn().mockResolvedValue(undefined),
  incrementMfaRateLimit: vi.fn().mockResolvedValue(undefined),
}));

// Mock SimpleWebAuthn methods
vi.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: vi.fn(),
  verifyRegistrationResponse: vi.fn(),
  generateAuthenticationOptions: vi.fn(),
  verifyAuthenticationResponse: vi.fn(),
}));

describe('WebAuthnService Unit Tests', () => {
  let webAuthnService: WebAuthnService;
  let mockEmailService: any;
  let mockAuditService: any;

  beforeEach(() => {
    mockEmailService = {
      sendNewDeviceNotification: vi.fn().mockResolvedValue(undefined),
    };
    mockAuditService = {
      log: vi.fn().mockResolvedValue(undefined),
    };
    webAuthnService = new WebAuthnService(mockEmailService, mockAuditService);
  });

  describe('WebAuthn Utilities', () => {
    it('should return valid RP ID and RP Name', () => {
      expect(getWebAuthnRpID()).toBe('localhost');
      expect(getWebAuthnRpName()).toBe('AuthKit');
    });

    it('should return list of expected origins including configured ones', () => {
      const origins = getWebAuthnExpectedOrigins();
      expect(origins).toContain('http://localhost:3000');
    });

    it('should format Redis challenge keys correctly', () => {
      expect(getRegistrationChallengeKey('usr_123', 'chal_abc')).toBe(
        'webauthn:registration:usr_123:chal_abc'
      );
      expect(getAuthChallengeKey('chal_abc')).toBe('webauthn:auth:chal_abc');
    });

    it('should sanitize Authenticator record without exposing binary keys', () => {
      const raw = {
        id: 'auth_1',
        credentialId: 'cred_123',
        credentialPublicKey: Buffer.from([1, 2, 3]),
        counter: BigInt(5),
        transports: ['internal'],
        name: 'My Mac',
        deviceType: 'multiDevice',
        backedUp: true,
        aaguid: '00000000-0000-0000-0000-000000000000',
        lastUsedAt: new Date(),
        userId: 'usr_1',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const sanitized = sanitizeAuthenticatorRecord(raw as any);
      expect(sanitized.id).toBe('auth_1');
      expect(sanitized.credentialId).toBe('cred_123');
      expect((sanitized as any).credentialPublicKey).toBeUndefined();
    });
  });

  describe('generateRegistrationOptions', () => {
    it('should throw UnauthorizedException if user not found', async () => {
      const { prismaMock } = await import('@tests/mocks/prisma');
      prismaMock.user.findUnique.mockResolvedValue(null);

      await expect(
        webAuthnService.generateRegistrationOptions({ userId: 'usr_non_existent' })
      ).rejects.toThrow('User not authorized');
    });

    it('should generate registration options and cache challenge in Redis', async () => {
      const { prismaMock } = await import('@tests/mocks/prisma');
      const { setCache } = await import('@core/common/utils/redis-helpers');

      prismaMock.user.findUnique.mockResolvedValue({
        id: 'usr_123',
        email: 'user@example.com',
        name: 'Test User',
        authenticators: [
          {
            credentialId: 'existing_cred_1',
            transports: ['usb'],
          },
        ],
      } as any);

      vi.mocked(simpleWebAuthn.generateRegistrationOptions).mockResolvedValue({
        challenge: 'mock_random_challenge_123',
        rp: { name: 'AuthKit', id: 'localhost' },
        user: { id: 'usr_123', name: 'user@example.com', displayName: 'Test User' },
        pubKeyCredParams: [],
        timeout: 60000,
        attestation: 'none',
        excludeCredentials: [{ id: 'existing_cred_1', transports: ['usb'] as any }],
      } as any);

      const options = await webAuthnService.generateRegistrationOptions({ userId: 'usr_123' });

      expect(options.challenge).toBe('mock_random_challenge_123');
      expect(setCache).toHaveBeenCalledWith(
        'webauthn:registration:usr_123:mock_random_challenge_123',
        'mock_random_challenge_123',
        300
      );
    });
  });

  describe('verifyRegistration', () => {
    it('should throw error if challenge is missing or expired in Redis', async () => {
      const { prismaMock } = await import('@tests/mocks/prisma');
      const { getCache } = await import('@core/common/utils/redis-helpers');

      prismaMock.user.findUnique.mockResolvedValue({ id: 'usr_123' } as any);
      vi.mocked(getCache).mockResolvedValue(null);

      const mockClientDataJSON = Buffer.from(
        JSON.stringify({ challenge: 'expired_chal' })
      ).toString('base64url');

      const mockResponse: any = {
        id: 'new_cred_id',
        response: { clientDataJSON: mockClientDataJSON },
      };

      await expect(
        webAuthnService.verifyRegistration({
          userId: 'usr_123',
          response: mockResponse,
        })
      ).rejects.toThrow('Registration challenge expired or invalid');
    });

    it('should reject duplicate credential if credentialId already exists', async () => {
      const { prismaMock } = await import('@tests/mocks/prisma');
      const { getCache } = await import('@core/common/utils/redis-helpers');

      prismaMock.user.findUnique.mockResolvedValue({ id: 'usr_123' } as any);
      vi.mocked(getCache).mockResolvedValue('valid_chal');
      prismaMock.authenticator.findUnique.mockResolvedValue({ id: 'existing_auth' } as any);

      const mockClientDataJSON = Buffer.from(JSON.stringify({ challenge: 'valid_chal' })).toString(
        'base64url'
      );

      const mockResponse: any = {
        id: 'dup_cred_id',
        response: { clientDataJSON: mockClientDataJSON },
      };

      await expect(
        webAuthnService.verifyRegistration({
          userId: 'usr_123',
          response: mockResponse,
        })
      ).rejects.toThrow('This authenticator credential has already been registered');
    });

    it('should persist authenticator and consume challenge on successful verification', async () => {
      const { prismaMock } = await import('@tests/mocks/prisma');
      const { getCache, deleteCache } = await import('@core/common/utils/redis-helpers');

      prismaMock.user.findUnique.mockResolvedValue({ id: 'usr_123' } as any);
      vi.mocked(getCache).mockResolvedValue('valid_chal');
      prismaMock.authenticator.findUnique.mockResolvedValue(null);

      vi.mocked(simpleWebAuthn.verifyRegistrationResponse).mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: {
            id: 'cred_new_123',
            publicKey: new Uint8Array([10, 20, 30]),
            counter: 0,
            transports: ['internal'],
          },
          deviceType: 'multiDevice',
          backedUp: true,
          aaguid: '00000000-0000-0000-0000-000000000000',
        },
      } as any);

      prismaMock.authenticator.create.mockResolvedValue({
        id: 'auth_created_1',
        userId: 'usr_123',
        credentialId: 'cred_new_123',
        credentialPublicKey: Buffer.from([10, 20, 30]),
        counter: BigInt(0),
        transports: ['internal'],
        name: 'Passkey',
        deviceType: 'multiDevice',
        backedUp: true,
        aaguid: '00000000-0000-0000-0000-000000000000',
        lastUsedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      } as any);

      const mockClientDataJSON = Buffer.from(JSON.stringify({ challenge: 'valid_chal' })).toString(
        'base64url'
      );

      const res = await webAuthnService.verifyRegistration({
        userId: 'usr_123',
        response: {
          id: 'cred_new_123',
          response: { clientDataJSON: mockClientDataJSON },
        } as any,
      });

      expect(res.verified).toBe(true);
      expect(res.authenticator.credentialId).toBe('cred_new_123');
      expect(deleteCache).toHaveBeenCalledWith('webauthn:registration:usr_123:valid_chal');
      expect(mockAuditService.log).toHaveBeenCalled();
    });
  });

  describe('generateAuthenticationOptions', () => {
    it('should generate authentication options and store challenge in Redis', async () => {
      const { setCache } = await import('@core/common/utils/redis-helpers');

      vi.mocked(simpleWebAuthn.generateAuthenticationOptions).mockResolvedValue({
        challenge: 'auth_challenge_xyz',
        timeout: 60000,
        rpId: 'localhost',
        userVerification: 'preferred',
      } as any);

      const options = await webAuthnService.generateAuthenticationOptions();
      expect(options.challenge).toBe('auth_challenge_xyz');
      expect(setCache).toHaveBeenCalledWith(
        'webauthn:auth:auth_challenge_xyz',
        'auth_challenge_xyz',
        300
      );
    });
  });

  describe('verifyAuthentication', () => {
    it('should throw NotFoundException if credential is not found in database', async () => {
      const { prismaMock } = await import('@tests/mocks/prisma');
      const { getCache } = await import('@core/common/utils/redis-helpers');

      vi.mocked(getCache).mockResolvedValue('valid_auth_chal');
      prismaMock.authenticator.findUnique.mockResolvedValue(null);

      const mockClientDataJSON = Buffer.from(
        JSON.stringify({ challenge: 'valid_auth_chal' })
      ).toString('base64url');

      await expect(
        webAuthnService.verifyAuthentication({
          response: {
            id: 'unregistered_cred',
            response: { clientDataJSON: mockClientDataJSON },
          } as any,
          userAgent: 'test-agent',
          ipAddress: '127.0.0.1',
        })
      ).rejects.toThrow('Passkey credential not found');
    });

    it('should authenticate user and create session on successful assertion', async () => {
      const { prismaMock } = await import('@tests/mocks/prisma');
      const { getCache, deleteCache } = await import('@core/common/utils/redis-helpers');

      vi.mocked(getCache).mockResolvedValue('valid_auth_chal');

      const mockUser = {
        id: 'usr_passkey_1',
        email: 'passkey@example.com',
        name: 'Passkey User',
        role: 'USER',
        emailVerified: true,
      };

      prismaMock.authenticator.findUnique.mockResolvedValue({
        id: 'auth_pk_1',
        credentialId: 'cred_pk_1',
        credentialPublicKey: Buffer.from([1, 2, 3]),
        counter: BigInt(5),
        transports: ['internal'],
        user: mockUser,
      } as any);

      vi.mocked(simpleWebAuthn.verifyAuthenticationResponse).mockResolvedValue({
        verified: true,
        authenticationInfo: {
          newCounter: 6,
          userVerified: true,
        },
      } as any);

      prismaMock.session.create.mockResolvedValue({
        id: 'sess_123',
        userId: 'usr_passkey_1',
      } as any);

      const mockClientDataJSON = Buffer.from(
        JSON.stringify({ challenge: 'valid_auth_chal' })
      ).toString('base64url');

      const res = await webAuthnService.verifyAuthentication({
        response: {
          id: 'cred_pk_1',
          response: { clientDataJSON: mockClientDataJSON },
        } as any,
        userAgent: 'test-agent',
        ipAddress: '127.0.0.1',
      });

      expect(res.user.id).toBe('usr_passkey_1');
      expect(res.accessToken).toBeDefined();
      expect(res.refreshToken).toBeDefined();
      expect(deleteCache).toHaveBeenCalledWith('webauthn:auth:valid_auth_chal');
      expect(mockAuditService.log).toHaveBeenCalled();
    });
  });

  describe('Authenticator Management', () => {
    it('should list authenticators for a user', async () => {
      const { prismaMock } = await import('@tests/mocks/prisma');

      prismaMock.authenticator.findMany.mockResolvedValue([
        {
          id: 'auth_1',
          credentialId: 'cred_1',
          name: 'YubiKey 5C',
          transports: ['usb'],
          deviceType: 'singleDevice',
          backedUp: false,
          aaguid: null,
          lastUsedAt: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ] as any);

      const list = await webAuthnService.listAuthenticators({ userId: 'usr_1' });
      expect(list).toHaveLength(1);
      expect(list[0].name).toBe('YubiKey 5C');
    });

    it('should delete an authenticator and log audit action', async () => {
      const { prismaMock } = await import('@tests/mocks/prisma');

      prismaMock.authenticator.findFirst.mockResolvedValue({
        id: 'auth_del_1',
        userId: 'usr_1',
        name: 'Old Key',
        credentialId: 'cred_del_1',
      } as any);

      const res = await webAuthnService.deleteAuthenticator({
        userId: 'usr_1',
        authenticatorId: 'auth_del_1',
      });

      expect(res.success).toBe(true);
      expect(prismaMock.authenticator.delete).toHaveBeenCalledWith({
        where: { id: 'auth_del_1' },
      });
      expect(mockAuditService.log).toHaveBeenCalled();
    });
  });
});

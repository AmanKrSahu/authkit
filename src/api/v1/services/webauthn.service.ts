import { AuditService } from '@api/v1/services/audit.service';
import { JWT_CONFIG } from '@core/common/constants/jwt.constant';
import { RATE_LIMIT } from '@core/common/constants/rate-limit.constant';
import { ErrorCodeEnum } from '@core/common/enums/error-code.enum';
import type {
  DeleteAuthenticatorData,
  GenerateAuthenticationOptionsData,
  GenerateRegistrationOptionsData,
  ListAuthenticatorsData,
  SanitizedAuthenticator,
  UpdateAuthenticatorNameData,
  VerifyAuthenticationData,
  VerifyAuthenticationForMfaData,
  VerifyRegistrationData,
} from '@core/common/interface/webauthn.interface';
import {
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
} from '@core/common/utils/app-error';
import { generateDeviceFingerprint, hashToken } from '@core/common/utils/crypto';
import { calculateExpirationDate } from '@core/common/utils/date-time';
import type { MFATPayload } from '@core/common/utils/jwt';
import {
  mfaTokenSignOptions,
  refreshTokenSignOptions,
  signJwtToken,
  verifyJwtToken,
} from '@core/common/utils/jwt';
import {
  checkForNewDevice,
  checkLoginLockout,
  checkMfaRateLimit,
  clearLoginLockout,
  clearMfaRateLimit,
  incrementLoginFailedAttempts,
  incrementMfaRateLimit,
} from '@core/common/utils/metadata';
import { deleteCache, getCache, setCache } from '@core/common/utils/redis-helpers';
import { sanitizeUser } from '@core/common/utils/sanitize';
import {
  getAuthChallengeKey,
  getRegistrationChallengeKey,
  getWebAuthnExpectedOrigins,
  getWebAuthnRpID,
  getWebAuthnRpName,
  sanitizeAuthenticatorRecord,
  WEBAUTHN_CHALLENGE_TTL_SECONDS,
} from '@core/common/utils/webauthn.util';
import prisma from '@core/database/prisma';
import { EmailService } from '@core/mailers/resend';
import { AuditAction, AuditStatus } from '@prisma/client';
import type {
  AuthenticatorTransport,
  PublicKeyCredentialDescriptorJSON,
} from '@simplewebauthn/server';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

export class WebAuthnService {
  private emailService: EmailService;
  private auditService: AuditService;

  constructor(
    emailService: EmailService = new EmailService(),
    auditService: AuditService = new AuditService()
  ) {
    this.emailService = emailService;
    this.auditService = auditService;
  }

  public async generateRegistrationOptions(
    generateRegistrationOptionsData: GenerateRegistrationOptionsData
  ) {
    const { userId } = generateRegistrationOptionsData;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { authenticators: true },
    });

    if (!user) {
      throw new UnauthorizedException('User not authorized');
    }

    const options = await generateRegistrationOptions({
      rpName: getWebAuthnRpName(),
      rpID: getWebAuthnRpID(),
      userID: Buffer.from(user.id, 'utf8'),
      userName: user.email,
      userDisplayName: user.name,
      attestationType: 'none',
      excludeCredentials: user.authenticators.map(auth => ({
        id: auth.credentialId,
        type: 'public-key' as const,
        transports: auth.transports as AuthenticatorTransport[],
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    // Store challenge in Redis bound to the user
    const cacheKey = getRegistrationChallengeKey(user.id, options.challenge);
    await setCache(cacheKey, options.challenge, WEBAUTHN_CHALLENGE_TTL_SECONDS);

    return options;
  }

  public async verifyRegistration(verifyRegistrationData: VerifyRegistrationData) {
    const { userId, response, name, userAgent, ipAddress } = verifyRegistrationData;

    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new UnauthorizedException('User not authorized');
    }

    // Retrieve and validate challenge from Redis
    const clientDataJSON = response.response?.clientDataJSON;
    let challenge: string | undefined;

    if (clientDataJSON) {
      try {
        const parsed = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'));
        challenge = parsed.challenge;
      } catch {
        // Handled below
      }
    }

    if (!challenge) {
      throw new BadRequestException(
        'Invalid WebAuthn response payload',
        ErrorCodeEnum.WEBAUTHN_VERIFICATION_FAILED
      );
    }

    const cacheKey = getRegistrationChallengeKey(user.id, challenge);
    const expectedChallenge = await getCache(cacheKey);

    if (!expectedChallenge) {
      throw new BadRequestException(
        'Registration challenge expired or invalid',
        ErrorCodeEnum.WEBAUTHN_CHALLENGE_EXPIRED
      );
    }

    // Check if credential ID already exists globally
    const existingCredential = await prisma.authenticator.findUnique({
      where: { credentialId: response.id },
    });

    if (existingCredential) {
      throw new BadRequestException(
        'This authenticator credential has already been registered',
        ErrorCodeEnum.WEBAUTHN_CREDENTIAL_ALREADY_REGISTERED
      );
    }

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response,
        expectedChallenge,
        expectedOrigin: getWebAuthnExpectedOrigins(),
        expectedRPID: getWebAuthnRpID(),
        requireUserVerification: false,
      });
    } catch (error: unknown) {
      throw new BadRequestException(
        (error as Error)?.message ?? 'WebAuthn registration verification failed',
        ErrorCodeEnum.WEBAUTHN_VERIFICATION_FAILED
      );
    }

    const { verified, registrationInfo } = verification;

    if (!verified || !registrationInfo) {
      throw new BadRequestException(
        'WebAuthn registration could not be verified',
        ErrorCodeEnum.WEBAUTHN_VERIFICATION_FAILED
      );
    }

    const { credential, credentialDeviceType, credentialBackedUp, aaguid } = registrationInfo;

    const authenticator = await prisma.authenticator.create({
      data: {
        userId: user.id,
        credentialId: credential.id,
        credentialPublicKey: Buffer.from(credential.publicKey),
        counter: BigInt(credential.counter),
        transports: (credential.transports as string[]) ?? [],
        name: name ?? (credentialDeviceType === 'multiDevice' ? 'Passkey' : 'Security Key'),
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        aaguid: aaguid || null,
      },
    });

    // Consume challenge
    await deleteCache(cacheKey);

    await this.auditService.log({
      userId: user.id,
      action: AuditAction.WEBAUTHN_REGISTER,
      entityType: 'Authenticator',
      entityId: authenticator.id,
      description: `Registered WebAuthn passkey: ${authenticator.name}`,
      status: AuditStatus.SUCCESS,
      ipAddress,
      userAgent,
      metadata: {
        credentialId: authenticator.credentialId,
        deviceType: credentialDeviceType,
      },
    });

    return {
      verified: true,
      authenticator: sanitizeAuthenticatorRecord(authenticator),
    };
  }

  public async generateAuthenticationOptions(
    generateAuthenticationOptionsData: GenerateAuthenticationOptionsData = {}
  ) {
    const { email, userId } = generateAuthenticationOptionsData;

    let allowCredentials: PublicKeyCredentialDescriptorJSON[] | undefined;

    if (email || userId) {
      const user = await prisma.user.findFirst({
        where: email ? { email } : { id: userId },
        include: { authenticators: true },
      });

      if (user && user.authenticators.length > 0) {
        allowCredentials = user.authenticators.map(auth => ({
          id: auth.credentialId,
          type: 'public-key' as const,
          transports: auth.transports as AuthenticatorTransport[],
        }));
      }
    }

    const options = await generateAuthenticationOptions({
      rpID: getWebAuthnRpID(),
      allowCredentials,
      userVerification: 'preferred',
    });

    // Store challenge in Redis
    const cacheKey = getAuthChallengeKey(options.challenge);
    await setCache(cacheKey, options.challenge, WEBAUTHN_CHALLENGE_TTL_SECONDS);

    return options;
  }

  public async verifyAuthentication(verifyAuthenticationData: VerifyAuthenticationData) {
    const { response, userAgent, ipAddress } = verifyAuthenticationData;

    // Retrieve challenge from clientDataJSON
    const clientDataJSON = response.response?.clientDataJSON;
    let challenge: string | undefined;

    if (clientDataJSON) {
      try {
        const parsed = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'));
        challenge = parsed.challenge;
      } catch {
        // Handled below
      }
    }

    if (!challenge) {
      throw new BadRequestException(
        'Invalid WebAuthn response payload',
        ErrorCodeEnum.WEBAUTHN_VERIFICATION_FAILED
      );
    }

    const cacheKey = getAuthChallengeKey(challenge);
    const expectedChallenge = await getCache(cacheKey);

    if (!expectedChallenge) {
      throw new BadRequestException(
        'Authentication challenge expired or invalid',
        ErrorCodeEnum.WEBAUTHN_CHALLENGE_EXPIRED
      );
    }

    // Lookup authenticator by credentialId
    const authenticator = await prisma.authenticator.findUnique({
      where: { credentialId: response.id },
      include: { user: true },
    });

    if (!authenticator) {
      throw new NotFoundException(
        'Passkey credential not found',
        ErrorCodeEnum.WEBAUTHN_CREDENTIAL_NOT_FOUND
      );
    }

    const user = authenticator.user;

    await checkLoginLockout(user.email);

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: getWebAuthnExpectedOrigins(),
        expectedRPID: getWebAuthnRpID(),
        credential: {
          id: authenticator.credentialId,
          publicKey: new Uint8Array(authenticator.credentialPublicKey),
          counter: Number(authenticator.counter),
          transports: authenticator.transports as AuthenticatorTransport[],
        },
        requireUserVerification: false,
      });
    } catch (error: unknown) {
      await incrementLoginFailedAttempts(user.email);
      const errorMessage = (error as Error)?.message ?? 'Verification error';
      await this.auditService.log({
        userId: user.id,
        action: AuditAction.FAILED_LOGIN,
        entityType: 'User',
        entityId: user.id,
        description: `Failed WebAuthn authentication: ${errorMessage}`,
        status: AuditStatus.FAILURE,
        ipAddress,
        userAgent,
        metadata: { credentialId: authenticator.credentialId },
      });
      throw new BadRequestException(
        (error as Error)?.message ?? 'WebAuthn assertion verification failed',
        ErrorCodeEnum.WEBAUTHN_VERIFICATION_FAILED
      );
    }

    const { verified, authenticationInfo } = verification;

    if (!verified || !authenticationInfo) {
      await incrementLoginFailedAttempts(user.email);
      throw new BadRequestException(
        'WebAuthn assertion could not be verified',
        ErrorCodeEnum.WEBAUTHN_VERIFICATION_FAILED
      );
    }

    // Update authenticator counter and lastUsedAt
    await prisma.authenticator.update({
      where: { id: authenticator.id },
      data: {
        counter: BigInt(authenticationInfo.newCounter),
        lastUsedAt: new Date(),
      },
    });

    // Clear challenge and login lockout
    await deleteCache(cacheKey);
    await clearLoginLockout(user.email);

    // Create session
    const deviceFingerprint = generateDeviceFingerprint(userAgent, ipAddress);
    const isNewDevice = await checkForNewDevice(user.id, deviceFingerprint);
    const expiresAt = calculateExpirationDate(JWT_CONFIG.REFRESH_EXPIRES_IN);

    const session = await prisma.session.create({
      data: {
        userId: user.id,
        expiresAt,
        ipAddress,
        userAgent,
        deviceFingerprint,
        isNewDevice,
      },
    });

    if (isNewDevice) {
      await this.emailService.sendNewDeviceNotification(
        user.email,
        {
          deviceInfo: userAgent,
          ipAddress,
          loginTime: new Date(),
        },
        user.name
      );
    }

    const accessToken = signJwtToken({ userId: user.id, sessionId: session.id });
    const refreshToken = signJwtToken({ sessionId: session.id }, refreshTokenSignOptions);

    // Store refresh token hash in Redis
    const refreshTokenHash = hashToken(refreshToken);
    await setCache(
      `active_refresh_token:${session.id}`,
      refreshTokenHash,
      JWT_CONFIG.REFRESH_EXPIRES_IN
    );

    await this.auditService.log({
      userId: user.id,
      action: AuditAction.WEBAUTHN_AUTHENTICATE,
      entityType: 'User',
      entityId: user.id,
      description: 'User logged in successfully via WebAuthn passkey',
      status: AuditStatus.SUCCESS,
      ipAddress,
      userAgent,
      metadata: { credentialId: authenticator.credentialId },
    });

    return {
      user: sanitizeUser(user),
      accessToken,
      refreshToken,
    };
  }

  public async verifyAuthenticationForMfa(
    verifyAuthenticationForMfaData: VerifyAuthenticationForMfaData
  ) {
    const { response, mfaLoginToken, userAgent, ipAddress } = verifyAuthenticationForMfaData;

    const { payload } = verifyJwtToken<MFATPayload>(mfaLoginToken, {
      secret: mfaTokenSignOptions.secret,
    });

    if (!payload) {
      throw new UnauthorizedException('Invalid or expired login token');
    }

    const cacheKeyNonce = `mfa_login_nonce:${payload.userId}:${payload.nonce}`;
    const nonceExists = await getCache(cacheKeyNonce);

    if (!nonceExists) {
      throw new UnauthorizedException('MFA login challenge has expired or been replayed');
    }

    const clientDataJSON = response.response?.clientDataJSON;
    let challenge: string | undefined;

    if (clientDataJSON) {
      try {
        const parsed = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'));
        challenge = parsed.challenge;
      } catch {
        // Handled below
      }
    }

    if (!challenge) {
      throw new BadRequestException(
        'Invalid WebAuthn response payload',
        ErrorCodeEnum.WEBAUTHN_VERIFICATION_FAILED
      );
    }

    const cacheKeyAuth = getAuthChallengeKey(challenge);
    const expectedChallenge = await getCache(cacheKeyAuth);

    if (!expectedChallenge) {
      throw new BadRequestException(
        'Authentication challenge expired or invalid',
        ErrorCodeEnum.WEBAUTHN_CHALLENGE_EXPIRED
      );
    }

    const authenticator = await prisma.authenticator.findUnique({
      where: { credentialId: response.id },
      include: { user: true },
    });

    if (authenticator?.userId !== payload.userId) {
      throw new BadRequestException(
        'Authenticator not registered to this account',
        ErrorCodeEnum.WEBAUTHN_CREDENTIAL_NOT_FOUND
      );
    }

    const user = authenticator.user;
    const mfaAttempts = await checkMfaRateLimit(user.id, RATE_LIMIT.MFA.MAX_ATTEMPTS);

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: getWebAuthnExpectedOrigins(),
        expectedRPID: getWebAuthnRpID(),
        credential: {
          id: authenticator.credentialId,
          publicKey: new Uint8Array(authenticator.credentialPublicKey),
          counter: Number(authenticator.counter),
          transports: authenticator.transports as AuthenticatorTransport[],
        },
        requireUserVerification: false,
      });
    } catch {
      const remainingAttempts = RATE_LIMIT.MFA.MAX_ATTEMPTS - (mfaAttempts + 1);
      await incrementMfaRateLimit(user.id);
      throw new BadRequestException(
        `Invalid MFA WebAuthn assertion. ${remainingAttempts} attempt(s) remaining.`
      );
    }

    const { verified, authenticationInfo } = verification;

    if (!verified || !authenticationInfo) {
      const remainingAttempts = RATE_LIMIT.MFA.MAX_ATTEMPTS - (mfaAttempts + 1);
      await incrementMfaRateLimit(user.id);
      throw new BadRequestException(
        `Invalid MFA WebAuthn assertion. ${remainingAttempts} attempt(s) remaining.`
      );
    }

    await prisma.authenticator.update({
      where: { id: authenticator.id },
      data: {
        counter: BigInt(authenticationInfo.newCounter),
        lastUsedAt: new Date(),
      },
    });

    await clearMfaRateLimit(user.id);
    await deleteCache(cacheKeyNonce);
    await deleteCache(cacheKeyAuth);

    const deviceFingerprint = generateDeviceFingerprint(userAgent, ipAddress);
    const isNewDevice = await checkForNewDevice(user.id, deviceFingerprint);
    const expiresAt = calculateExpirationDate(JWT_CONFIG.REFRESH_EXPIRES_IN);

    const session = await prisma.session.create({
      data: {
        userId: user.id,
        expiresAt,
        ipAddress,
        userAgent,
        deviceFingerprint,
        isNewDevice,
      },
    });

    if (isNewDevice) {
      await this.emailService.sendNewDeviceNotification(
        user.email,
        {
          deviceInfo: userAgent,
          ipAddress,
          loginTime: new Date(),
        },
        user.name
      );
    }

    const accessToken = signJwtToken({ userId: user.id, sessionId: session.id });
    const refreshToken = signJwtToken({ sessionId: session.id }, refreshTokenSignOptions);

    const refreshTokenHash = hashToken(refreshToken);
    await setCache(
      `active_refresh_token:${session.id}`,
      refreshTokenHash,
      JWT_CONFIG.REFRESH_EXPIRES_IN
    );

    await this.auditService.log({
      userId: user.id,
      action: AuditAction.WEBAUTHN_AUTHENTICATE,
      entityType: 'User',
      entityId: user.id,
      description: 'MFA verified successfully via WebAuthn passkey',
      status: AuditStatus.SUCCESS,
      ipAddress,
      userAgent,
      metadata: { credentialId: authenticator.credentialId },
    });

    return {
      user: sanitizeUser(user),
      accessToken,
      refreshToken,
    };
  }

  public async listAuthenticators(
    listAuthenticatorsData: ListAuthenticatorsData
  ): Promise<SanitizedAuthenticator[]> {
    const { userId } = listAuthenticatorsData;

    const authenticators = await prisma.authenticator.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });

    return authenticators.map(sanitizeAuthenticatorRecord);
  }

  public async deleteAuthenticator(deleteAuthenticatorData: DeleteAuthenticatorData) {
    const { userId, authenticatorId } = deleteAuthenticatorData;

    const authenticator = await prisma.authenticator.findFirst({
      where: { id: authenticatorId, userId },
    });

    if (!authenticator) {
      throw new NotFoundException('Authenticator not found');
    }

    await prisma.authenticator.delete({
      where: { id: authenticator.id },
    });

    await this.auditService.log({
      userId,
      action: AuditAction.WEBAUTHN_DELETE,
      entityType: 'Authenticator',
      entityId: authenticator.id,
      description: `Deleted WebAuthn authenticator: ${authenticator.name}`,
      status: AuditStatus.SUCCESS,
      metadata: { credentialId: authenticator.credentialId },
    });

    return { success: true };
  }

  public async updateAuthenticatorName(
    updateAuthenticatorNameData: UpdateAuthenticatorNameData
  ): Promise<SanitizedAuthenticator> {
    const { userId, authenticatorId, name } = updateAuthenticatorNameData;

    const authenticator = await prisma.authenticator.findFirst({
      where: { id: authenticatorId, userId },
    });

    if (!authenticator) {
      throw new NotFoundException('Authenticator not found');
    }

    const updated = await prisma.authenticator.update({
      where: { id: authenticator.id },
      data: { name },
    });

    return sanitizeAuthenticatorRecord(updated);
  }
}

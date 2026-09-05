import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';

export interface GenerateRegistrationOptionsData {
  userId: string;
}

export interface VerifyRegistrationData {
  userId: string;
  response: RegistrationResponseJSON;
  name?: string;
  userAgent?: string;
  ipAddress?: string;
}

export interface GenerateAuthenticationOptionsData {
  email?: string;
  userId?: string;
}

export interface VerifyAuthenticationData {
  response: AuthenticationResponseJSON;
  userAgent: string;
  ipAddress: string;
}

export interface VerifyAuthenticationForMfaData {
  response: AuthenticationResponseJSON;
  mfaLoginToken: string;
  userAgent: string;
  ipAddress: string;
}

export interface ListAuthenticatorsData {
  userId: string;
}

export interface DeleteAuthenticatorData {
  userId: string;
  authenticatorId: string;
}

export interface UpdateAuthenticatorNameData {
  userId: string;
  authenticatorId: string;
  name: string;
}

export interface OidcWebAuthnOptionsData {
  uid: string;
  email?: string;
}

export interface OidcWebAuthnVerifyData {
  uid: string;
  response: AuthenticationResponseJSON;
  userAgent: string;
  ipAddress: string;
}

export interface SanitizedAuthenticator {
  id: string;
  credentialId: string;
  name: string | null;
  transports: string[];
  deviceType: string | null;
  backedUp: boolean;
  aaguid: string | null;
  lastUsedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

import crypto from 'node:crypto';

import { config } from '@core/config/app.config';

const ALGORITHM = 'aes-256-gcm';

export const encrypt = (text: string): string => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, config.AUTHENTICATOR_APP_SECRET, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  // Format: iv:authTag:encrypted
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
};

export const decrypt = (text: string): string => {
  const parts = text.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted text format');
  }

  const [ivHex, authTagHex, encryptedHex] = parts;

  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, config.AUTHENTICATOR_APP_SECRET, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
};

export const generateRandomToken = (): string => {
  return crypto.randomBytes(32).toString('hex');
};

export const generateSessionToken = (): string => {
  return crypto.randomBytes(64).toString('hex');
};

export const generateOTP = (length: number = 6): string => {
  const digits = '0123456789';
  let otp = '';
  for (let i = 0; i < length; i++) {
    otp += digits[Math.floor(Math.random() * digits.length)];
  }
  return otp;
};

export const isTokenExpired = (expiresAt: Date): boolean => {
  return new Date() > expiresAt;
};

export const generateDeviceFingerprint = (userAgent: string, ipAddress: string): string => {
  const fingerprintData = `${userAgent}-${ipAddress}`;
  return crypto.createHash('sha256').update(fingerprintData).digest('hex');
};

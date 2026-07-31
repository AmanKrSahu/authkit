import crypto from 'node:crypto';

import { config } from '@core/config/app.config';

const ALGORITHM = 'aes-256-gcm';

export const encrypt = (text: string): string => {
  const iv = crypto.randomBytes(16);
  const key = crypto.createHash('sha256').update(config.AUTHENTICATOR_APP_SECRET).digest();

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

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

  const key = crypto.createHash('sha256').update(config.AUTHENTICATOR_APP_SECRET).digest();

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
};

export const generateRandomToken = (): string => {
  return crypto.randomBytes(32).toString('hex');
};

export const hashToken = (token: string): string => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

export const generateOTP = (length: number = 6): string => {
  let otp = '';
  for (let i = 0; i < length; i++) {
    otp += crypto.randomInt(0, 10).toString();
  }
  return otp;
};

export const timingSafeCompare = (a: string, b: string): boolean => {
  const hashA = crypto.createHash('sha256').update(a).digest();
  const hashB = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(hashA, hashB);
};

export const isTokenExpired = (expiresAt: Date): boolean => {
  return new Date() > expiresAt;
};

export const generateBackupCode = (): string => {
  const buffer = crypto.randomBytes(10);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return `${output.slice(0, 8)}-${output.slice(8, 16)}`;
};

export const normalizeBackupCode = (code: string): string => {
  const stripped = code.replaceAll(/[\s-]/g, '').toUpperCase();
  if (stripped.length === 16) {
    return `${stripped.slice(0, 8)}-${stripped.slice(8, 16)}`;
  }
  return code;
};

export const generateDeviceFingerprint = (userAgent: string, ipAddress: string): string => {
  const fingerprintData = `${userAgent}-${ipAddress}`;
  return crypto.createHash('sha256').update(fingerprintData).digest('hex');
};

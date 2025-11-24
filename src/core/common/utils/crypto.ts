import crypto from 'node:crypto';

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

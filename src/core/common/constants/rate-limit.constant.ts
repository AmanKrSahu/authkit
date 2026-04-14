import {
  FIFTEEN_MINUTES_IN_MS,
  ONE_HOUR_IN_MS,
  TEN_MINUTES_IN_MS,
} from '@core/common/utils/date-time';

export const RATE_LIMIT = {
  // Global API Protection (General DoS prevention)
  GLOBAL: {
    MAX_REQUESTS: 200,
    WINDOW_MS: FIFTEEN_MINUTES_IN_MS,
  },

  // Authentication (Brute-force protection for Login/Register)
  AUTH: {
    MAX_REQUESTS: 5,
    WINDOW_MS: FIFTEEN_MINUTES_IN_MS,
  },

  // OIDC Identity Provider (Handles multi-step handshakes)
  OIDC: {
    MAX_REQUESTS: 100,
    WINDOW_MS: FIFTEEN_MINUTES_IN_MS,
  },

  // Multi-Factor Authentication Verification
  MFA: {
    MAX_ATTEMPTS: 5,
    LOCKOUT_MS: ONE_HOUR_IN_MS,
  },

  // One-Time Passwords (Forgot Password, Email Verification)
  OTP: {
    MAX_REQUESTS: 3,
    MAX_VERIFICATION_ATTEMPTS: 3,
    EXPIRY_MS: TEN_MINUTES_IN_MS,
    WINDOW_MS: ONE_HOUR_IN_MS,
  },
};

import { config } from '@core/config/app.config';

import { logger } from './logger';

/**
 * Checks if an origin is allowed by the security policy (CORS, CSRF, and Redirects).
 *
 * @param origin The origin to check (e.g. "https://tenant.yourdomain.com")
 * @returns true if allowed, false otherwise
 */
export const isAllowedOrigin = (origin?: string): boolean => {
  if (!origin) return false;

  const normalized = origin.toLowerCase().trim();

  // 1. Development: Allow any localhost/127.0.0.1 origin on any port
  if (
    config.NODE_ENV !== 'production' &&
    (normalized.startsWith('http://localhost:') ||
      normalized.startsWith('http://127.0.0.1:') ||
      normalized === 'http://localhost' ||
      normalized === 'http://127.0.0.1')
  ) {
    return true;
  }

  // 2. Static Whitelist: Allow exact matches in FRONTEND_ORIGINS config
  if (config.FRONTEND_ORIGINS.some(o => o.trim().toLowerCase() === normalized)) {
    return true;
  }

  // 3. Multi-Tenant Subdomain Matching: Allow https://*.yourdomain.com
  if (config.DOMAIN_URL) {
    try {
      const url = new URL(normalized);

      // Strict Protocol: Only allow HTTPS in production for wildcard subdomains
      const isAllowedProtocol =
        config.NODE_ENV === 'production'
          ? url.protocol === 'https:'
          : url.protocol === 'http:' || url.protocol === 'https:';

      if (isAllowedProtocol) {
        const targetDomain = config.DOMAIN_URL.toLowerCase().trim();
        const suffix = `.${targetDomain}`;

        // Matches exact root domain (yourdomain.com) or any subdomain (*.yourdomain.com)
        if (url.hostname === targetDomain || url.hostname.endsWith(suffix)) {
          return true;
        }
      }
    } catch {
      return false;
    }
  }

  return false;
};

/**
 * Validates a requested redirect URL against the allowed FRONTEND_ORIGINS whitelist.
 * Returns the requested URL if it's safe and allowed, otherwise falls back to the default origin.
 *
 * @param requestedUrl The URL the client requested to redirect to
 * @returns A safe, validated redirection URL
 */
export const getValidRedirectUrl = (requestedUrl?: string): string => {
  const defaultOrigin = config.FRONTEND_ORIGINS[0];

  if (!requestedUrl) {
    return defaultOrigin;
  }

  try {
    const url = new URL(requestedUrl);

    // Validate using the unified origin checker
    if (isAllowedOrigin(url.origin)) {
      return requestedUrl; // It's safe, allow the exact requested path/query
    }

    logger.warn(`Rejected redirect URL: ${requestedUrl}. Origin ${url.origin} is not allowed.`);
    return defaultOrigin;
  } catch {
    // If URL parsing fails, it's malformed or partial. Fallback to default.
    return defaultOrigin;
  }
};

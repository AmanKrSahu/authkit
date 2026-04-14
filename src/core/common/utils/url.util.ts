import { config } from '@core/config/app.config';

import { logger } from './logger';

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

    // Check if the exact origin is in our whitelist
    if (config.FRONTEND_ORIGINS.includes(url.origin)) {
      return requestedUrl; // It's safe, allow the exact requested path/query
    }

    logger.warn(
      `Rejected redirect URL: ${requestedUrl}. Origin ${url.origin} is not in whitelist.`
    );
    return defaultOrigin;
  } catch {
    // If URL parsing fails, it's malformed or partial. Fallback to default.
    return defaultOrigin;
  }
};

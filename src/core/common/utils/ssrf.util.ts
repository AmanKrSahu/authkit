import dns from 'node:dns/promises';
import net from 'node:net';

import { HTTPSTATUS } from '../../config/http.config';
import { AppError } from './app-error';

/**
 * Checks whether an IPv4 address is in a private, loopback, or link-local range.
 */
export function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => Number.isNaN(p) || p < 0 || p > 255)) {
    return false;
  }

  const [b0, b1] = parts;

  // 127.0.0.0/8 (Loopback)
  if (b0 === 127) return true;

  // 10.0.0.0/8 (Private network)
  if (b0 === 10) return true;

  // 172.16.0.0/12 (Private network: 172.16.0.0 - 172.31.255.255)
  if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;

  // 192.168.0.0/16 (Private network)
  if (b0 === 192 && b1 === 168) return true;

  // 169.254.0.0/16 (Link-local / Cloud metadata endpoint 169.254.169.254)
  if (b0 === 169 && b1 === 254) return true;

  // 0.0.0.0/8 (Broadcast/Current network)
  if (b0 === 0) return true;

  return false;
}

/**
 * Checks whether an IPv6 address is loopback, link-local, or unique local.
 */
export function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  if (normalized === '::1' || normalized === '::') return true;

  // fe80::/10 (Link-local)
  if (normalized.startsWith('fe80:')) return true;

  // fc00::/7 (Unique local)
  if (normalized.startsWith('fc00:') || normalized.startsWith('fd00:')) return true;

  return false;
}

/**
 * Validates a target webhook URL to prevent SSRF vulnerabilities.
 */
export async function validateWebhookUrl(urlStr: string): Promise<void> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(urlStr);
  } catch {
    throw new AppError('Invalid webhook URL format', HTTPSTATUS.BAD_REQUEST);
  }

  const isTestOrDev =
    process.env.NODE_ENV === 'test' ||
    process.env.NODE_ENV === 'development' ||
    process.env.ALLOW_HTTP_WEBHOOKS === 'true';

  // Enforce HTTPS unless running in test/dev environment
  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    throw new AppError('Webhook URL must use the HTTPS protocol', HTTPSTATUS.BAD_REQUEST);
  }

  if (parsedUrl.protocol === 'http:' && !isTestOrDev) {
    throw new AppError(
      'Webhook URL must use the HTTPS protocol in production environments',
      HTTPSTATUS.BAD_REQUEST
    );
  }

  const hostname = parsedUrl.hostname.toLowerCase();

  // Allow localhost targets in unit/integration test mode
  if (isTestOrDev && (hostname === 'localhost' || hostname === '127.0.0.1')) {
    return;
  }

  // Disallow obvious localhost hostname aliases in production
  if (hostname === 'localhost' || hostname === '0.0.0.0' || hostname === '[::1]') {
    throw new AppError('Webhook URL targeting localhost is restricted', HTTPSTATUS.BAD_REQUEST);
  }

  // Check if direct IP address
  if (net.isIP(hostname)) {
    if (net.isIPv4(hostname) && isPrivateIPv4(hostname)) {
      throw new AppError(
        'Webhook URL targeting private/internal IP ranges is restricted',
        HTTPSTATUS.BAD_REQUEST
      );
    }
    if (net.isIPv6(hostname) && isPrivateIPv6(hostname)) {
      throw new AppError(
        'Webhook URL targeting private/internal IPv6 ranges is restricted',
        HTTPSTATUS.BAD_REQUEST
      );
    }
    return;
  }

  // Resolve hostname via DNS to verify target IP isn't internal/private (DNS rebinding protection)
  try {
    const addresses = await dns.resolve(hostname);
    for (const address of addresses) {
      if (net.isIPv4(address) && isPrivateIPv4(address)) {
        throw new AppError(
          'Webhook URL hostname resolves to a restricted private IP address',
          HTTPSTATUS.BAD_REQUEST
        );
      }
      if (net.isIPv6(address) && isPrivateIPv6(address)) {
        throw new AppError(
          'Webhook URL hostname resolves to a restricted private IPv6 address',
          HTTPSTATUS.BAD_REQUEST
        );
      }
    }
  } catch (error) {
    if (error instanceof AppError) throw error;
    // Allow unresolvable hostnames in test environment if mock DNS
    if (!isTestOrDev) {
      throw new AppError(
        'Failed to resolve webhook URL hostname for security verification',
        HTTPSTATUS.BAD_REQUEST
      );
    }
  }
}

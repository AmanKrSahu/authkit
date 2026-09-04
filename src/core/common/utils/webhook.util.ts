import crypto from 'node:crypto';

import type {
  ExecuteDeliveryHttpParams,
  WebhookDeliveryAttemptResult,
} from '../interface/webhook.interface';

export const MAX_WEBHOOK_RETRIES = 5;
export const HTTP_TIMEOUT_MS = 5000;
export const SENSITIVE_RESPONSE_KEYS = new Set([
  'password',
  'token',
  'secret',
  'authorization',
  'cookie',
]);

/**
 * Generates a cryptographically secure random signing secret prefixed with 'whsec_'.
 */
export function generateSigningSecret(): string {
  return `whsec_${crypto.randomBytes(24).toString('hex')}`;
}

/**
 * Computes HMAC-SHA256 signature for a payload and timestamp using the secret.
 */
export function generateSignature(
  payloadString: string,
  secret: string,
  timestamp: number
): string {
  const signaturePayload = `${timestamp}.${payloadString}`;
  return crypto.createHmac('sha256', secret).update(signaturePayload).digest('hex');
}

/**
 * Redacts sensitive tokens and truncates response body to at most 1KB.
 */
export function redactResponseBody(bodyText: string | null | undefined): string | null {
  if (!bodyText) return null;
  let text = bodyText.slice(0, 1024); // Truncate to max 1KB
  for (const key of SENSITIVE_RESPONSE_KEYS) {
    const regex = new RegExp(String.raw`("${key}"\s*:\s*")[^"]+(")`, 'gi');
    text = text.replace(regex, '$1[REDACTED]$2');
  }
  return text;
}

/**
 * Calculates exponential backoff delay based on retry attempt number or Retry-After header.
 */
export function calculateBackoffDelayMs(
  attemptNumber: number,
  retryAfterHeader?: string | null
): number {
  if (retryAfterHeader) {
    const seconds = Number.parseInt(retryAfterHeader, 10);
    if (!Number.isNaN(seconds) && seconds > 0) {
      return Math.min(seconds * 1000, 3_600_000); // Cap at 1 hour
    }
  }
  // Exponential backoff: Attempt 1 -> 10s, Attempt 2 -> 60s, Attempt 3 -> 5m, Attempt 4 -> 15m
  const delays = [10_000, 60_000, 300_000, 900_000];
  return delays[attemptNumber - 1] ?? 1_800_000;
}

/**
 * Executes outbound HTTP POST request to subscriber URL with HMAC headers.
 */
export async function executeDeliveryHttp(
  params: ExecuteDeliveryHttpParams
): Promise<WebhookDeliveryAttemptResult> {
  const { url, secret, previousSecret, previousSecretExpiresAt, envelope } = params;

  const payloadStr = JSON.stringify(envelope);
  const timestamp = Math.floor(Date.now() / 1000);

  const primarySignature = generateSignature(payloadStr, secret, timestamp);
  let signatureHeader = `t=${timestamp},v1=${primarySignature}`;

  // Append rotation signature if previous secret is within 24h grace window
  if (previousSecret && previousSecretExpiresAt && new Date() < new Date(previousSecretExpiresAt)) {
    const oldSignature = generateSignature(payloadStr, previousSecret, timestamp);
    signatureHeader += `,v1_old=${oldSignature}`;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);
  const startTime = Date.now();

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'AuthKit-WebhookDelivery/1.0',
        'X-Webhook-Id': envelope.id,
        'X-Webhook-Timestamp': timestamp.toString(),
        'X-Webhook-Event': envelope.type,
        'X-Webhook-Signature': signatureHeader,
      },
      body: payloadStr,
      signal: controller.signal,
    });

    const duration = Date.now() - startTime;
    clearTimeout(timeoutId);

    const rawBody = await response.text().catch(() => '');
    const responseBody = redactResponseBody(rawBody);

    if (response.ok) {
      return {
        success: true,
        httpStatus: response.status,
        duration,
        responseBody: responseBody ?? undefined,
      };
    }

    return {
      success: false,
      httpStatus: response.status,
      duration,
      errorCode: `HTTP_${response.status}`,
      errorMessage: `Subscriber endpoint returned HTTP ${response.status}`,
      responseBody: responseBody ?? undefined,
    };
  } catch (error: unknown) {
    const duration = Date.now() - startTime;
    clearTimeout(timeoutId);

    const errObj = error as { name?: string; message?: string };
    const isAbort = errObj.name === 'AbortError';
    return {
      success: false,
      duration,
      errorCode: isAbort ? 'TIMEOUT' : 'FETCH_ERROR',
      errorMessage: isAbort
        ? 'Delivery timed out after 5000ms'
        : (errObj.message ?? 'Fetch failed'),
    };
  }
}

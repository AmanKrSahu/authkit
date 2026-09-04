# AuthKit Webhooks Integrator Guide

AuthKit provides an event-driven webhook notification platform that delivers real-time HTTP POST notifications to external platforms and subscriber applications.

---

## 1. Event Envelope Format

Every webhook payload delivered by AuthKit conforms to a standardized JSON envelope:

```json
{
  "id": "evt_clx1234567890",
  "type": "user.created",
  "version": 1,
  "timestamp": "2026-08-23T13:45:00.000Z",
  "data": {
    "userId": "usr_12345",
    "entityType": "User",
    "description": "New user registered"
  }
}
```

### Event Envelope Fields

| Field       | Type    | Description                                                                 |
| :---------- | :------ | :-------------------------------------------------------------------------- |
| `id`        | String  | Unique event ID (`evt_...`). Reused across all retries for deduplication.   |
| `type`      | String  | Dot-notation event type (e.g. `user.created`, `user.login`, `mfa.enabled`). |
| `version`   | Integer | Event schema version (currently `1`).                                       |
| `timestamp` | String  | ISO 8601 UTC timestamp when the event was emitted.                          |
| `data`      | Object  | Event payload containing non-sensitive details.                             |

---

## 2. HTTP Request Headers & HMAC-SHA256 Signature Verification

AuthKit signs every outgoing HTTP POST request with an HMAC-SHA256 signature using the endpoint's secret key (`whsec_...`).

### Headers Sent

```http
POST /your-webhook-receiver HTTP/1.1
Host: api.yourcompany.com
Content-Type: application/json
User-Agent: AuthKit-WebhookDelivery/1.0
X-Webhook-Id: evt_clx1234567890
X-Webhook-Timestamp: 1700000000
X-Webhook-Event: user.created
X-Webhook-Signature: t=1700000000,v1=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

### Signature Verification Algorithm

To verify that an incoming request originated from AuthKit and has not been tampered with:

1. Extract the `X-Webhook-Timestamp` header (`t`) and `X-Webhook-Signature` header.
2. Verify that the timestamp is within your allowed clock-skew threshold (e.g. 5 minutes) to protect against replay attacks.
3. Compute HMAC-SHA256 hex string over the canonical string:
   $$\text{canonicalPayload} = \text{X-Webhook-Timestamp} + "." + \text{raw_http_body}$$
4. Compare your computed HMAC hex signature against the `v1` value in the `X-Webhook-Signature` header using timing-safe string comparison.

#### Node.js Verification Example

```typescript
import crypto from 'node:crypto';

export function verifyWebhookSignature(
  rawBody: string,
  signatureHeader: string,
  secret: string,
  toleranceSeconds = 300
): boolean {
  const parts = Object.fromEntries(signatureHeader.split(',').map(item => item.split('=')));

  const timestamp = Number.parseInt(parts.t, 10);
  const receivedSig = parts.v1;

  if (Math.abs(Math.floor(Date.now() / 1000) - timestamp) > toleranceSeconds) {
    throw new Error('Webhook timestamp outside allowed clock skew window');
  }

  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${rawBody}`)
    .digest('hex');

  return crypto.timingSafeEqual(Buffer.from(receivedSig, 'utf8'), Buffer.from(expectedSig, 'utf8'));
}
```

---

## 3. Secret Rotation Grace Period

When a signing secret is rotated via `POST /admin/webhooks/:id/rotate-secret`:

- The new secret immediately becomes active.
- The previous secret remains valid for a 24-hour grace window.
- During the grace period, AuthKit sends both signatures in the `X-Webhook-Signature` header:
  `X-Webhook-Signature: t=1700000000,v1=NEW_HMAC,v1_old=OLD_HMAC`

---

## 4. Retries & Backoff Policy

- **Delivery Guarantee**: At-least-once delivery. Receivers MUST deduplicate using `X-Webhook-Id` or `body.id`.
- **Timeout**: 5000ms HTTP timeout per delivery attempt.
- **Transient Errors Retried**: Connection timeouts, DNS failures, HTTP 408, HTTP 429, and HTTP 5xx.
- **Permanent Errors Not Retried**: HTTP 400, 401, 403, 404.
- **Exponential Backoff Schedule**:
  - Attempt 1: Immediate
  - Attempt 2: +10 seconds
  - Attempt 3: +60 seconds
  - Attempt 4: +5 minutes (300s)
  - Attempt 5: +15 minutes (900s)
- **Automatic Disabling**: Subscriptions with 10 consecutive delivery failures are automatically marked `DISABLED`.

import { isPrivateIPv4, isPrivateIPv6, validateWebhookUrl } from '@core/common/utils/ssrf.util';
import { describe, expect, it } from 'vitest';

describe('SSRF Protection Unit Tests', () => {
  describe('isPrivateIPv4', () => {
    it('should correctly identify loopback IP 127.0.0.1 as private', () => {
      expect(isPrivateIPv4('127.0.0.1')).toBe(true);
      expect(isPrivateIPv4('127.0.0.254')).toBe(true);
    });

    it('should correctly identify 10.0.0.0/8 range as private', () => {
      expect(isPrivateIPv4('10.0.0.1')).toBe(true);
      expect(isPrivateIPv4('10.255.255.254')).toBe(true);
    });

    it('should correctly identify 172.16.0.0/12 range as private', () => {
      expect(isPrivateIPv4('172.16.0.1')).toBe(true);
      expect(isPrivateIPv4('172.31.255.254')).toBe(true);
      expect(isPrivateIPv4('172.32.0.1')).toBe(false); // Outside range
    });

    it('should correctly identify 192.168.0.0/16 range as private', () => {
      expect(isPrivateIPv4('192.168.1.1')).toBe(true);
      expect(isPrivateIPv4('192.168.255.254')).toBe(true);
    });

    it('should correctly identify AWS/cloud metadata IP 169.254.169.254 as private', () => {
      expect(isPrivateIPv4('169.254.169.254')).toBe(true);
    });

    it('should identify public IPv4 addresses as non-private', () => {
      expect(isPrivateIPv4('8.8.8.8')).toBe(false);
      expect(isPrivateIPv4('1.1.1.1')).toBe(false);
      expect(isPrivateIPv4('93.184.216.34')).toBe(false);
    });
  });

  describe('isPrivateIPv6', () => {
    it('should identify ::1 loopback IPv6 as private', () => {
      expect(isPrivateIPv6('::1')).toBe(true);
    });

    it('should identify link-local fe80::/10 as private', () => {
      expect(isPrivateIPv6('fe80::1')).toBe(true);
    });
  });

  describe('validateWebhookUrl', () => {
    it('should accept valid https URLs', async () => {
      await expect(validateWebhookUrl('https://api.example.com/webhooks')).resolves.not.toThrow();
    });

    it('should reject malformed URLs', async () => {
      await expect(validateWebhookUrl('not-a-valid-url')).rejects.toThrow(
        'Invalid webhook URL format'
      );
    });

    it('should reject non-HTTP/HTTPS protocols', async () => {
      await expect(validateWebhookUrl('ftp://example.com/webhook')).rejects.toThrow(
        'Webhook URL must use the HTTPS protocol'
      );
    });
  });
});

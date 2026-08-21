/**
 * Mock implementation of EmailService for testing email dispatches.
 * Spies on sent emails and captures call arguments.
 */
import { vi } from 'vitest';

export class MockEmailService {
  public sendEmailVerification = vi.fn().mockResolvedValue({ id: 'mock-verification-id' });
  public sendPasswordResetOTP = vi.fn().mockResolvedValue({ id: 'mock-reset-id' });
  public sendPasswordChangeConfirmation = vi.fn().mockResolvedValue({ id: 'mock-confirm-id' });
  public sendWelcomeEmail = vi.fn().mockResolvedValue({ id: 'mock-welcome-id' });
  public sendNewDeviceNotification = vi.fn().mockResolvedValue({ id: 'mock-device-id' });
  public sendMagicLink = vi.fn().mockResolvedValue({ id: 'mock-magic-link-id' });
}

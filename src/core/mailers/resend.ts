import { formatDate } from '@core/common/utils/date-time';
import { logger } from '@core/common/utils/logger';
import { config } from '@core/config/app.config';
import { Resend } from 'resend';

const resend = new Resend(config.RESEND_API_KEY);

interface EmailTemplate {
  to: string;
  subject: string;
  html: string;
  from?: string;
}

interface NewDeviceInfo {
  deviceInfo: string;
  ipAddress: string;
  loginTime: Date;
}

export class EmailService {
  private readonly fromEmail: string;

  constructor() {
    this.fromEmail = config.RESEND_SENDER_EMAIL;
  }

  private async sendEmail({ to, subject, html, from }: EmailTemplate) {
    try {
      const result = await resend.emails.send({
        from: from ?? this.fromEmail,
        to,
        subject,
        html,
      });

      return result;
    } catch (error) {
      logger.error('Failed to send email:', error as Error);
      throw new Error('Failed to send email');
    }
  }

  // Send email verification notification
  public async sendEmailVerification(to: string, verificationUrl: string, name?: string) {
    const subject = 'Verify Your Email Address';
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Email Verification</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="text-align: center; margin-bottom: 30px;">
              <h1 style="color: #2563eb;">Verify Your Email</h1>
            </div>
            
            <div style="background-color: #f8fafc; padding: 30px; border-radius: 8px; margin-bottom: 30px;">
              <p style="font-size: 16px; margin-bottom: 20px;">
                ${name ? `Hi ${name},` : 'Hi there,'}
              </p>
              
              <p style="font-size: 16px; margin-bottom: 20px;">
                Thanks for signing up! Please verify your email address by clicking the button below:
              </p>
              
              <div style="text-align: center; margin: 30px 0;">
                <a href="${verificationUrl}" 
                   style="display: inline-block; background-color: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                  Verify Email Address
                </a>
              </div>
              
              <p style="font-size: 14px; color: #6b7280; margin-top: 30px;">
                If you can't click the button, copy and paste this link into your browser:
                <br>
                <a href="${verificationUrl}" style="color: #2563eb; word-break: break-all;">
                  ${verificationUrl}
                </a>
              </p>
            </div>
            
            <div style="text-align: center; color: #6b7280; font-size: 14px;">
              <p>This verification link will expire in 24 hours.</p>
              <p>If you didn't create an account, you can safely ignore this email.</p>
            </div>
          </div>
        </body>
      </html>
    `;

    return this.sendEmail({ to, subject, html });
  }

  // Send password reset email notification
  public async sendPasswordResetOTP(to: string, otp: string, name?: string) {
    const subject = 'Reset Your Password';
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Password Reset</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="text-align: center; margin-bottom: 30px;">
              <h1 style="color: #dc2626;">Password Reset</h1>
            </div>
            
            <div style="background-color: #fef2f2; padding: 30px; border-radius: 8px; margin-bottom: 30px; border-left: 4px solid #dc2626;">
              <p style="font-size: 16px; margin-bottom: 20px;">
                ${name ? `Hi ${name},` : 'Hi there,'}
              </p>
              
              <p style="font-size: 16px; margin-bottom: 20px;">
                We received a request to reset your password. Use the following OTP to proceed:
              </p>
              
              <div style="text-align: center; margin: 30px 0;">
                <div style="display: inline-block; background-color: #dc2626; color: white; padding: 15px 40px; border-radius: 8px; font-size: 32px; font-weight: 600; letter-spacing: 8px;">
                  ${otp}
                </div>
              </div>
              
              <p style="font-size: 14px; color: #6b7280; margin-top: 30px;">
                This OTP will expire in 10 minutes.
              </p>
              
              <p style="font-size: 14px; color: #6b7280;">
                If you didn't request a password reset, please ignore this email.
              </p>
            </div>
          </div>
        </body>
      </html>
    `;

    return this.sendEmail({ to, subject, html });
  }

  // Send password change confirmation notification
  public async sendPasswordChangeConfirmation(to: string, name?: string) {
    const subject = 'Password Changed Successfully';
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Password Changed</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="text-align: center; margin-bottom: 30px;">
              <h1 style="color: #059669;">Password Changed</h1>
            </div>
            
            <div style="background-color: #f0fdf4; padding: 30px; border-radius: 8px; margin-bottom: 30px; border-left: 4px solid #059669;">
              <p style="font-size: 16px; margin-bottom: 20px;">
                ${name ? `Hi ${name},` : 'Hi there,'}
              </p>
              
              <p style="font-size: 16px; margin-bottom: 20px;">
                Your password has been successfully changed. If you made this change, no further action is required.
              </p>
              
              <p style="font-size: 16px; margin-bottom: 20px;">
                If you didn't change your password, please contact our support team immediately.
              </p>
            </div>
            
            <div style="text-align: center; color: #6b7280; font-size: 14px;">
              <p>For security reasons, you've been logged out of all other devices.</p>
            </div>
          </div>
        </body>
      </html>
    `;

    return this.sendEmail({ to, subject, html });
  }

  // Send welcome email notification
  public async sendWelcomeEmail(to: string, name?: string) {
    const subject = 'Welcome to Our Platform!';
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Welcome</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="text-align: center; margin-bottom: 30px;">
              <h1 style="color: #2563eb;">Welcome!</h1>
            </div>
            
            <div style="background-color: #f8fafc; padding: 30px; border-radius: 8px; margin-bottom: 30px;">
              <p style="font-size: 16px; margin-bottom: 20px;">
                ${name ? `Hi ${name},` : 'Hi there,'}
              </p>
              
              <p style="font-size: 16px; margin-bottom: 20px;">
                Welcome to our platform! We're excited to have you on board.
              </p>
              
              <p style="font-size: 16px; margin-bottom: 20px;">
                You can now access all the features and start exploring what we have to offer.
              </p>
            </div>
            
            <div style="text-align: center; color: #6b7280; font-size: 14px;">
              <p>If you have any questions, feel free to reach out to our support team.</p>
            </div>
          </div>
        </body>
      </html>
    `;

    return this.sendEmail({ to, subject, html });
  }

  // Send New Device login notification
  public async sendNewDeviceNotification(to: string, deviceInfo: NewDeviceInfo, name?: string) {
    const subject = 'New Login Device Detected';

    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>New Device Login</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="text-align: center; margin-bottom: 30px;">
              <h1 style="color: #f59e0b;">🔒 New Device Login</h1>
            </div>
            
            <div style="background-color: #fffbeb; padding: 30px; border-radius: 8px; margin-bottom: 30px; border-left: 4px solid #f59e0b;">
              <p style="font-size: 16px; margin-bottom: 20px;">
                ${name ? `Hi ${name},` : 'Hi there,'}
              </p>
              
              <p style="font-size: 16px; margin-bottom: 20px;">
                We detected a login to your account from a new device or location. Here are the details:
              </p>
              
              <div style="background-color: #fff; padding: 20px; border-radius: 6px; margin: 20px 0; border: 1px solid #e5e7eb;">
                <table style="width: 100%; border-collapse: collapse;">
                  <tr>
                    <td style="padding: 8px 0; font-weight: 600; color: #374151; width: 30%;">Date & Time:</td>
                    <td style="padding: 8px 0; color: #6b7280;">${formatDate(deviceInfo.loginTime)}</td>
                  </tr>
                  <tr>
                    <td style="padding: 8px 0; font-weight: 600; color: #374151;">Device:</td>
                    <td style="padding: 8px 0; color: #6b7280;">${deviceInfo.deviceInfo}</td>
                  </tr>
                  <tr>
                    <td style="padding: 8px 0; font-weight: 600; color: #374151;">IP Address:</td>
                    <td style="padding: 8px 0; color: #6b7280;">${deviceInfo.ipAddress}</td>
                  </tr>
                </table>
              </div>
              
              <div style="background-color: #fef2f2; padding: 15px; border-radius: 6px; margin: 20px 0; border-left: 3px solid #dc2626;">
                <p style="font-size: 14px; color: #dc2626; margin: 0; font-weight: 600;">
                  ⚠️ If this wasn't you:
                </p>
                <ul style="font-size: 14px; color: #dc2626; margin: 10px 0 0 20px; padding: 0;">
                  <li>Change your password immediately</li>
                  <li>Review and revoke any suspicious sessions</li>
                  <li>Enable two-factor authentication if you haven't already</li>
                  <li>Contact our support team</li>
                </ul>
              </div>
              
              <div style="text-align: center; margin: 30px 0;">
                <a href="${config.FRONTEND_ORIGINS[0]}/account/security" 
                   style="display: inline-block; background-color: #dc2626; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: 600; margin-right: 10px;">
                  Review Security Settings
                </a>
                <a href="${config.FRONTEND_ORIGINS[0]}/account/sessions" 
                   style="display: inline-block; background-color: #6b7280; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                  Manage Sessions
                </a>
              </div>
            </div>
            
            <div style="text-align: center; color: #6b7280; font-size: 14px;">
              <p>If this was you, you can safely ignore this email.</p>
              <p>We send these notifications to help keep your account secure.</p>
            </div>
          </div>
        </body>
      </html>
    `;

    return this.sendEmail({ to, subject, html });
  }
}

// Export singleton instance
export const emailService = new EmailService();

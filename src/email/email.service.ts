import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  constructor(private readonly config: ConfigService) {}

  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: this.config.get('email.user'),
      pass: this.config.get('email.password'),
    },
  });

  async sendVerificationEmail(
    email: string,
    token: string,
    firstName?: string,
  ): Promise<void> {
    const frontendUrl = this.config.get<string>('frontendUrl');
    const verificationUrl = `${frontendUrl}/auth/verify-email?token=${token}`;

    await this.transporter.sendMail({
      from: this.config.get('email.from'),
      to: email,
      subject: 'Verify Your Email Address',
      html: `
        <h2>Welcome!</h2>
        <p>Hi ${firstName || 'there'},</p>
        <p>Please verify your email address by clicking the button below:</p>
        <a href="${verificationUrl}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">
          Verify Email
        </a>
        <p>Or copy and paste this link:</p>
        <p>${verificationUrl}</p>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't create an account, please ignore this email.</p>
      `,
    });
  }

  async sendWelcomeEmail(email: string, firstName?: string): Promise<void> {
    await this.transporter.sendMail({
      from: this.config.get('email.from'),
      to: email,
      subject: 'Welcome to Our Platform!',
      html: `
      <p>=====================================</p>
      <p>WELCOME EMAIL</p>
      <p>=====================================</p>
      <p>To: ${email}</p>
      <p>Subject: Welcome to Our Platform!</p>
      <br/>
      <p>Hi ${firstName || 'there'},</p>
      <br/>
      <p>Your email has been verified successfully!</p>
      <p>Welcome to our platform.</p>
      <p>=====================================</p>

    `,
    });
  }

  async sendPasswordResetEmail(
    email: string,
    token: string,
    firstName?: string,
  ): Promise<void> {
    const frontendUrl = this.config.get<string>('frontendUrl');
    const resetUrl = `${frontendUrl}/auth/reset-password?token=${token}`;

    await this.transporter.sendMail({
      from: this.config.get('email.from'),
      to: email,
      subject: 'Reset Your Password',
      html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Password Reset Request</h2>
        <p>Hi ${firstName || 'there'},</p>
        <p>You requested to reset your password. Click the button below to create a new password:</p>
        <div style="margin: 30px 0;">
          <a href="${resetUrl}" 
             style="display: inline-block; padding: 12px 24px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">
            Reset Password
          </a>
        </div>
        <p>Or copy and paste this link:</p>
        <p style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; word-break: break-all;">
          ${resetUrl}
        </p>
        <p style="color: #666; font-size: 14px;">
          <strong>This link will expire in 1 hour.</strong>
        </p>
        <p style="color: #666; font-size: 14px;">
          If you didn't request this, please ignore this email and your password will remain unchanged.
        </p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
        <p style="color: #999; font-size: 12px;">
          For security reasons, we recommend:
        </p>
        <ul style="color: #999; font-size: 12px;">
          <li>Using a strong, unique password</li>
          <li>Not sharing your password with anyone</li>
          <li>Enabling two-factor authentication (if available)</li>
        </ul>
      </div>
    `,
    });
  }

  async sendPasswordChangedNotification(
    email: string,
    firstName?: string,
  ): Promise<void> {
    await this.transporter.sendMail({
      from: this.config.get('email.from'),
      to: email,
      subject: 'Your Password Was Changed',
      html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Password Changed Successfully</h2>
        <p>Hi ${firstName || 'there'},</p>
        <p>This is a confirmation that your password was successfully changed.</p>
        <div style="background-color: #f0f9ff; border-left: 4px solid #0066cc; padding: 15px; margin: 20px 0;">
          <p style="margin: 0; color: #0066cc; font-weight: bold;">Time: ${new Date().toUTCString()}</p>
        </div>
        <div style="background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0;">
          <p style="margin: 0; color: #856404;">
            <strong>⚠️ If you didn't make this change</strong>, please contact our support team immediately.
          </p>
        </div>
        <p style="color: #666; font-size: 14px;">
          For your security, you've been logged out of all devices. Please log in again with your new password.
        </p>
      </div>
    `,
    });
  }
}

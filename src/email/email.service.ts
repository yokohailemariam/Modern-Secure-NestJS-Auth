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
}

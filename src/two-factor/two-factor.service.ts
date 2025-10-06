import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { PrismaService } from '@prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import * as crypto from 'crypto';

@Injectable()
export class TwoFactorService {
  private readonly logger = new Logger(TwoFactorService.name);
  private readonly encryptionKey: string;
  private readonly appName: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {
    this.encryptionKey =
      this.config.get<string>('security.encryptionKey') ||
      crypto.randomBytes(32).toString('hex');
    this.appName = this.config.get<string>('app.name') || 'MyApp';
  }

  /**
   * Encrypt sensitive data
   */
  private encrypt(text: string): string {
    const algorithm = 'aes-256-cbc';
    const key = Buffer.from(this.encryptionKey.slice(0, 32), 'utf-8');
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return `${iv.toString('hex')}:${encrypted}`;
  }

  /**
   * Decrypt sensitive data
   */
  private decrypt(encryptedText: string): string {
    const algorithm = 'aes-256-cbc';
    const key = Buffer.from(this.encryptionKey.slice(0, 32), 'utf-8');

    const parts = encryptedText.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];

    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * Generate backup codes
   */
  private generateBackupCodes(count = 10): string[] {
    const codes: string[] = [];

    for (let i = 0; i < count; i++) {
      const code = crypto.randomBytes(4).toString('hex').toUpperCase();
      const formatted = `${code.slice(0, 4)}-${code.slice(4, 8)}`;
      codes.push(formatted);
    }

    return codes;
  }

  /**
   * Hash backup code for storage
   */
  private hashBackupCode(code: string): string {
    return crypto.createHash('sha256').update(code).digest('hex');
  }

  /**
   * Generate 2FA secret and QR code
   */
  async generateSecret(userId: string): Promise<{
    secret: string;
    otpauthUrl: string;
    qrCode: string;
  }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { email: true, twoFactorEnabled: true },
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (user.twoFactorEnabled) {
      throw new BadRequestException(
        'Two-factor authentication is already enabled',
      );
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `${this.appName} (${user.email})`,
      issuer: this.appName,
      length: 32,
    });

    // Generate QR code
    const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    return {
      secret: secret.base32,
      otpauthUrl: secret.otpauth_url,
      qrCode: qrCodeDataUrl,
    };
  }

  /**
   * Verify TOTP code
   */
  verifyToken(secret: string, token: string, window = 1): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window, // Allow 1 time step before and after (30 seconds each)
    });
  }

  /**
   * Enable 2FA for user
   */
  async enable2FA(
    userId: string,
    secret: string,
    code: string,
  ): Promise<{ backupCodes: string[]; message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (user.twoFactorEnabled) {
      throw new BadRequestException(
        'Two-factor authentication is already enabled',
      );
    }

    // Verify the code
    const isValid = this.verifyToken(secret, code);

    if (!isValid) {
      throw new BadRequestException('Invalid verification code');
    }

    // Generate backup codes
    const backupCodes = this.generateBackupCodes(10);
    const hashedBackupCodes = backupCodes.map((code) =>
      this.hashBackupCode(code),
    );

    // Encrypt and save secret
    const encryptedSecret = this.encrypt(secret);

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: true,
        twoFactorSecret: encryptedSecret,
        twoFactorBackupCodes: hashedBackupCodes,
        twoFactorEnabledAt: new Date(),
        twoFactorMethod: 'TOTP',
      },
    });

    this.logger.log(`2FA enabled for user ${userId}`);

    return {
      backupCodes,
      message:
        'Two-factor authentication enabled successfully. Save these backup codes in a secure location.',
    };
  }

  /**
   * Disable 2FA
   */
  async disable2FA(userId: string): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (!user.twoFactorEnabled) {
      throw new BadRequestException('Two-factor authentication is not enabled');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: false,
        twoFactorSecret: null,
        twoFactorBackupCodes: [],
        twoFactorEnabledAt: null,
        twoFactorLastUsedAt: null,
      },
    });

    this.logger.log(`2FA disabled for user ${userId}`);

    return { message: 'Two-factor authentication disabled successfully' };
  }

  /**
   * Verify 2FA code during login
   */
  async verify2FACode(userId: string, code: string): Promise<boolean> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
      throw new BadRequestException('Two-factor authentication is not enabled');
    }

    // Remove any spaces or dashes from the code
    const cleanCode = code.replace(/[\s-]/g, '');

    // Check if it's a backup code (8 characters without dash, or 9 with dash)
    if (cleanCode.length === 8) {
      return this.verifyBackupCode(userId, code);
    }

    // Verify TOTP code (6 digits)
    if (cleanCode.length !== 6 || !/^\d{6}$/.test(cleanCode)) {
      return false;
    }

    const decryptedSecret = this.decrypt(user.twoFactorSecret);
    const isValid = this.verifyToken(decryptedSecret, cleanCode, 1);

    if (isValid) {
      // Update last used timestamp
      await this.prisma.user.update({
        where: { id: userId },
        data: { twoFactorLastUsedAt: new Date() },
      });
    }

    return isValid;
  }

  /**
   * Verify backup code
   */
  async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.twoFactorEnabled) {
      return false;
    }

    const cleanCode = code.replace(/[\s-]/g, '').toUpperCase();
    const hashedCode = this.hashBackupCode(cleanCode);

    const backupCodes = user.twoFactorBackupCodes || [];
    const codeIndex = backupCodes.indexOf(hashedCode);

    if (codeIndex === -1) {
      return false;
    }

    // Remove used backup code
    const updatedCodes = backupCodes.filter((_, index) => index !== codeIndex);

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorBackupCodes: updatedCodes,
        twoFactorLastUsedAt: new Date(),
      },
    });

    this.logger.log(
      `Backup code used for user ${userId}. Remaining: ${updatedCodes.length}`,
    );

    return true;
  }

  /**
   * Regenerate backup codes
   */
  async regenerateBackupCodes(userId: string): Promise<string[]> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (!user.twoFactorEnabled) {
      throw new BadRequestException('Two-factor authentication is not enabled');
    }

    const backupCodes = this.generateBackupCodes(10);
    const hashedBackupCodes = backupCodes.map((code) =>
      this.hashBackupCode(code),
    );

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorBackupCodes: hashedBackupCodes,
      },
    });

    this.logger.log(`Backup codes regenerated for user ${userId}`);

    return backupCodes;
  }

  /**
   * Get 2FA status
   */
  async get2FAStatus(userId: string): Promise<{
    enabled: boolean;
    method?: string;
    enabledAt?: Date;
    lastUsedAt?: Date;
    remainingBackupCodes?: number;
  }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        twoFactorEnabled: true,
        twoFactorMethod: true,
        twoFactorEnabledAt: true,
        twoFactorLastUsedAt: true,
        twoFactorBackupCodes: true,
      },
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    return {
      enabled: user.twoFactorEnabled,
      method: user.twoFactorEnabled ? user.twoFactorMethod : undefined,
      enabledAt: user.twoFactorEnabledAt || undefined,
      lastUsedAt: user.twoFactorLastUsedAt || undefined,
      remainingBackupCodes: user.twoFactorEnabled
        ? user.twoFactorBackupCodes?.length || 0
        : undefined,
    };
  }

  /**
   * Check if user has 2FA enabled
   */
  async is2FAEnabled(userId: string): Promise<boolean> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { twoFactorEnabled: true },
    });

    return user?.twoFactorEnabled || false;
  }
}

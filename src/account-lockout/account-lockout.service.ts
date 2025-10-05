import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '@prisma/prisma.service';
import { EmailService } from '@src/email/email.service';

export interface LockoutConfig {
  maxAttempts: number;
  lockDuration: number; // in minutes
  attemptWindow: number; // in minutes
  progressiveLockout: boolean;
}

export interface LoginAttemptLog {
  userId: string;
  success: boolean;
  ipAddress: string | null;
  userAgent: string | null;
  failureReason: string | null;
}

@Injectable()
export class AccountLockoutService {
  private readonly logger = new Logger(AccountLockoutService.name);
  private readonly lockoutConfig: LockoutConfig;
  private readonly LOGIN_HISTORY_LIMIT = 50;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly emailService: EmailService,
  ) {
    this.lockoutConfig = {
      maxAttempts:
        this.config.get<number>('security.accountLockout.maxAttempts') || 5,
      lockDuration:
        this.config.get<number>('security.accountLockout.lockDuration') || 15,
      attemptWindow:
        this.config.get<number>('security.accountLockout.attemptWindow') || 15,
      progressiveLockout:
        this.config.get<boolean>(
          'security.accountLockout.progressiveLockout',
        ) || false,
    };
  }

  /**
   * Check if account is currently locked
   */
  async isAccountLocked(userId: string): Promise<{
    isLocked: boolean;
    lockedUntil?: Date;
    remainingAttempts: number;
  }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        failedLoginAttempts: true,
        lockedUntil: true,
      },
    });

    if (!user) {
      return {
        isLocked: false,
        remainingAttempts: this.lockoutConfig.maxAttempts,
      };
    }

    // Check if account is locked and lock period hasn't expired
    if (user.lockedUntil && new Date() < user.lockedUntil) {
      return {
        isLocked: true,
        lockedUntil: user.lockedUntil,
        remainingAttempts: 0,
      };
    }

    // If lock period expired, reset the lock
    if (user.lockedUntil && new Date() >= user.lockedUntil) {
      await this.unlockAccount(userId);
      return {
        isLocked: false,
        remainingAttempts: this.lockoutConfig.maxAttempts,
      };
    }

    const remainingAttempts = Math.max(
      0,
      this.lockoutConfig.maxAttempts - user.failedLoginAttempts,
    );

    return {
      isLocked: false,
      remainingAttempts,
    };
  }

  /**
   * Record failed login attempt
   */
  async recordFailedAttempt(
    userId: string,
    ipAddress?: string,
    userAgent?: string,
    reason?: string,
  ): Promise<{
    isLocked: boolean;
    lockedUntil?: Date;
    remainingAttempts: number;
  }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        failedLoginAttempts: true,
        email: true,
        firstName: true,
      },
    });

    if (!user) {
      throw new Error('User not found');
    }

    const newAttemptCount = user.failedLoginAttempts + 1;
    const shouldLock = newAttemptCount >= this.lockoutConfig.maxAttempts;

    let lockDurationMinutes = this.lockoutConfig.lockDuration;
    if (this.lockoutConfig.progressiveLockout && shouldLock) {
      const lockoutCycle = Math.floor(
        newAttemptCount / this.lockoutConfig.maxAttempts,
      );
      lockDurationMinutes =
        this.lockoutConfig.lockDuration * Math.pow(2, lockoutCycle - 1);
      lockDurationMinutes = Math.min(lockDurationMinutes, 24 * 60);
    }

    const lockedUntil = shouldLock
      ? new Date(Date.now() + lockDurationMinutes * 60 * 1000)
      : null;

    // Nested create for relation instead of assigning array
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        failedLoginAttempts: newAttemptCount,
        lockedUntil,
        lastFailedLoginAt: new Date(),
        loginHistory: {
          create: {
            success: false,
            ipAddress: ipAddress ?? null,
            userAgent: userAgent ?? null,
            failureReason: reason || 'Invalid credentials',
          },
        },
      },
    });

    // Trim excess history
    await this.trimLoginHistory(userId);

    if (shouldLock) {
      this.logger.warn(
        `Account locked for user ${user.email} until ${lockedUntil?.toISOString()}. Lock duration: ${lockDurationMinutes} minutes`,
      );
      await this.emailService.sendAccountLockedNotification(
        user.email,
        lockedUntil,
        user.firstName,
      );
    }

    return {
      isLocked: shouldLock,
      lockedUntil,
      remainingAttempts: Math.max(
        0,
        this.lockoutConfig.maxAttempts - newAttemptCount,
      ),
    };
  }
  /**
   * Record successful login
   */
  async recordSuccessfulLogin(
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        failedLoginAttempts: 0,
        lockedUntil: null,
        lastSuccessfulLoginAt: new Date(),
        loginHistory: {
          create: {
            success: true,
            ipAddress: ipAddress ?? null,
            userAgent: userAgent ?? null,
            failureReason: null,
          },
        },
      },
    });

    await this.trimLoginHistory(userId);
  }

  /**
   * Manually unlock account (admin function)
   */
  async unlockAccount(userId: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        failedLoginAttempts: 0,
        lockedUntil: null,
      },
    });

    this.logger.log(`Account unlocked for user ID: ${userId}`);
  }

  /**
   * Get login history for user
   */
  async getLoginHistory(
    userId: string,
    limit = 20,
  ): Promise<LoginAttemptLog[]> {
    const rows = await this.prisma.loginHistory.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: limit,
      select: {
        userId: true,
        success: true,
        ipAddress: true,
        userAgent: true,
        failureReason: true,
      },
    });

    return rows;
  }

  private async trimLoginHistory(userId: string): Promise<void> {
    const excess = await this.prisma.loginHistory.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      skip: this.LOGIN_HISTORY_LIMIT,
      select: { id: true },
    });

    if (!excess.length) return;

    await this.prisma.loginHistory.deleteMany({
      where: { id: { in: excess.map((e) => e.id) } },
    });
  }

  /**
   * Get lockout status for display
   */
  async getLockoutStatus(userId: string): Promise<{
    isLocked: boolean;
    failedAttempts: number;
    remainingAttempts: number;
    lockedUntil?: Date;
    lastFailedLoginAt?: Date;
  }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        failedLoginAttempts: true,
        lockedUntil: true,
        lastFailedLoginAt: true,
      },
    });

    if (!user) {
      return {
        isLocked: false,
        failedAttempts: 0,
        remainingAttempts: this.lockoutConfig.maxAttempts,
      };
    }

    const lockStatus = await this.isAccountLocked(userId);

    return {
      isLocked: lockStatus.isLocked,
      failedAttempts: user.failedLoginAttempts,
      remainingAttempts: lockStatus.remainingAttempts,
      lockedUntil: lockStatus.lockedUntil,
      lastFailedLoginAt: user.lastFailedLoginAt,
    };
  }
}

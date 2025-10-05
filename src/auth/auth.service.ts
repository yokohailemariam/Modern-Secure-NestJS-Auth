import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../user/user.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

import { Tokens } from './interfaces/tokens.interface';
import { AuthResponseDto } from './dto/auth-response.dto';
import {
  JwtPayload,
  JwtRefreshPayload,
} from './interfaces/jwt.payload.interface';
import { PrismaService } from '@prisma/prisma.service';
import { SocialAuthDto, SocialAuthResponseDto } from './dto/social-auth.dto';
import { EmailService } from '@src/email/email.service';
import * as crypto from 'crypto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { CurrentUser } from './decorator/current-user.decorator';
import {
  ChangePasswordDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  ValidateResetTokenDto,
} from './dto/password-reset.dto';
import { AccountLockoutService } from '@src/account-lockout/account-lockout.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
    private readonly emailService: EmailService,
    private readonly accountLockoutService: AccountLockoutService,
  ) {}

  async register(registerDto: RegisterDto): Promise<AuthResponseDto> {
    const user = await this.userService.create(registerDto);

    await this.sendVerificationEmail(user.id, user.email, user.firstName);

    const tokens = await this.generateTokens(user.id, user.email, user.role);

    return {
      ...tokens,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
    };
  }

  async login(
    loginDto: LoginDto,
    deviceId?: string,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<AuthResponseDto> {
    const user = await this.userService.findByEmail(loginDto.email);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if account is locked
    const lockStatus = await this.accountLockoutService.isAccountLocked(
      user.id,
    );

    if (lockStatus.isLocked) {
      const minutesRemaining = Math.ceil(
        (lockStatus.lockedUntil.getTime() - Date.now()) / (60 * 1000),
      );

      throw new UnauthorizedException(
        `Account is locked due to too many failed login attempts. ` +
          `Please try again in ${minutesRemaining} minute(s).`,
      );
    }

    const isPasswordValid = await this.userService.validatePassword(
      loginDto.password,
      user.password,
    );

    if (!isPasswordValid) {
      // Record failed attempt
      const attemptResult =
        await this.accountLockoutService.recordFailedAttempt(
          user.id,
          ipAddress,
          userAgent,
          'Invalid password',
        );

      if (attemptResult.isLocked) {
        const minutesLocked = Math.ceil(
          (attemptResult.lockedUntil.getTime() - Date.now()) / (60 * 1000),
        );

        throw new UnauthorizedException(
          `Account locked due to too many failed attempts. ` +
            `Please try again in ${minutesLocked} minute(s).`,
        );
      }

      throw new UnauthorizedException(
        `Invalid credentials. ${attemptResult.remainingAttempts} attempt(s) remaining.`,
      );
    }

    if (!user.isActive) {
      await this.accountLockoutService.recordFailedAttempt(
        user.id,
        ipAddress,
        userAgent,
        'Account inactive',
      );

      throw new UnauthorizedException('Account is inactive');
    }
    /*
    if (!user.isEmailVerified) {
      await this.accountLockoutService.recordFailedAttempt(
        user.id,
        ipAddress,
        userAgent,
        'Email not verified',
      );
      throw new UnauthorizedException('Please verify your email before logging in');
    }
    */

    // Successful login - record it and reset failed attempts
    await this.accountLockoutService.recordSuccessfulLogin(
      user.id,
      ipAddress,
      userAgent,
    );

    const tokens = await this.generateTokens(
      user.id,
      user.email,
      user.role,
      deviceId,
      userAgent,
      ipAddress,
    );

    const { password, ...userWithoutPassword } = user;
    void password;

    return {
      ...tokens,
      user: {
        id: userWithoutPassword.id,
        email: userWithoutPassword.email,
        firstName: userWithoutPassword.firstName,
        lastName: userWithoutPassword.lastName,
        role: userWithoutPassword.role,
      },
    };
  }

  // Add method to get lockout status
  async getAccountLockoutStatus(userId: string) {
    return this.accountLockoutService.getLockoutStatus(userId);
  }

  // Add method to get login history
  async getLoginHistory(userId: string, limit = 20) {
    return this.accountLockoutService.getLoginHistory(userId, limit);
  }

  // Add admin method to unlock account
  async unlockAccount(email: string): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    await this.accountLockoutService.unlockAccount(user.id);

    return { message: 'Account unlocked successfully' };
  }

  async refreshTokens(
    userId: string,
    tokenId: string,
    deviceId?: string,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<Tokens & { expiresIn: number }> {
    await this.revokeRefreshToken(tokenId);

    const user = await this.userService.findById(userId);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return this.generateTokens(
      userId,
      user.email,
      user.role,
      deviceId,
      userAgent,
      ipAddress,
    );
  }

  async logout(tokenId: string): Promise<void> {
    await this.revokeRefreshToken(tokenId);
  }

  async logoutAll(userId: string): Promise<void> {
    await this.prisma.refreshToken.updateMany({
      where: {
        userId,
        isRevoked: false,
      },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
      },
    });
  }

  private async generateTokens(
    userId: string,
    email: string,
    role: any,
    deviceId?: string,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<Tokens & { expiresIn: number }> {
    const accessTokenPayload: JwtPayload = {
      sub: userId,
      email,
      role,
    };

    const accessToken = await this.jwtService.signAsync(accessTokenPayload, {
      secret: this.config.get<string>('jwt.access.secret'),
      expiresIn: this.config.get<string>('jwt.access.expiresIn'),
    });

    const refreshTokenExpiration = this.config.get<string>(
      'jwt.refresh.expiresIn',
    );
    const expiresAt = this.calculateExpirationDate(refreshTokenExpiration);

    const refreshTokenRecord = await this.prisma.refreshToken.create({
      data: {
        userId,
        token: '',
        expiresAt,
        deviceId,
        userAgent,
        ipAddress,
      },
    });

    const refreshTokenPayload: JwtRefreshPayload = {
      sub: userId,
      tokenId: refreshTokenRecord.id,
    };

    const refreshToken = await this.jwtService.signAsync(refreshTokenPayload, {
      secret: this.config.get<string>('jwt.refresh.secret'),
      expiresIn: refreshTokenExpiration,
    });

    await this.prisma.refreshToken.update({
      where: { id: refreshTokenRecord.id },
      data: { token: refreshToken },
    });

    const expiresIn = this.parseExpirationToSeconds(
      this.config.get<string>('jwt.access.expiresIn'),
    );

    return {
      accessToken,
      refreshToken,
      expiresIn,
    };
  }

  private async revokeRefreshToken(tokenId: string): Promise<void> {
    await this.prisma.refreshToken.update({
      where: { id: tokenId },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
      },
    });
  }

  private calculateExpirationDate(expiresIn: string): Date {
    const now = new Date();
    const seconds = this.parseExpirationToSeconds(expiresIn);
    return new Date(now.getTime() + seconds * 1000);
  }

  private parseExpirationToSeconds(expiresIn: string): number {
    const match = expiresIn.match(/^(\d+)([smhd])$/);
    if (!match) {
      throw new BadRequestException('Invalid expiration format');
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    const multipliers = {
      s: 1,
      m: 60,
      h: 3600,
      d: 86400,
    };

    return value * multipliers[unit];
  }

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.userService.findByEmail(email);

    if (!user) {
      return null;
    }

    const isValid = await this.userService.validatePassword(
      password,
      user.password,
    );

    if (isValid) {
      const { password, ...result } = user;
      void password;
      return result;
    }

    return null;
  }

  private generateVerificationToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  async sendVerificationEmail(
    userId: string,
    email: string,
    firstName?: string,
  ): Promise<void> {
    const token = this.generateVerificationToken();
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        emailVerificationToken: token,
        emailVerificationExpires: expires,
      },
    });

    await this.emailService.sendVerificationEmail(email, token, firstName);
  }

  async verifyEmail(
    verifyEmailDto: VerifyEmailDto,
  ): Promise<{ message: string }> {
    const { token } = verifyEmailDto;

    const user = await this.prisma.user.findUnique({
      where: { emailVerificationToken: token },
    });

    if (!user) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    if (user.isEmailVerified) {
      throw new BadRequestException('Email already verified');
    }

    if (
      user.emailVerificationExpires &&
      new Date() > user.emailVerificationExpires
    ) {
      throw new BadRequestException(
        'Verification token has expired. Please request a new one.',
      );
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        isEmailVerified: true,
        emailVerificationToken: null,
        emailVerificationExpires: null,
      },
    });

    await this.emailService.sendWelcomeEmail(user.email, user.firstName);

    return { message: 'Email verified successfully' };
  }

  async resendVerificationEmail(email: string): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return {
        message: 'If the email exists, a verification link has been sent',
      };
    }

    if (user.isEmailVerified) {
      throw new BadRequestException('Email already verified');
    }

    if (user.emailVerificationExpires) {
      const timeSinceLastEmail =
        Date.now() -
        (new Date(user.emailVerificationExpires).getTime() -
          24 * 60 * 60 * 1000);
      if (timeSinceLastEmail < 60000) {
        throw new BadRequestException(
          'Please wait before requesting another verification email',
        );
      }
    }

    await this.sendVerificationEmail(user.id, user.email, user.firstName);

    return { message: 'Verification email sent' };
  }

  async getVerificationStatus(@CurrentUser() user: any) {
    const userData = await this.prisma.user.findUnique({
      where: { id: user.id },
      select: {
        isEmailVerified: true,
        email: true,
      },
    });

    return {
      email: userData.email,
      isVerified: userData.isEmailVerified,
    };
  }

  private generateResetToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  async forgotPassword(
    forgotPasswordDto: ForgotPasswordDto,
  ): Promise<{ message: string }> {
    const { email } = forgotPasswordDto;

    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return {
        message: 'If the email exists, a password reset link has been sent',
      };
    }

    if (
      user.passwordResetAttempts >= 5 &&
      user.passwordResetAttemptsExpires &&
      new Date() < user.passwordResetAttemptsExpires
    ) {
      throw new BadRequestException(
        'Too many password reset requests. Please try again later.',
      );
    }

    const resetAttempts =
      user.passwordResetAttemptsExpires &&
      new Date() > user.passwordResetAttemptsExpires
        ? 1
        : (user.passwordResetAttempts || 0) + 1;

    const token = this.generateResetToken();
    const expires = new Date(Date.now() + 60 * 60 * 1000);
    const attemptsExpires = new Date(Date.now() + 60 * 60 * 1000);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken: token,
        passwordResetExpires: expires,
        passwordResetAttempts: resetAttempts,
        passwordResetAttemptsExpires: attemptsExpires,
      },
    });

    await this.emailService.sendPasswordResetEmail(
      user.email,
      token,
      user.firstName,
    );

    return {
      message: 'If the email exists, a password reset link has been sent',
    };
  }

  async validateResetToken(validateTokenDto: ValidateResetTokenDto): Promise<{
    valid: boolean;
    message: string;
    email?: string;
  }> {
    const { token } = validateTokenDto;

    const user = await this.prisma.user.findUnique({
      where: { passwordResetToken: token },
      select: {
        email: true,
        passwordResetExpires: true,
      },
    });

    if (!user) {
      return {
        valid: false,
        message: 'Invalid or expired reset token',
      };
    }

    if (user.passwordResetExpires && new Date() > user.passwordResetExpires) {
      return {
        valid: false,
        message: 'Reset token has expired. Please request a new one.',
      };
    }

    return {
      valid: true,
      message: 'Token is valid',
      email: user.email,
    };
  }

  async resetPassword(
    resetPasswordDto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    const { token, newPassword } = resetPasswordDto;

    const user = await this.prisma.user.findUnique({
      where: { passwordResetToken: token },
    });

    if (!user) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    if (user.passwordResetExpires && new Date() > user.passwordResetExpires) {
      throw new BadRequestException(
        'Reset token has expired. Please request a new one.',
      );
    }

    if (user.password) {
      const isSamePassword = await this.userService.validatePassword(
        newPassword,
        user.password,
      );
      if (isSamePassword) {
        throw new BadRequestException(
          'New password must be different from your previous password',
        );
      }
    }

    await this.userService.updatePassword(user.id, newPassword);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken: null,
        passwordResetExpires: null,
        passwordResetAttempts: 0,
        passwordResetAttemptsExpires: null,
        passwordChangedAt: new Date(),
      },
    });

    await this.logoutAll(user.id);

    await this.emailService.sendPasswordChangedNotification(
      user.email,
      user.firstName,
    );

    return {
      message:
        'Password reset successfully. Please log in with your new password.',
    };
  }

  async changePassword(
    userId: string,
    changePasswordDto: ChangePasswordDto,
  ): Promise<{ message: string }> {
    const { currentPassword, newPassword } = changePasswordDto;

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (user.password) {
      const isCurrentPasswordValid = await this.userService.validatePassword(
        currentPassword,
        user.password,
      );

      if (!isCurrentPasswordValid) {
        throw new BadRequestException('Current password is incorrect');
      }

      const isSamePassword = await this.userService.validatePassword(
        newPassword,
        user.password,
      );
      if (isSamePassword) {
        throw new BadRequestException(
          'New password must be different from your current password',
        );
      }
    }

    await this.userService.updatePassword(user.id, newPassword);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordChangedAt: new Date(),
      },
    });

    await this.logoutAll(user.id);

    await this.emailService.sendPasswordChangedNotification(
      user.email,
      user.firstName,
    );

    return { message: 'Password changed successfully. Please log in again.' };
  }

  async googleLogin(
    socialAuthDto: SocialAuthDto,
    deviceId?: string,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<SocialAuthResponseDto> {
    let user = await this.prisma.user.findUnique({
      where: { googleId: socialAuthDto.googleId },
    });

    let isNewUser = false;

    if (!user) {
      user = await this.prisma.user.findUnique({
        where: { email: socialAuthDto.email },
      });

      if (user) {
        user = await this.prisma.user.update({
          where: { id: user.id },
          data: {
            googleId: socialAuthDto.googleId,
            avatar: socialAuthDto.avatar || user.avatar,
            firstName: user.firstName || socialAuthDto.firstName,
            lastName: user.lastName || socialAuthDto.lastName,
          },
        });
      } else {
        user = await this.prisma.user.create({
          data: {
            email: socialAuthDto.email,
            googleId: socialAuthDto.googleId,
            firstName: socialAuthDto.firstName,
            lastName: socialAuthDto.lastName,
            avatar: socialAuthDto.avatar,
            provider: 'GOOGLE',
            isActive: true,
            role: 'USER',
            password: '',
          },
        });
        isNewUser = true;
      }
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Account is inactive');
    }

    const tokens = await this.generateTokens(
      user.id,
      user.email,
      user.role,
      deviceId,
      userAgent,
      ipAddress,
    );

    return {
      ...tokens,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        avatar: user.avatar,
        provider: user.provider,
      },
      isNewUser,
    };
  }

  // Generic social login handler (for future providers)
  async socialLogin(
    provider: 'GOOGLE' | 'FACEBOOK' | 'TWITTER' | 'GITHUB',
    socialAuthDto: SocialAuthDto,
    deviceId?: string,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<SocialAuthResponseDto> {
    const providerIdField =
      `${provider.toLowerCase()}Id` as keyof typeof socialAuthDto;
    const providerId = socialAuthDto[providerIdField] as string;

    let user = await this.prisma.user.findFirst({
      where: { [providerIdField]: providerId },
    });

    let isNewUser = false;

    if (!user) {
      user = await this.prisma.user.findUnique({
        where: { email: socialAuthDto.email },
      });

      if (user) {
        user = await this.prisma.user.update({
          where: { id: user.id },
          data: {
            [providerIdField]: providerId,
            avatar: socialAuthDto.avatar || user.avatar,
            firstName: user.firstName || socialAuthDto.firstName,
            lastName: user.lastName || socialAuthDto.lastName,
          },
        });
      } else {
        user = await this.prisma.user.create({
          data: {
            email: socialAuthDto.email,
            [providerIdField]: providerId,
            firstName: socialAuthDto.firstName,
            lastName: socialAuthDto.lastName,
            avatar: socialAuthDto.avatar,
            provider: provider,
            isActive: true,
            role: 'USER',
            password: '',
          },
        });
        isNewUser = true;
      }
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Account is inactive');
    }

    const tokens = await this.generateTokens(
      user.id,
      user.email,
      user.role,
      deviceId,
      userAgent,
      ipAddress,
    );

    return {
      ...tokens,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        avatar: user.avatar,
        provider: user.provider,
      },
      isNewUser,
    };
  }
}

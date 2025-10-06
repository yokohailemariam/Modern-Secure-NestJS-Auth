import {
  Controller,
  Post,
  Body,
  UseGuards,
  Req,
  Res,
  HttpCode,
  HttpStatus,
  Get,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiResponse,
} from '@nestjs/swagger';
import { Response, Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { Public } from './decorator/public.decorator';
import { CurrentUser } from './decorator/current-user.decorator';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { SocialAuthDto } from './dto/social-auth.dto';
import { ResendVerificationDto, VerifyEmailDto } from './dto/verify-email.dto';
import {
  ChangePasswordDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  ValidateResetTokenDto,
} from './dto/password-reset.dto';
import { Throttle } from '@nestjs/throttler';
import { Roles } from './decorator/role.decorator';
import { Role } from '@prisma/generated/prisma';
import { RolesGuard } from './guards/roles.guard';
import {
  AccountLockoutResponseDto,
  UnlockAccountDto,
} from './dto/account-lockout.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
  ) {}

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Register a new user' })
  async register(
    @Body() registerDto: RegisterDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.register(registerDto);

    this.setRefreshTokenCookie(res, result.refreshToken);

    return {
      accessToken: result.accessToken,
      expiresIn: result.expiresIn,
      user: result.user,
    };
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login with email and password' })
  @ApiResponse({
    status: 200,
    description: 'Successful login or 2FA required',
    schema: {
      oneOf: [
        {
          properties: {
            accessToken: { type: 'string' },
            expiresIn: { type: 'number' },
            user: { type: 'object' },
          },
        },
        {
          properties: {
            requires2FA: { type: 'boolean', example: true },
            user: { type: 'object' },
          },
        },
      ],
    },
  })
  async login(
    @Body() loginDto: LoginDto,
    @Body('twoFactorCode') twoFactorCode: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const deviceId = req.headers['x-device-id'] as string;
    const userAgent = req.headers['user-agent'];
    const ipAddress = req.ip;

    const result = await this.authService.login(
      loginDto,
      deviceId,
      userAgent,
      ipAddress,
      twoFactorCode,
    );

    // If 2FA is required, don't set refresh token
    if (result.requires2FA) {
      return {
        requires2FA: true,
        message: 'Two-factor authentication required',
        user: result.user,
      };
    }

    this.setRefreshTokenCookie(res, result.refreshToken);

    return {
      accessToken: result.accessToken,
      expiresIn: result.expiresIn,
      user: result.user,
    };
  }

  @Public()
  @UseGuards(JwtRefreshGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token using refresh token' })
  async refresh(
    @CurrentUser() user: any,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const deviceId = req.headers['x-device-id'] as string;
    const userAgent = req.headers['user-agent'];
    const ipAddress = req.ip;

    const tokens = await this.authService.refreshTokens(
      user.id,
      user.tokenId,
      deviceId,
      userAgent,
      ipAddress,
    );

    // Set new refresh token in HTTP-only cookie
    this.setRefreshTokenCookie(res, tokens.refreshToken);

    return {
      accessToken: tokens.accessToken,
      expiresIn: tokens.expiresIn,
    };
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard, JwtRefreshGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Logout and invalidate refresh token' })
  async logout(
    @CurrentUser() user: any,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.logout(user.tokenId);

    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: this.config.get('environment') === 'production',
      sameSite: 'strict',
    });

    return { message: 'Logged out successfully' };
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Logout from all devices' })
  async logoutAll(
    @CurrentUser('id') userId: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.logoutAll(userId);

    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: this.config.get('environment') === 'production',
      sameSite: 'strict',
    });

    return { message: 'Logged out from all devices successfully' };
  }

  private setRefreshTokenCookie(res: Response, refreshToken: string) {
    const isProduction = this.config.get('environment') === 'production';
    const expiresIn = this.config.get<string>('jwt.refresh.expiresIn');

    const maxAge = this.parseExpirationToMs(expiresIn);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge,
      path: '/',
    });
  }

  private parseExpirationToMs(expiresIn: string): number {
    const match = expiresIn.match(/^(\d+)([smhd])$/);
    if (!match) return 7 * 24 * 60 * 60 * 1000;

    const value = parseInt(match[1], 10);
    const unit = match[2];

    const multipliers = {
      s: 1000,
      m: 60 * 1000,
      h: 3600 * 1000,
      d: 86400 * 1000,
    };

    return value * multipliers[unit];
  }

  @Public()
  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify email address',
    description: 'Verify user email using the token sent to their email',
  })
  @ApiResponse({
    status: 200,
    description: 'Email verified successfully',
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid or expired token',
  })
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
    return this.authService.verifyEmail(verifyEmailDto);
  }

  @Public()
  @Post('resend-verification')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Resend verification email',
    description: 'Request a new verification email to be sent',
  })
  @ApiResponse({
    status: 200,
    description: 'Verification email sent',
  })
  @ApiResponse({
    status: 400,
    description: 'Email already verified or invalid email',
  })
  async resendVerification(@Body() resendDto: ResendVerificationDto) {
    return this.authService.resendVerificationEmail(resendDto.email);
  }

  // Optional: Add endpoint to check verification status
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('verification-status')
  @ApiOperation({ summary: 'Check email verification status' })
  async getVerificationStatus(@CurrentUser() user: any) {
    return this.authService.getVerificationStatus(user.id);
  }

  @Public()
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({ summary: 'Initiate Google OAuth login' })
  async googleAuth() {}
  @Public()
  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({ summary: 'Google OAuth callback' })
  async googleAuthCallback(
    @CurrentUser() user: any,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const deviceId = req.headers['x-device-id'] as string;
    const userAgent = req.headers['user-agent'];
    const ipAddress = req.ip;

    const socialAuthDto: SocialAuthDto = {
      googleId: user.googleId,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      avatar: user.avatar,
      provider: 'GOOGLE',
    };

    const result = await this.authService.googleLogin(
      socialAuthDto,
      deviceId,
      userAgent,
      ipAddress,
    );

    this.setRefreshTokenCookie(res, result.refreshToken);

    const frontendUrl = this.config.get<string>('frontendUrl');

    res.redirect(
      `${frontendUrl}/auth/callback?token=${result.accessToken}&isNewUser=${result.isNewUser}`,
    );
  }
  @Public()
  @Post('google/token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Exchange Google token for app tokens' })
  async googleTokenLogin(
    @Body() socialAuthDto: SocialAuthDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const deviceId = req.headers['x-device-id'] as string;
    const userAgent = req.headers['user-agent'];
    const ipAddress = req.ip;

    const result = await this.authService.googleLogin(
      socialAuthDto,
      deviceId,
      userAgent,
      ipAddress,
    );

    this.setRefreshTokenCookie(res, result.refreshToken);

    return {
      accessToken: result.accessToken,
      expiresIn: result.expiresIn,
      user: result.user,
      isNewUser: result.isNewUser,
    };
  }

  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @ApiOperation({
    summary: 'Request password reset',
    description: 'Send password reset link to user email',
  })
  @ApiResponse({
    status: 200,
    description: 'If email exists, password reset link has been sent',
  })
  @ApiResponse({
    status: 429,
    description: 'Too many requests',
  })
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto);
  }

  @Public()
  @Post('validate-reset-token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Validate password reset token',
    description: 'Check if reset token is valid and not expired',
  })
  @ApiResponse({
    status: 200,
    description: 'Token validation result',
    schema: {
      example: {
        valid: true,
        message: 'Token is valid',
        email: 'user@example.com',
      },
    },
  })
  async validateResetToken(@Body() validateTokenDto: ValidateResetTokenDto) {
    return this.authService.validateResetToken(validateTokenDto);
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // Max 5 attempts per minute
  @ApiOperation({
    summary: 'Reset password with token',
    description: 'Reset user password using the token from email',
  })
  @ApiResponse({
    status: 200,
    description: 'Password reset successfully',
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid or expired token, or weak password',
  })
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(resetPasswordDto);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Change password (authenticated)',
    description: 'Change password for currently logged in user',
  })
  @ApiResponse({
    status: 200,
    description: 'Password changed successfully',
  })
  @ApiResponse({
    status: 400,
    description: 'Current password incorrect or new password too weak',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
  })
  async changePassword(
    @CurrentUser() user: any,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    return this.authService.changePassword(user.id, changePasswordDto);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('lockout-status')
  @ApiOperation({
    summary: 'Get account lockout status',
    description:
      'Check current account lockout status and failed login attempts',
  })
  @ApiResponse({
    status: 200,
    description: 'Account lockout status',
    type: AccountLockoutResponseDto,
  })
  async getLockoutStatus(@CurrentUser() user: any) {
    return this.authService.getAccountLockoutStatus(user.id);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('login-history')
  @ApiOperation({
    summary: 'Get login history',
    description: 'Retrieve recent login attempts for the authenticated user',
  })
  @ApiResponse({
    status: 200,
    description: 'Login history',
    schema: {
      example: [
        {
          timestamp: '2025-10-05T13:14:35.000Z',
          ipAddress: '192.168.1.1',
          userAgent: 'Mozilla/5.0...',
          success: true,
        },
      ],
    },
  })
  async getLoginHistory(@CurrentUser() user: any) {
    return this.authService.getLoginHistory(user.id);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @Post('admin/unlock-account')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Unlock user account (Admin only)',
    description: 'Manually unlock a locked user account',
  })
  @ApiResponse({
    status: 200,
    description: 'Account unlocked successfully',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async unlockAccount(@Body() unlockDto: UnlockAccountDto) {
    return this.authService.unlockAccount(unlockDto.email);
  }
}

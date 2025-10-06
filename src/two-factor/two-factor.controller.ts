import {
  Controller,
  Get,
  Post,
  Delete,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiResponse,
} from '@nestjs/swagger';
import { TwoFactorService } from './two-factor.service';
import {
  Enable2FADto,
  Disable2FADto,
  TwoFactorSetupResponseDto,
  TwoFactorStatusDto,
  BackupCodesResponseDto,
} from './dto/two-factor.dto';
import { JwtAuthGuard } from '@src/auth/guards/jwt-auth.guard';
import { CurrentUser } from '@src/auth/decorator/current-user.decorator';
import { UserService } from '@src/user/user.service';
import { BadRequestException } from '@nestjs/common';

@ApiTags('two-factor-auth')
@ApiBearerAuth()
@Controller('two-factor')
@UseGuards(JwtAuthGuard)
export class TwoFactorController {
  constructor(
    private readonly twoFactorService: TwoFactorService,
    private readonly userService: UserService,
  ) {}

  @Get('status')
  @ApiOperation({
    summary: 'Get 2FA status',
    description: 'Check if two-factor authentication is enabled',
  })
  @ApiResponse({
    status: 200,
    description: '2FA status',
    type: TwoFactorStatusDto,
  })
  async get2FAStatus(@CurrentUser() user: any): Promise<TwoFactorStatusDto> {
    return this.twoFactorService.get2FAStatus(user.id);
  }

  @Post('setup')
  @ApiOperation({
    summary: 'Generate 2FA setup QR code',
    description: 'Generate QR code for setting up two-factor authentication',
  })
  @ApiResponse({
    status: 200,
    description: '2FA setup information with QR code',
    type: TwoFactorSetupResponseDto,
  })
  async setup2FA(@CurrentUser() user: any): Promise<TwoFactorSetupResponseDto> {
    const { secret, otpauthUrl, qrCode } =
      await this.twoFactorService.generateSecret(user.id);

    return {
      secret,
      otpauthUrl,
      qrCode,
      message:
        'Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)',
    };
  }

  @Post('enable')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Enable 2FA',
    description: 'Enable two-factor authentication with verification code',
  })
  @ApiResponse({
    status: 200,
    description: '2FA enabled successfully with backup codes',
    type: BackupCodesResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid verification code',
  })
  async enable2FA(
    @CurrentUser() user: any,
    @Body() dto: Enable2FADto,
    @Body('secret') secret: string,
  ): Promise<BackupCodesResponseDto> {
    if (!secret) {
      throw new BadRequestException(
        'Secret is required. Call /two-factor/setup first.',
      );
    }

    const result = await this.twoFactorService.enable2FA(
      user.id,
      secret,
      dto.code,
    );

    return result;
  }

  @Delete('disable')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Disable 2FA',
    description: 'Disable two-factor authentication (requires password)',
  })
  @ApiResponse({
    status: 200,
    description: '2FA disabled successfully',
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid password or verification code',
  })
  async disable2FA(
    @CurrentUser() user: any,
    @Body() dto: Disable2FADto,
  ): Promise<{ message: string }> {
    // Verify password
    const userData = await this.userService.findByEmail(user.email);
    const isPasswordValid = await this.userService.validatePassword(
      dto.password,
      userData.password,
    );

    if (!isPasswordValid) {
      throw new BadRequestException('Invalid password');
    }

    // If 2FA code provided, verify it
    if (dto.code) {
      const isCodeValid = await this.twoFactorService.verify2FACode(
        user.id,
        dto.code,
      );
      if (!isCodeValid) {
        throw new BadRequestException('Invalid verification code');
      }
    }

    const result = await this.twoFactorService.disable2FA(user.id);

    return result;
  }

  @Post('backup-codes/regenerate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Regenerate backup codes',
    description: 'Generate new backup codes (invalidates old ones)',
  })
  @ApiResponse({
    status: 200,
    description: 'New backup codes generated',
    type: BackupCodesResponseDto,
  })
  async regenerateBackupCodes(
    @CurrentUser() user: any,
  ): Promise<BackupCodesResponseDto> {
    const backupCodes = await this.twoFactorService.regenerateBackupCodes(
      user.id,
    );

    return {
      backupCodes,
      message:
        'New backup codes generated. Save these securely - old codes are now invalid.',
    };
  }
}

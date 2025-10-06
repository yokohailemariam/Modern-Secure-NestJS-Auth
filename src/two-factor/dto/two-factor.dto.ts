import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsString,
  IsNotEmpty,
  Length,
  Matches,
  IsOptional,
} from 'class-validator';

export class Enable2FADto {
  @ApiProperty({
    example: '123456',
    description: '6-digit TOTP code from authenticator app',
  })
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  @Matches(/^\d{6}$/, { message: 'Code must be exactly 6 digits' })
  code: string;
}

export class Verify2FADto {
  @ApiProperty({
    example: '123456',
    description: '6-digit TOTP code or backup code',
  })
  @IsString()
  @IsNotEmpty()
  code: string;
}

export class Disable2FADto {
  @ApiProperty({
    example: 'MyPassword123!',
    description: 'Current password for verification',
  })
  @IsString()
  @IsNotEmpty()
  password: string;

  @ApiPropertyOptional({
    example: '123456',
    description: '6-digit TOTP code (optional if using backup code)',
  })
  @IsOptional()
  @IsString()
  code?: string;
}

export class TwoFactorSetupResponseDto {
  @ApiProperty({
    example:
      'otpauth://totp/MyApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp',
  })
  otpauthUrl: string;

  @ApiProperty({
    example: 'JBSWY3DPEHPK3PXP',
  })
  secret: string;

  @ApiProperty({
    example: 'data:image/png;base64,iVBORw0KG...',
  })
  qrCode: string;

  @ApiProperty()
  message: string;
}

export class TwoFactorStatusDto {
  @ApiProperty({ example: true })
  enabled: boolean;

  @ApiProperty({ example: 'TOTP' })
  method?: string;

  @ApiProperty({ example: '2025-10-06T05:24:21.000Z' })
  enabledAt?: Date;

  @ApiProperty({ example: '2025-10-06T05:24:21.000Z' })
  lastUsedAt?: Date;

  @ApiProperty({ example: 8 })
  remainingBackupCodes?: number;
}

export class BackupCodesResponseDto {
  @ApiProperty({
    example: ['ABCD-1234', 'EFGH-5678', 'IJKL-9012'],
    description: 'One-time use backup codes (save these securely!)',
  })
  backupCodes: string[];

  @ApiProperty()
  message: string;
}

export class LoginWith2FADto {
  @ApiProperty({ example: 'user@example.com' })
  @IsString()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ example: 'MyPassword123!' })
  @IsString()
  @IsNotEmpty()
  password: string;

  @ApiProperty({
    example: '123456',
    description: '6-digit TOTP code or backup code',
  })
  @IsString()
  @IsNotEmpty()
  twoFactorCode: string;
}

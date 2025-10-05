import { ApiProperty } from '@nestjs/swagger';

export class AccountLockoutResponseDto {
  @ApiProperty({ example: true })
  isLocked: boolean;

  @ApiProperty({ example: 3 })
  remainingAttempts: number;

  @ApiProperty({ example: '2025-10-05T14:30:00.000Z' })
  lockedUntil?: Date;

  @ApiProperty({
    example: 'Account locked due to too many failed login attempts',
  })
  message: string;
}

export class UnlockAccountDto {
  @ApiProperty({ example: 'user@example.com' })
  email: string;
}

export class LoginHistoryDto {
  @ApiProperty()
  timestamp: Date;

  @ApiProperty()
  ipAddress?: string;

  @ApiProperty()
  userAgent?: string;

  @ApiProperty()
  success: boolean;

  @ApiProperty()
  failureReason?: string;
}

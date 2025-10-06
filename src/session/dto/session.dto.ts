import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsOptional } from 'class-validator';

export class SessionResponseDto {
  @ApiProperty({ example: '550e8400-e29b-41d4-a716-446655440000' })
  id: string;

  @ApiProperty({ example: 'Chrome on Windows' })
  deviceName: string;

  @ApiProperty({ example: 'desktop' })
  deviceType: string;

  @ApiPropertyOptional({ example: 'Chrome' })
  browser?: string;

  @ApiPropertyOptional({ example: 'Windows 10' })
  os?: string;

  @ApiPropertyOptional({ example: '192.168.1.1' })
  ipAddress?: string;

  @ApiPropertyOptional({
    example: {
      city: 'New York',
      country: 'United States',
      latitude: 40.7128,
      longitude: -74.006,
    },
  })
  location?: any;

  @ApiProperty({ example: '2025-10-06T05:24:21.000Z' })
  createdAt: Date;

  @ApiProperty({ example: '2025-10-06T05:24:21.000Z' })
  lastUsedAt: Date;

  @ApiProperty({ example: '2025-10-13T05:24:21.000Z' })
  expiresAt: Date;

  @ApiProperty({ example: true })
  isCurrent: boolean;

  @ApiProperty({ example: false })
  isExpired: boolean;
}

export class RevokeSessionDto {
  @ApiProperty({
    example: '550e8400-e29b-41d4-a716-446655440000',
    description: 'Session ID to revoke',
  })
  @IsString()
  sessionId: string;
}

export class RevokeMultipleSessionsDto {
  @ApiProperty({
    example: [
      '550e8400-e29b-41d4-a716-446655440000',
      '660e8400-e29b-41d4-a716-446655440001',
    ],
    description: 'Array of session IDs to revoke',
  })
  sessionIds: string[];
}

export class SessionStatsDto {
  @ApiProperty({ example: 3 })
  totalSessions: number;

  @ApiProperty({ example: 2 })
  activeSessions: number;

  @ApiProperty({ example: 1 })
  expiredSessions: number;

  @ApiProperty({ example: ['desktop', 'mobile'] })
  deviceTypes: string[];

  @ApiProperty({ example: '2025-10-06T05:24:21.000Z' })
  lastActivity: Date;
}

export class UpdateSessionDto {
  @ApiPropertyOptional({ example: 'My iPhone' })
  @IsOptional()
  @IsString()
  deviceName?: string;
}

import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Role } from '@prisma/generated/prisma';

export class AuthResponseDto {
  @ApiProperty()
  accessToken: string;

  @ApiProperty()
  refreshToken: string;

  @ApiProperty()
  expiresIn: number;

  @ApiPropertyOptional()
  requires2FA?: boolean;

  @ApiProperty()
  user: {
    id: string;
    email: string;
    firstName?: string;
    lastName?: string;
    role: Role;
  };
}

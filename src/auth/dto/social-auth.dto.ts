import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Role } from '@prisma/generated/prisma';

export class SocialAuthDto {
  @ApiPropertyOptional()
  googleId?: string;

  @ApiPropertyOptional()
  facebookId?: string;

  @ApiPropertyOptional()
  githubId?: string;

  @ApiPropertyOptional()
  username?: string;

  @ApiProperty()
  email: string;

  @ApiPropertyOptional()
  firstName?: string;

  @ApiPropertyOptional()
  lastName?: string;

  @ApiPropertyOptional()
  avatar?: string;

  @ApiProperty()
  provider: string;
}

export class SocialAuthResponseDto {
  @ApiProperty()
  accessToken: string;

  @ApiProperty()
  refreshToken: string;

  @ApiProperty()
  expiresIn: number;

  @ApiProperty()
  user: {
    id: string;
    email: string;
    firstName?: string;
    lastName?: string;
    role: Role;
    avatar?: string;
    provider: string;
    username?: string;
  };

  @ApiProperty()
  isNewUser: boolean;
}

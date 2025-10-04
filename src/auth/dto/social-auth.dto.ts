import { ApiProperty } from '@nestjs/swagger';
import { Role } from '@prisma/generated/prisma';

export class SocialAuthDto {
  @ApiProperty()
  googleId?: string;

  @ApiProperty()
  facebookId?: string;

  @ApiProperty()
  email: string;

  @ApiProperty()
  firstName?: string;

  @ApiProperty()
  lastName?: string;

  @ApiProperty()
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
  };

  @ApiProperty()
  isNewUser: boolean;
}

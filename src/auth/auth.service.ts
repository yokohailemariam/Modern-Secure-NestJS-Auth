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

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  async register(registerDto: RegisterDto): Promise<AuthResponseDto> {
    const user = await this.userService.create(registerDto);
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

    const isPasswordValid = await this.userService.validatePassword(
      loginDto.password,
      user.password,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
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
        // Link social account to existing user
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
        // Create new user
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

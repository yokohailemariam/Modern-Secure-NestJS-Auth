import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '@prisma/prisma.service';
import { SessionResponseDto, SessionStatsDto } from './dto/session.dto';
import { UAParser } from 'ua-parser-js';

@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name);

  constructor(private readonly prisma: PrismaService) {}

  private parseUserAgent(userAgent: string): {
    deviceName: string;
    deviceType: string;
    browser: string;
    os: string;
  } {
    const parser = new UAParser(userAgent);
    const result = parser.getResult();

    const browser = result.browser.name || 'Unknown Browser';
    const os = result.os.name
      ? `${result.os.name}${result.os.version ? ' ' + result.os.version : ''}`
      : 'Unknown OS';

    const deviceType = result.device.type || 'desktop';
    const deviceModel = result.device.model || '';

    let deviceName = '';
    if (deviceModel) {
      deviceName = deviceModel;
    } else if (deviceType === 'mobile') {
      deviceName = `${browser} on ${os}`;
    } else {
      deviceName = `${browser} on ${os}`;
    }

    return {
      deviceName,
      deviceType,
      browser,
      os,
    };
  }

  async getUserSessions(
    userId: string,
    currentTokenId?: string,
  ): Promise<SessionResponseDto[]> {
    const sessions = await this.prisma.refreshToken.findMany({
      where: {
        userId,
        isRevoked: false,
      },
      orderBy: {
        lastUsedAt: 'desc',
      },
    });

    const now = new Date();

    return sessions.map((session) => ({
      id: session.id,
      deviceName: session.deviceName || 'Unknown Device',
      deviceType: session.deviceType || 'desktop',
      browser: session.browser || undefined,
      os: session.os || undefined,
      ipAddress: session.ipAddress || undefined,
      location: session.location || undefined,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt || session.createdAt,
      expiresAt: session.expiresAt,
      isCurrent: session.id === currentTokenId,
      isExpired: session.expiresAt < now,
    }));
  }

  async getSessionStats(userId: string): Promise<SessionStatsDto> {
    const sessions = await this.prisma.refreshToken.findMany({
      where: {
        userId,
        isRevoked: false,
      },
    });

    const now = new Date();
    const activeSessions = sessions.filter((s) => s.expiresAt >= now);
    const expiredSessions = sessions.filter((s) => s.expiresAt < now);
    const deviceTypes = [
      ...new Set(sessions.map((s) => s.deviceType).filter(Boolean)),
    ];

    const lastActivity = sessions.reduce((latest, session) => {
      const sessionDate = session.lastUsedAt || session.createdAt;
      return sessionDate > latest ? sessionDate : latest;
    }, new Date(0));

    return {
      totalSessions: sessions.length,
      activeSessions: activeSessions.length,
      expiredSessions: expiredSessions.length,
      deviceTypes,
      lastActivity: lastActivity.getTime() > 0 ? lastActivity : new Date(),
    };
  }

  async getSessionById(
    sessionId: string,
    userId: string,
  ): Promise<SessionResponseDto> {
    const session = await this.prisma.refreshToken.findFirst({
      where: {
        id: sessionId,
        userId,
      },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    const now = new Date();

    return {
      id: session.id,
      deviceName: session.deviceName || 'Unknown Device',
      deviceType: session.deviceType || 'desktop',
      browser: session.browser || undefined,
      os: session.os || undefined,
      ipAddress: session.ipAddress || undefined,
      location: session.location || undefined,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt || session.createdAt,
      expiresAt: session.expiresAt,
      isCurrent: false,
      isExpired: session.expiresAt < now,
    };
  }

  async revokeSession(
    sessionId: string,
    userId: string,
    currentTokenId?: string,
  ): Promise<void> {
    const session = await this.prisma.refreshToken.findFirst({
      where: {
        id: sessionId,
        userId,
      },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    if (currentTokenId && sessionId === currentTokenId) {
      throw new ForbiddenException(
        'Cannot revoke current session. Use logout instead.',
      );
    }

    await this.prisma.refreshToken.update({
      where: { id: sessionId },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
      },
    });

    this.logger.log(`Session ${sessionId} revoked for user ${userId}`);
  }

  async revokeMultipleSessions(
    sessionIds: string[],
    userId: string,
    currentTokenId?: string,
  ): Promise<{ revoked: number }> {
    const idsToRevoke = sessionIds.filter((id) => id !== currentTokenId);

    if (idsToRevoke.length === 0) {
      return { revoked: 0 };
    }

    const result = await this.prisma.refreshToken.updateMany({
      where: {
        id: { in: idsToRevoke },
        userId,
        isRevoked: false,
      },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
      },
    });

    this.logger.log(`${result.count} sessions revoked for user ${userId}`);

    return { revoked: result.count };
  }

  async revokeAllOtherSessions(
    userId: string,
    currentTokenId: string,
  ): Promise<{ revoked: number }> {
    const result = await this.prisma.refreshToken.updateMany({
      where: {
        userId,
        id: { not: currentTokenId },
        isRevoked: false,
      },
      data: {
        isRevoked: true,
        revokedAt: new Date(),
      },
    });

    this.logger.log(
      `${result.count} sessions revoked for user ${userId}, keeping current session`,
    );

    return { revoked: result.count };
  }

  async updateSessionName(
    sessionId: string,
    userId: string,
    deviceName: string,
  ): Promise<SessionResponseDto> {
    const session = await this.prisma.refreshToken.findFirst({
      where: {
        id: sessionId,
        userId,
      },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    const updated = await this.prisma.refreshToken.update({
      where: { id: sessionId },
      data: { deviceName },
    });

    const now = new Date();

    return {
      id: updated.id,
      deviceName: updated.deviceName || 'Unknown Device',
      deviceType: updated.deviceType || 'desktop',
      browser: updated.browser || undefined,
      os: updated.os || undefined,
      ipAddress: updated.ipAddress || undefined,
      location: updated.location || undefined,
      createdAt: updated.createdAt,
      lastUsedAt: updated.lastUsedAt || updated.createdAt,
      expiresAt: updated.expiresAt,
      isCurrent: false,
      isExpired: updated.expiresAt < now,
    };
  }

  async updateLastUsed(tokenId: string): Promise<void> {
    await this.prisma.refreshToken.update({
      where: { id: tokenId },
      data: { lastUsedAt: new Date() },
    });
  }

  async createSession(
    userId: string,
    token: string,
    expiresAt: Date,
    deviceId?: string,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<string> {
    let deviceInfo = {
      deviceName: 'Unknown Device',
      deviceType: 'desktop',
      browser: undefined,
      os: undefined,
    };

    if (userAgent) {
      deviceInfo = this.parseUserAgent(userAgent);
    }

    const session = await this.prisma.refreshToken.create({
      data: {
        userId,
        token,
        expiresAt,
        deviceId,
        userAgent,
        ipAddress,
        deviceName: deviceInfo.deviceName,
        deviceType: deviceInfo.deviceType,
        browser: deviceInfo.browser,
        os: deviceInfo.os,
        lastUsedAt: new Date(),
      },
    });

    return session.id;
  }

  async cleanupExpiredSessions(): Promise<number> {
    const result = await this.prisma.refreshToken.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });

    this.logger.log(`Cleaned up ${result.count} expired sessions`);
    return result.count;
  }

  async getSessionsByDeviceType(
    userId: string,
    deviceType: string,
  ): Promise<SessionResponseDto[]> {
    const sessions = await this.prisma.refreshToken.findMany({
      where: {
        userId,
        deviceType,
        isRevoked: false,
      },
      orderBy: {
        lastUsedAt: 'desc',
      },
    });

    const now = new Date();

    return sessions.map((session) => ({
      id: session.id,
      deviceName: session.deviceName || 'Unknown Device',
      deviceType: session.deviceType || 'desktop',
      browser: session.browser || undefined,
      os: session.os || undefined,
      ipAddress: session.ipAddress || undefined,
      location: session.location || undefined,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt || session.createdAt,
      expiresAt: session.expiresAt,
      isCurrent: false,
      isExpired: session.expiresAt < now,
    }));
  }
}

import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { SessionService } from './session.service';

@Injectable()
export class SessionCleanupService {
  private readonly logger = new Logger(SessionCleanupService.name);

  constructor(private readonly sessionService: SessionService) {}

  @Cron(CronExpression.EVERY_DAY_AT_3AM)
  async handleCleanup() {
    this.logger.log('Starting session cleanup...');

    try {
      const deleted = await this.sessionService.cleanupExpiredSessions();
      this.logger.log(
        `Session cleanup completed. Deleted ${deleted} expired sessions.`,
      );
    } catch (error) {
      this.logger.error('Session cleanup failed', error.stack);
    }
  }
}

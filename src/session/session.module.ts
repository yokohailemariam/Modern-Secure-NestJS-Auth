import { Module } from '@nestjs/common';
import { SessionService } from './session.service';
import { SessionController } from './session.controller';
import { SessionCleanupService } from './session-cleanup.service';

@Module({
  providers: [SessionService, SessionCleanupService],
  controllers: [SessionController],
  exports: [SessionService],
})
export class SessionModule {}

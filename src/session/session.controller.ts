import {
  Controller,
  Get,
  Delete,
  Patch,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiResponse,
  ApiParam,
} from '@nestjs/swagger';
import { SessionService } from './session.service';
import {
  SessionResponseDto,
  RevokeMultipleSessionsDto,
  SessionStatsDto,
  UpdateSessionDto,
} from './dto/session.dto';
import { JwtAuthGuard } from '@src/auth/guards/jwt-auth.guard';
import { CurrentUser } from '@src/auth/decorator/current-user.decorator';

@ApiTags('sessions')
@ApiBearerAuth()
@Controller('sessions')
@UseGuards(JwtAuthGuard)
export class SessionController {
  constructor(private readonly sessionService: SessionService) {}

  @Get()
  @ApiOperation({
    summary: 'Get all active sessions',
    description: 'Retrieve all active sessions for the authenticated user',
  })
  @ApiResponse({
    status: 200,
    description: 'List of active sessions',
    type: [SessionResponseDto],
  })
  async getAllSessions(
    @CurrentUser() user: any,
  ): Promise<SessionResponseDto[]> {
    return this.sessionService.getUserSessions(user.id, user.tokenId);
  }

  @Get('stats')
  @ApiOperation({
    summary: 'Get session statistics',
    description: 'Get statistics about user sessions',
  })
  @ApiResponse({
    status: 200,
    description: 'Session statistics',
    type: SessionStatsDto,
  })
  async getSessionStats(@CurrentUser() user: any): Promise<SessionStatsDto> {
    return this.sessionService.getSessionStats(user.id);
  }

  @Get('device/:deviceType')
  @ApiOperation({
    summary: 'Get sessions by device type',
    description:
      'Get all sessions for a specific device type (mobile, desktop, tablet)',
  })
  @ApiParam({
    name: 'deviceType',
    description: 'Device type',
    enum: ['mobile', 'desktop', 'tablet'],
  })
  @ApiResponse({
    status: 200,
    description: 'List of sessions for device type',
    type: [SessionResponseDto],
  })
  async getSessionsByDeviceType(
    @CurrentUser() user: any,
    @Param('deviceType') deviceType: string,
  ): Promise<SessionResponseDto[]> {
    return this.sessionService.getSessionsByDeviceType(user.id, deviceType);
  }

  @Get(':sessionId')
  @ApiOperation({
    summary: 'Get session details',
    description: 'Get detailed information about a specific session',
  })
  @ApiParam({ name: 'sessionId', description: 'Session ID' })
  @ApiResponse({
    status: 200,
    description: 'Session details',
    type: SessionResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Session not found' })
  async getSessionById(
    @CurrentUser() user: any,
    @Param('sessionId') sessionId: string,
  ): Promise<SessionResponseDto> {
    return this.sessionService.getSessionById(sessionId, user.id);
  }

  @Delete(':sessionId')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Revoke a session',
    description: 'Revoke/logout a specific session',
  })
  @ApiParam({ name: 'sessionId', description: 'Session ID to revoke' })
  @ApiResponse({
    status: 200,
    description: 'Session revoked successfully',
  })
  @ApiResponse({
    status: 403,
    description: 'Cannot revoke current session',
  })
  @ApiResponse({ status: 404, description: 'Session not found' })
  async revokeSession(
    @CurrentUser() user: any,
    @Param('sessionId') sessionId: string,
  ): Promise<{ message: string }> {
    await this.sessionService.revokeSession(sessionId, user.id, user.tokenId);
    return { message: 'Session revoked successfully' };
  }

  @Delete()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Revoke multiple sessions',
    description: 'Revoke multiple sessions at once',
  })
  @ApiResponse({
    status: 200,
    description: 'Sessions revoked successfully',
    schema: {
      example: { revoked: 3, message: '3 session(s) revoked successfully' },
    },
  })
  async revokeMultipleSessions(
    @CurrentUser() user: any,
    @Body() dto: RevokeMultipleSessionsDto,
  ): Promise<{ revoked: number; message: string }> {
    const result = await this.sessionService.revokeMultipleSessions(
      dto.sessionIds,
      user.id,
      user.tokenId,
    );
    return {
      revoked: result.revoked,
      message: `${result.revoked} session(s) revoked successfully`,
    };
  }

  @Delete('revoke-all/except-current')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Revoke all other sessions',
    description: 'Revoke all sessions except the current one',
  })
  @ApiResponse({
    status: 200,
    description: 'All other sessions revoked',
    schema: {
      example: {
        revoked: 5,
        message: 'All other sessions revoked successfully',
      },
    },
  })
  async revokeAllOtherSessions(
    @CurrentUser() user: any,
  ): Promise<{ revoked: number; message: string }> {
    const result = await this.sessionService.revokeAllOtherSessions(
      user.id,
      user.tokenId,
    );
    return {
      revoked: result.revoked,
      message: 'All other sessions revoked successfully',
    };
  }

  @Patch(':sessionId')
  @ApiOperation({
    summary: 'Update session name',
    description: 'Update the display name of a session',
  })
  @ApiParam({ name: 'sessionId', description: 'Session ID' })
  @ApiResponse({
    status: 200,
    description: 'Session updated successfully',
    type: SessionResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Session not found' })
  async updateSessionName(
    @CurrentUser() user: any,
    @Param('sessionId') sessionId: string,
    @Body() dto: UpdateSessionDto,
  ): Promise<SessionResponseDto> {
    return this.sessionService.updateSessionName(
      sessionId,
      user.id,
      dto.deviceName,
    );
  }
}

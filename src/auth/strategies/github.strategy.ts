import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile } from 'passport-github2';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class GitHubStrategy extends PassportStrategy(Strategy, 'github') {
  private readonly logger = new Logger(GitHubStrategy.name);

  constructor(private readonly config: ConfigService) {
    super({
      clientID:
        config.get<string>('oauth.github.clientId') ||
        config.get<string>('GITHUB_CLIENT_ID'),
      clientSecret:
        config.get<string>('oauth.github.clientSecret') ||
        config.get<string>('GITHUB_CLIENT_SECRET'),
      callbackURL:
        config.get<string>('oauth.github.callbackUrl') ||
        config.get<string>('GITHUB_CALLBACK_URL'),
      scope: ['user:email', 'read:user'],
    });

    this.logger.log('GitHub Strategy initialized');
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (error: any, user?: any, info?: any) => void,
  ): Promise<any> {
    const { id, username, displayName, emails, photos } = profile;

    // GitHub may not always return email if user's email is private
    const email =
      emails && emails.length > 0
        ? emails[0].value
        : `${username}@github.user.noreply.github.com`;

    // Parse name from displayName
    const nameParts = displayName ? displayName.split(' ') : [username];
    const firstName = nameParts[0] || username;
    const lastName = nameParts.slice(1).join(' ') || '';

    const user = {
      githubId: id,
      username,
      email,
      firstName,
      lastName,
      avatar: photos && photos.length > 0 ? photos[0].value : null,
      accessToken,
      provider: 'GITHUB',
    };

    this.logger.log(`GitHub OAuth validation successful for user: ${username}`);

    done(null, user);
  }
}

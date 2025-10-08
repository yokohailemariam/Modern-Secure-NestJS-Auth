import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile } from 'passport-facebook';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
  private readonly logger = new Logger(FacebookStrategy.name);

  constructor(private readonly config: ConfigService) {
    super({
      clientID:
        config.get<string>('oauth.facebook.clientId') ||
        config.get<string>('FACEBOOK_CLIENT_ID'),
      clientSecret:
        config.get<string>('oauth.facebook.clientSecret') ||
        config.get<string>('FACEBOOK_CLIENT_SECRET'),
      callbackURL:
        config.get<string>('oauth.facebook.callbackUrl') ||
        config.get<string>('FACEBOOK_CALLBACK_URL'),
      scope: ['email', 'public_profile'],
      profileFields: ['id', 'displayName', 'name', 'emails', 'photos'],
    });

    this.logger.log('Facebook Strategy initialized');
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (error: any, user?: any, info?: any) => void,
  ): Promise<any> {
    const { id, name, emails, photos } = profile;

    // Facebook always provides email (it's required in our scope)
    const email = emails && emails.length > 0 ? emails[0].value : null;

    if (!email) {
      this.logger.warn(`Facebook user ${id} has no email address`);
      return done(new Error('Email is required for registration'), null);
    }

    const user = {
      facebookId: id,
      email,
      firstName: name?.givenName || '',
      lastName: name?.familyName || '',
      avatar: photos && photos.length > 0 ? photos[0].value : null,
      accessToken,
      provider: 'FACEBOOK',
    };

    this.logger.log(`Facebook OAuth validation successful for user: ${email}`);

    done(null, user);
  }
}

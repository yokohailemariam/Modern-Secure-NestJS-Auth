import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback, Profile } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private readonly config: ConfigService) {
    super({
      clientID:
        config.get<string>('oauth.google.clientId') ||
        config.get<string>('GOOGLE_CLIENT_ID'),
      clientSecret:
        config.get<string>('oauth.google.clientSecret') ||
        config.get<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL:
        config.get<string>('oauth.google.callbackUrl') ||
        config.get<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ): Promise<any> {
    const { id, name, emails, photos } = profile;

    const user = {
      googleId: id,
      email: emails[0].value,
      firstName: name.givenName,
      lastName: name.familyName,
      avatar: photos[0]?.value,
      accessToken,
    };

    done(null, user);
  }
}

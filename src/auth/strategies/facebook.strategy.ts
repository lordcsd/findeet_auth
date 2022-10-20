import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile } from 'passport-facebook';
import { config } from 'dotenv';

import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { configConstants } from 'src/constants/configConstants';

@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
  constructor(private readonly configService: ConfigService) {
    super({
      clientID: configService.get<string>(configConstants.facebookAuth.appId),
      clientSecret: configService.get<string>(
        configConstants.facebookAuth.apiKey,
      ),
      callbackURL: `${configService.get<string>(
        configConstants.service.root,
      )}/api/v1/auth/facebook/redirect`,
      scope: 'email',
      profileFields: ['emails', 'name'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (err: any, user: any, info?: any) => void,
  ): Promise<any> {
    console.log(profile);
    const { name, emails } = profile;
    const user = {
      email: emails[0].value,
      firstName: name.givenName,
      lastName: name.familyName,
      accessToken,
    };

    done(null, user);
  }
}

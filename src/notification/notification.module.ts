import { Module } from '@nestjs/common';
import { NotificationService } from './notification.service';

import { ConfigModule, ConfigService } from '@nestjs/config';
import { configConstants } from '../constants/configConstants';
import { MailjetModule } from 'nest-mailjet';

@Module({
  imports: [
    MailjetModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        apiKey: configService.get<string>(configConstants.mailjet.apiKey),
        apiSecret: configService.get<string>(configConstants.mailjet.apiSecret),
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [NotificationService],
})
export class NotificationModule {}

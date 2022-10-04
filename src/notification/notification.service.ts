import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MailjetService } from 'nest-mailjet';
import { configConstants } from 'src/constants/configConstants';

@Injectable()
export class NotificationService {
  constructor(
    private readonly mailService: MailjetService,
    private readonly configService: ConfigService,
  ) {}

  async sendMail(to: string, Subject: string, HTMLPart: string) {
    return await this.mailService.send({
      Messages: [
        {
          From: {
            Email: this.configService.get<string>(configConstants.email.source),
          },
          To: [
            {
              Email: to,
            },
          ],
          Subject,
          HTMLPart,
        },
      ],
    });
  }
}

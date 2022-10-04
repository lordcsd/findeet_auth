import Mailjet from 'node-mailjet';
import { emailSenderParams } from './dtos/emailSenderParams';

console.log(process.env.BCRYPT_SALT);

const mailjet = new Mailjet({
  apiKey: process.env.MJ_APIKEY_PUBLIC || 'your-api-key',
  apiSecret: process.env.MJ_APIKEY_PRIVATE || 'your-api-secret',
});

export async function mailSender(params: emailSenderParams) {
  const request = mailjet.post('send', { version: 'v3.1' }).request({
    Messages: [
      {
        From: {
          Email: 'dimgbachinonso@gmail.com',
          Name: 'Chinonso',
        },
        To: [
          {
            Email: 'dimgbachinonso@gmail.com',
            Name: 'Chinonso',
          },
        ],
        Subject: 'Greetings from Mailjet.',
        TextPart: 'My first Mailjet email',
        HTMLPart:
          "<h3>Dear passenger 1, welcome to <a href='https://www.mailjet.com/'>Mailjet</a>!</h3><br />May the delivery force be with you!",
        CustomID: 'AppGettingStartedTest',
      },
    ],
  });

  return await request;
}

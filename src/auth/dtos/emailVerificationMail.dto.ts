import { Transform } from 'class-transformer';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class EmailVerificationMail {
  @IsNotEmpty({ message: 'Email must not be empty' })
  @IsEmail({ message: 'Email ' })
  @Transform(({ value }) => value.toLowerCase())
  email: string;
}

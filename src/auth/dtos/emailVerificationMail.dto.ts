import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class EmailVerificationMail {
  @IsNotEmpty({ message: 'Email must not be empty' })
  @IsEmail({ message: 'Email ' })
  @Transform(({ value }) => value.toLowerCase())
  @ApiProperty({
    description: 'user Email',
    type: String,
    default: 'someone@gmail.com',
  })
  email: string;
}

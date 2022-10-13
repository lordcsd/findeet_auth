import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class CompleteLoginWithOTP {
  @ApiProperty({ description: 'User Email', default: 'someone@gmail.com' })
  @IsString({ message: 'Email: Must be a valid string' })
  @IsNotEmpty({ message: 'Email: Must not be empty' })
  @IsEmail({ message: 'Email: Must be a valid Email' })
  email: string;

  @ApiProperty({ description: 'Correct One time password' })
  @IsString({ message: 'otp: Must be a string' })
  @IsNotEmpty({ message: 'otp: Must not be empty' })
  otp: string;
}

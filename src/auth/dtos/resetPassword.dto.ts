import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';

export class ResetPasswordDTO {
  @IsNotEmpty({ message: 'Email cannot be empty' })
  @IsString({ message: 'Email: Must be a string' })
  @IsEmail({ message: 'Invalid Email' })
  @Transform(({ value }) => value.toLowerCase())
  @ApiProperty({
    type: String,
    description: 'User email',
    default: 'nicdos@gmail.com',
  })
  email: string;

  @IsNotEmpty({ message: 'oldPassword: Must not be empty' })
  @IsString({ message: 'oldPassword: Must be a string' })
  @MinLength(8, { message: 'oldPassword: Must have at least 8 characters' })
  @Matches(/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})/, {
    message: 'oldPassword: Invalid',
  })
  @ApiProperty({
    type: String,
    description: "User's secure pawword",
    default: 'ckjsdhcuisjdu7y12%^',
  })
  oldPassword: string;

  @IsNotEmpty({ message: 'newPassword: Must not be empty' })
  @IsString({ message: 'newPassword: Must be a string' })
  @MinLength(8, { message: 'newPassword: Must have at least 8 characters' })
  @Matches(/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})/, {
    message: 'newPassword: Is too weak',
  })
  @ApiProperty({
    type: String,
    description: "User's secure password",
    default: 'ckjsdhcuisjdu7y12%^',
  })
  newPassword: string;

  @IsNotEmpty({ message: 'confirmPassword: Must not be empty' })
  @IsString({ message: 'confirmPassword: Must be a string' })
  @MinLength(8, { message: 'confirmPassword: Must have at least 8 characters' })
  @Matches(/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})/, {
    message: 'confirmPassword: Is too weak',
  })
  @ApiProperty({
    type: String,
    description: 'Confirms password',
    default: 'ckjsdhcuisjdu7y12%^',
  })
  confirmPassword: string;
}

import {
  IsString,
  IsEnum,
  IsNotEmpty,
  Matches,
  MinLength,
  IsEmail,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { userRoles } from '../../dtos/userRole.dto';
import { ApiProperty } from '@nestjs/swagger';

export class signUpDTO {
  @IsNotEmpty({ message: 'Email cannot be empty' })
  @IsEmail({}, { message: 'Invalid Email' })
  @Transform(({ value }) => value.toLowerCase())
  @ApiProperty({
    type: String,
    description: 'User email',
    default: 'nicdos@gmail.com',
  })
  email: string;

  @IsNotEmpty()
  @IsString()
  @ApiProperty({
    type: String,
    description: 'User Full name',
    default: 'John',
  })
  name: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  @Matches(/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})/, {
    message: 'password too weak',
  })
  @ApiProperty({
    type: String,
    description: "User's secure pawword",
    default: 'ckjsdhcuisjdu7y12%^',
  })
  password: string;

  @IsNotEmpty()
  @IsEnum(userRoles, {
    message: `role must be ${Object.values(userRoles).join(' or ')}`,
  })
  @ApiProperty({
    type: String,
    description: 'User role',
    default: userRoles.student,
  })
  role: userRoles;
}

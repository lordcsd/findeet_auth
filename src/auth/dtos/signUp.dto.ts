import {
  IsString,
  IsEnum,
  IsNotEmpty,
  Matches,
  MinLength,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { userRoles } from '../../dtos/userRole.dto';
import { ApiProperty } from '@nestjs/swagger';

export class signUpDTO {
  @IsNotEmpty()
  @Matches(
    /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
    {
      message: 'Invalid email',
    },
  )
  @Transform(({ value }) => value.toLowerCase())
  @ApiProperty({
    type: String,
    description: 'User email',
    default: 'nicdos@gmail.com',
  })
  email: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({
    type: String,
    description: 'User First name',
    default: 'John',
  })
  firstName: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({
    type: String,
    description: 'User Last name',
    default: 'Doe',
  })
  lastName: string;

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

  @IsEnum(userRoles, {
    message: `role must be ${Object.values(userRoles).join(' or ')}`,
  })
  @IsNotEmpty()
  @ApiProperty({
    type: String,
    description: 'User role',
    default: userRoles.student,
  })
  role: userRoles;
}

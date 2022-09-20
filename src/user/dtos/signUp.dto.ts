import {
  IsString,
  IsEnum,
  IsNotEmpty,
  Matches,
  MinLength,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { userRoles } from 'src/dtos/userRole.dto';

export class signUpDTO {
  @IsNotEmpty()
  @Matches(
    /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
    {
      message: 'Invalid email',
    },
  )
  @Transform(({ value }) => value.toLowerCase())
  email: string;

  @IsString()
  firstName: string;

  @IsString()
  lastName: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  @Matches(/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})/, {
    message: 'password too weak',
  })
  password: string;

  @IsEnum(userRoles, {
    message: `role must be ${Object.values(userRoles).join(' or ')}`,
  })
  role: userRoles;
}

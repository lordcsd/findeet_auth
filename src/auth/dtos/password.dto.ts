import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Matches, MinLength } from 'class-validator';

export class PasswordDTO {
  @IsNotEmpty()
  @IsString()
  @MinLength(8, { message: 'password: must have at least 8 characters' })
  @Matches(/(?=.*[a-z])/, {
    message: 'password: must contain at least one lowercase alphabet',
  })
  @Matches(/(?=.*[A-Z])/, {
    message: 'password: must contain at least one uppercase alphabet',
  })
  @Matches(/(?=.*[0-9])/, {
    message: 'password: must contain at least one number',
  })
  @Matches(/\W|_/, {
    message: 'password: must contain at least one special character',
  })
  @ApiProperty({
    type: String,
    description: "User's secure pawword",
    default: 'ckjsdhcuisjdu7y12%^',
  })
  password: string;
}

import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CompleteForgotPasswordDTO {
  @IsNotEmpty()
  @IsString()
  @ApiProperty({ description: 'Valid token for reset password process' })
  token: string;
}

import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CompleteEmailVerificationDTO {
  @ApiProperty({
    description:
      'Valid token to identity user through the verification process',
    default: 'ckjnsdvjpmksdovmpsmkdkvnskv',
  })
  @IsString({ message: 'processToken: Must be a string' })
  @IsNotEmpty({ message: 'processToken: Must not be empty' })
  processToken: string;
}

export interface decodedProcessTokenDTO {
  id: string;
}

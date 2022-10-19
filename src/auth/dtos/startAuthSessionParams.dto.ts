import { ApiProperty } from '@nestjs/swagger';
import { IsEnum } from 'class-validator';
import { userRoles } from '../../dtos/userRole.dto';

export class StartAuthSessionDTO {
  @ApiProperty({ type: userRoles, default: userRoles.STUDENT })
  @IsEnum(userRoles, {
    message: `userRole must be ${Object.keys(userRoles).join(' or ')}`,
  })
  userRole: userRoles;
}

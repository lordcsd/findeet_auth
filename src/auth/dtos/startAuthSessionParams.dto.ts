import { ApiProperty } from '@nestjs/swagger';
import { IsEnum } from 'class-validator';
import { UserRoles } from '../../dtos/userRole.dto';

export class StartAuthSessionDTO {
  @ApiProperty({ type: UserRoles, default: UserRoles.STUDENT })
  @IsEnum(UserRoles, {
    message: `userRole must be ${Object.keys(UserRoles).join(' or ')}`,
  })
  userRole: UserRoles;
}

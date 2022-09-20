import { Module } from '@nestjs/common';
import { SharedModule } from '../shared/shared.modules';
import { UserService } from './user.service';

@Module({
  imports: [SharedModule],
  controllers: [],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}

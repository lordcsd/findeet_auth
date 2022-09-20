import { Module } from '@nestjs/common';
import { CustomRepository } from 'src/database/repositories/customRepository';

@Module({
  imports: [],
  providers: [CustomRepository],
  controllers: [],
  exports: [CustomRepository],
})
export class SharedModule {}

import { Module } from '@nestjs/common';
import { CustomRepository } from '../database/repositories/customRepository';
import { Transport } from '@nestjs/microservices/enums';
import { ClientsModule } from '@nestjs/microservices/module';

@Module({
  imports: [],
  providers: [CustomRepository],
  controllers: [],
  exports: [CustomRepository],
})
export class SharedModule {}

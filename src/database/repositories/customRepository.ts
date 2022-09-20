import { User } from '../../entities/user.entity';
import { DataSource, Repository } from 'typeorm';
import { Injectable } from '@nestjs/common';

@Injectable()
export class CustomRepository {
  constructor(private dataSource: DataSource) {}

  UserRepository(): Repository<User> {
    return this.dataSource.getRepository(User);
  }
}

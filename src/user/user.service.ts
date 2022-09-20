import { Injectable } from '@nestjs/common';
import { User } from '../entities/user.entity';
import { Repository } from 'typeorm';
import { CustomRepository } from '../database/repositories/customRepository';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UserService {
  userRepository: Repository<User>;

  constructor(private readonly customRepository: CustomRepository) {
    this.userRepository = this.customRepository.UserRepository();
  }

  async getUserByEmail(email: string) {
    const user = await this.userRepository.findOne({
      where: { email: email },
    });
    return user;
  }
}

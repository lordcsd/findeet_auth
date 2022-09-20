import { Injectable } from '@nestjs/common';
import { User } from 'src/entities/user.entity';
import { loginDTO } from '../auth/dtos/login.dto';
import { signUpDTO } from './dtos/signup.dto';
import { Repository } from 'typeorm';
import { CustomRepository } from 'src/database/repositories/customRepository';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { configConstants } from 'src/constants/configConstants';

@Injectable()
export class UserService {
  userRepository: Repository<User>;

  constructor(
    private readonly customRepository: CustomRepository,
    private readonly configService: ConfigService,
  ) {
    this.userRepository = this.customRepository.UserRepository();
  }

  async getUserByEmail(email: string) {
    const user = await this.userRepository.findOne({
      where: { email: email },
    });

    return user;
  }
}

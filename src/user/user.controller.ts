import { Controller, Post, Body } from '@nestjs/common';
import { loginDTO } from '../auth/dtos/login.dto';
import { signUpDTO } from './dtos/signup.dto';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}
}

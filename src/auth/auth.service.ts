import {
  ConflictException,
  Injectable,
  Inject,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { configConstants } from '../constants/configConstants';
import { loginDTO } from './dtos/login.dto';
import { signUpDTO } from './dtos/signUp.dto';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { CustomRepository } from '../database/repositories/customRepository';
import { FindeetAppResponse } from 'findeet-api-package';
import { AuthProviders } from 'src/constants/authProviders';
import { ClientProxy } from '@nestjs/microservices/client';
import { firstValueFrom } from 'rxjs';

import {} from 'findeet-api-package';
@Injectable()
export class AuthService {
  userRepository: Repository<User>;
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly customRepository: CustomRepository,
    @Inject('NOTIF_SERVICE') private client: ClientProxy,
  ) {
    this.userRepository = this.customRepository.UserRepository();

    // setInterval(async () => {
    //   console.log(await firstValueFrom(this.client.emit('SEND_MAIL', {})));
    // }, 5000);
  }

  jwt_secret = this.configService.get<string>(configConstants.jwt.secret);

  async validate(email: string, password: string) {
    const user = await this.userService.getUserByEmail(email);

    if (!user) {
      return null;
    }

    //compare password
    const passwordIsValid = await bcrypt.compare(password, user.password);
    return passwordIsValid ? user : null;
  }

  async signUp(details: signUpDTO): Promise<FindeetAppResponse> {
    const alreadyExisting = await this.userRepository.findOne({
      where: { email: details.email },
    });

    if (alreadyExisting) {
      throw new ConflictException('Email Already in use');
    }
    const salt = Number(this.configService.get(configConstants.bcrypt.salt));
    details.password = await bcrypt.hash(details.password, salt);

    await this.userRepository.save({
      firstName: details.firstName,
      lastName: details.lastName,
      email: details.email,
      password: details.password,
      role: details.role,
    });

    return FindeetAppResponse.Ok('', 'New User created', 200);
  }

  async login(user: loginDTO): Promise<FindeetAppResponse> {
    const fetchedUser = await this.validate(user.email, user.password);

    if (fetchedUser && fetchedUser.authProvider == AuthProviders.local) {
      if (!fetchedUser.emailVerified) {
        throw new UnauthorizedException('Email not verified');
      }

      const payload = {
        email: user.email,
        id: fetchedUser.id,
      };

      return FindeetAppResponse.Ok(
        {
          access_token: this.jwtService.sign(payload, {
            secret: this.jwt_secret,
            expiresIn: 7200,
          }),
        },
        'Login Successful',
        201,
      );
    }

    throw new UnauthorizedException('Invalid credentials');
  }

  googleLogin(req, userRole: string) {
    if (!req.user) {
      return 'No user from google';
    }

    return {
      message: 'User information from google',
      user: { ...req.user, userRole },
    };
  }
}

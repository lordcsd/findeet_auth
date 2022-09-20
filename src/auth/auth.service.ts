import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { configConstants } from 'src/constants/configConstants';
import { loginDTO } from 'src/auth/dtos/login.dto';
import { signUpDTO } from 'src/user/dtos/signup.dto';
import { Repository } from 'typeorm';
import { User } from 'src/entities/user.entity';

@Injectable()
export class AuthService {
  userRepository: Repository<User>;
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  jwt_secret = this.configService.get<string>(configConstants.jwt.secret);

  async validate(email: string, password: string) {
    const user = await this.userService.getUserByEmail(email);

    if (!user) {
      return null;
    }

    //compare password
    const passwordIsValid = await bcrypt.compare(password, user.password); //password == user['password'];
    return passwordIsValid ? user : null;
  }

  async signUp(details: signUpDTO) {
    const salt = Number(this.configService.get(configConstants.bcrypt.salt));
    details.password = await bcrypt.hash(details.password, salt);

    const createdUser = await this.userRepository.save({
      firstName: details.firstName,
      lastName: details.lastName,
      email: details.email,
      password: details.password,
      role: details.role,
    });
    return createdUser;
  }

  async login(user: loginDTO): Promise<{ access_token: string }> {
    const fetchedUser = await this.validate(user.email, user.password);

    if (fetchedUser) {
      const payload = {
        email: user.email,
        id: fetchedUser.id,
      };
      return {
        access_token: this.jwtService.sign(payload, {
          secret: this.jwt_secret,
          expiresIn: 7200,
        }),
      };
    }
    throw new UnauthorizedException('Invalid credentials');
  }

  async verify(token: string) {
    const decoded = this.jwtService.verify(token, { secret: this.jwt_secret });
    return this.userService.getUserByEmail(decoded.email);
  }
}

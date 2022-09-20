import { Body, Controller, Post } from '@nestjs/common';
import { loginDTO } from 'src/auth/dtos/login.dto';
import { signUpDTO } from 'src/user/dtos/signup.dto';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(@Body() params: loginDTO): Promise<{ access_token: string }> {
    return await this.authService.login(params as loginDTO);
  }

  @Post('sign-up')
  async signUp(@Body() userDetails: signUpDTO) {
    return await this.authService.signUp(userDetails);
  }
}

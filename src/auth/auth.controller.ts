import { Body, Controller, Post, Get, UseGuards, Req } from '@nestjs/common';
import { loginDTO } from './dtos/login.dto';
import { signUpDTO } from './dtos/signUp.dto';
import { AuthService } from './auth.service';
import { SchoolAuthGuard } from './guards/school.guard';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { StudentAuthGuard } from './guards/student.guard';
import { ParentAuthGuard } from './guards/parent.guard';
import { GoogleAuthGuard } from './guards/googleAuth.guard';

@ApiTags('Users')
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

  @Get()
  @UseGuards(GoogleAuthGuard)
  async googleAuth(@Req() req) {
    //
  }

  @Get('redirect')
  @UseGuards(GoogleAuthGuard)
  googleAuthRedirect(@Req() req) {
    return this.authService.googleLogin(req);
  }

  @ApiBearerAuth()
  @UseGuards(SchoolAuthGuard)
  @Get('schools-only')
  async school() {
    return 'This route test JWT auth for School Role';
  }

  @ApiBearerAuth()
  @UseGuards(StudentAuthGuard)
  @Get('students-only')
  async student() {
    return 'This route test JWT auth for student Role';
  }

  @ApiBearerAuth()
  @UseGuards(ParentAuthGuard)
  @Get('parents-only')
  async parent() {
    return 'This route test JWT auth for parent Role';
  }
}

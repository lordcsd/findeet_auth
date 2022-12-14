import {
  Body,
  Controller,
  Post,
  Get,
  UseGuards,
  Req,
  Session,
  Query,
} from '@nestjs/common';
import { loginDTO } from './dtos/login.dto';
import { signUpDTO } from './dtos/signUp.dto';
import { AuthService } from './auth.service';
import { SchoolAuthGuard } from './guards/school.guard';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { StudentAuthGuard } from './guards/student.guard';
import { ParentAuthGuard } from './guards/parent.guard';
import { GoogleAuthGuard } from './guards/googleAuth.guard';
import { StartAuthSessionDTO } from './dtos/startAuthSessionParams.dto';
import { FindeetAppResponse } from 'findeet-api-package';
import { EmailVerificationMail } from './dtos/emailVerificationMail.dto';
import { CompleteEmailVerificationDTO } from './dtos/completeEmailVerification.dto';

@ApiTags('Users')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('start-auth-provider-session')
  async testSession(
    @Session() session: Record<string, any>,
    @Query() details: StartAuthSessionDTO,
  ) {
    session['userRole'] = details.userRole;
    return 'session started';
  }

  @ApiOperation({ description: 'Log-in to Findeet account' })
  @Post('login')
  async login(@Body() params: loginDTO): Promise<FindeetAppResponse> {
    return await this.authService.login(params as loginDTO);
  }

  @ApiOperation({
    description:
      "Send or Resend email verification mail to user's email address",
  })
  @Post('send_email_verification_mail')
  async sendEmailVerificationMail(@Body() params: EmailVerificationMail) {
    return await this.authService.sendEmailVerificationEmail(params);
  }

  @ApiOperation({
    description: 'Call this endpoint to complete email verification',
  })
  @Get('complete-email-verification')
  async completeEmailVerification(
    @Query() { processToken }: CompleteEmailVerificationDTO,
  ) {
    return await this.authService.completeEmailVerification(processToken);
  }

  @ApiOperation({ description: 'Create a new user' })
  @Post('sign-up')
  async signUp(@Body() userDetails: signUpDTO): Promise<FindeetAppResponse> {
    return await this.authService.signUp(userDetails);
  }

  @Get()
  @UseGuards(GoogleAuthGuard)
  async googleAuth(@Req() req, @Session() session: Record<string, any>) {
    //
  }

  @Get('redirect')
  @UseGuards(GoogleAuthGuard)
  googleAuthRedirect(@Req() req, @Session() session: Record<string, any>) {
    return this.authService.googleLogin(req, session['userRole']);
  }

  // @ApiBearerAuth()
  // @UseGuards(SchoolAuthGuard)
  // @Get('schools-only')
  // async school() {
  //   return 'This route test JWT auth for School Role';
  // }

  // @ApiBearerAuth()
  // @UseGuards(StudentAuthGuard)
  // @Get('students-only')
  // async student() {
  //   return 'This route test JWT auth for student Role';
  // }

  // @ApiBearerAuth()
  // @UseGuards(ParentAuthGuard)
  // @Get('parents-only')
  // async parent() {
  //   return 'This route test JWT auth for parent Role';
  // }
}

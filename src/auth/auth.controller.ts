import {
  Body,
  Controller,
  Post,
  Get,
  Res,
  UseGuards,
  Req,
  Session,
  Query,
  Headers,
  Render,
} from '@nestjs/common';
import { loginDTO } from './dtos/login.dto';
import {
  ParentSignUpDTO,
  SchoolSignUpDTO,
  signUpDTO,
  StudentSignUpDTO,
} from './dtos/signUp.dto';
import { AuthService } from './auth.service';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { JWTGuard } from './guards/jwtAuth';
import { GoogleAuthGuard } from './guards/googleAuth.guard';
import { StartAuthSessionDTO } from './dtos/startAuthSessionParams.dto';
import { FindeetAppResponse } from 'findeet-api-package';
import { EmailVerificationMail } from './dtos/emailVerificationMail.dto';
import { CompleteEmailVerificationDTO } from './dtos/completeEmailVerification.dto';
import { CompleteLoginWithOTP } from './dtos/completeLoginWithOTP';
import { ResetPasswordDTO } from './dtos/resetPassword.dto';
import { FacebookAuthGuard } from './guards/facebook.Auth.guard';
import { AuthGuard } from '@nestjs/passport';
import { Request, Response } from 'express';
import * as qs from 'qs';
import { CompleteForgotPasswordDTO } from './dtos/completeForgotPassword.DTO';
import { UserRoles } from 'src/dtos/userRole.dto';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // @Get('test-qr')
  // async generate2FA_QRCode(
  //   @Res() res: Response,
  //   @Body() { email }: EmailVerificationMail,
  // ) {
  //   return await this.authService.generate2FA_QRcode(email, res);
  // }

  // @Get('ejs')
  // @Render('forbidden_action')
  // async ejs() {
  //   return { message: 'Na here e sup' };
  // }

  @ApiOperation({ description: 'Log-in to Findeet account' })
  @Post('login')
  async login(@Body() params: loginDTO): Promise<FindeetAppResponse> {
    return await this.authService.login(params as loginDTO);
  }

  @ApiOperation({
    description: 'Last Login step, verifies OTP and returns token',
  })
  @Post('complete-login-with-otp')
  async completeLoginWithOTP(@Body() details: CompleteLoginWithOTP) {
    return await this.authService.completeLoginWithOTP(details);
  }

  @ApiOperation({
    description:
      "Send or Resend email verification mail to user's email address",
  })
  @Post('send-email-verification-mail')
  async sendEmailVerificationMail(
    @Body() params: EmailVerificationMail,
    @Req() req,
  ) {
    return await this.authService.sendEmailVerificationEmail(params);
  }

  @ApiOperation({
    description: 'Call this endpoint to complete email verification',
  })
  @Get('complete-email-verification')
  async completeEmailVerification(
    @Query() { processToken }: CompleteEmailVerificationDTO,
    @Res() res: Response,
  ) {
    return await this.authService.completeEmailVerification(processToken, res);
  }

  @ApiOperation({ description: 'Change user password' })
  @UseGuards(JWTGuard)
  @ApiBearerAuth()
  @Post('reset-password')
  async resetPassword(
    @Body() details: ResetPasswordDTO,
    @Headers() { user },
  ): Promise<FindeetAppResponse> {
    return await this.authService.resetPassword(details, user);
  }

  //forgot password
  @ApiOperation({ description: 'Restore forgotten password' })
  @Post('forgot-password')
  async forgotPassword(
    @Body() details: EmailVerificationMail,
  ): Promise<FindeetAppResponse> {
    return await this.authService.forgotPassWord(details);
  }

  @ApiOperation({ description: '' })
  @Post('complete-forget-password')
  async completeForgotPassword(@Query() { token }: CompleteForgotPasswordDTO) {
    return await this.authService.completeForgotPassword(token);
  }

  @ApiOperation({ description: 'Create a new user' })
  @Post('student-sign-up')
  async studentSignUp(
    @Body() userDetails: StudentSignUpDTO,
  ): Promise<FindeetAppResponse> {
    return await this.authService.signUp(userDetails, UserRoles.STUDENT);
  }

  @ApiOperation({ description: 'Create a new user' })
  @Post('parent-sign-up')
  async parentSignUp(
    @Body() userDetails: ParentSignUpDTO,
  ): Promise<FindeetAppResponse> {
    return await this.authService.signUp(userDetails, UserRoles.PARENT);
  }

  //google auth routes
  @Get('start-auth-provider-session')
  async testSession(
    @Session() session: Record<string, any>,
    @Query() details: StartAuthSessionDTO,
  ) {
    session['userRole'] = details.userRole;
    return 'session started';
  }

  @Get('google-auth')
  @UseGuards(GoogleAuthGuard)
  async googleAuth(@Req() req, @Session() session: Record<string, any>) {
    //
  }

  @Get('redirect')
  @UseGuards(GoogleAuthGuard)
  googleAuthRedirect(
    @Req() req: Request,
    @Session() session: Record<string, any>,
    @Res() res: Response,
  ) {
    return this.authService.OAuthLogin(req, session['userRole']);
  }

  @Get('facebook-auth')
  @UseGuards(FacebookAuthGuard)
  async facebookAuth(@Req() req, @Session() session: Record<string, any>) {
    //
  }

  @Get('/facebook/redirect')
  @UseGuards(AuthGuard('facebook'))
  async facebookLoginRedirect(
    @Req() req: Request,
    @Res() res: Response,
    @Session() session: Record<string, any>,
  ): Promise<any> {
    return this.authService.OAuthLogin(req, session['userRole']);
  }
}

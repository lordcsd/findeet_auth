import { ConflictException, Injectable, Inject } from '@nestjs/common';
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
import {
  EmailTypes,
  FindeetAppResponse,
  NOTIFICATION_QUEUE,
  SendEmailOptions,
} from 'findeet-api-package';
import { AuthProviders } from 'src/constants/authProviders';
import { ClientProxy } from '@nestjs/microservices/client';

import { EmailVerificationMail } from './dtos/emailVerificationMail.dto';
import { createOTP } from './utils/createOTP';
import { CompleteLoginWithOTP } from './dtos/completeLoginWithOTP';
import { decodedProcessTokenDTO } from './dtos/completeEmailVerification.dto';
import { ResetPasswordDTO } from './dtos/resetPassword.dto';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { Stream } from 'stream';

@Injectable()
export class AuthService {
  userRepository: Repository<User>;
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly customRepository: CustomRepository,
    @Inject('NOTIF_SERVICE') private notificationClient: ClientProxy,
  ) {
    this.userRepository = this.customRepository.UserRepository();
  }

  jwt_secret = this.configService.get<string>(configConstants.jwt.secret);

  async sendEmail(details: SendEmailOptions) {
    await this.notificationClient.emit(
      NOTIFICATION_QUEUE.PATTERNS.SEND_MAIL,
      details,
    );
  }

  async generate2FA_QRcode(email: string, response: any) {
    const { otpauth_url, base32 } = speakeasy.generateSecret({
      name: this.configService.get<string>(configConstants.google2FA.appName),
    });

    await this.userRepository.update(
      { email },
      { twoFactorAuthenticationCode: base32 },
    );

    return QRCode.toFileStream(response, otpauth_url);
  }

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
      return FindeetAppResponse.BadRequest(
        '',
        'Email Already in use',
        '409',
        '',
      );
    }
    const salt = Number(this.configService.get(configConstants.bcrypt.salt));
    details.password = await bcrypt.hash(details.password, salt);

    await this.userRepository.save(details);

    //send email verification mail
    await this.sendEmailVerificationEmail({ email: details.email });

    return FindeetAppResponse.Ok('', 'New User created', 200);
  }

  async forgotPassWord(
    details: EmailVerificationMail,
  ): Promise<FindeetAppResponse> {
    const { email } = details;
    const user = await this.userRepository.find({ where: { email: email } });

    if (!user) {
      return FindeetAppResponse.NotFoundRequest(
        'Invalid user',
        'User with Email not found',
        '',
        '404',
      );
    }
  }

  async resetPassword(details: ResetPasswordDTO): Promise<FindeetAppResponse> {
    const { email, newPassword, oldPassword, confirmPassword } = details;

    const user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      return FindeetAppResponse.BadRequest(
        'Not Found',
        'Invalid Email',
        '',
        '404',
      );
    }

    const passwordIsValid = await bcrypt.compare(oldPassword, user.password);

    if (!passwordIsValid) {
      return FindeetAppResponse.BadRequest(
        '',
        'Invalid oldPassword',
        '',
        '406',
      );
    }

    if (newPassword == confirmPassword) {
      const salt = Number(this.configService.get(configConstants.bcrypt.salt));
      const newPasswordHash = await bcrypt.hash(newPassword, salt);

      await this.userRepository.update(
        { email, password: user.password },
        { password: newPasswordHash },
      );
      return FindeetAppResponse.Ok('', 'Password Updated', '200');
    }

    return FindeetAppResponse.BadRequest(
      '',
      'newPassword and confirmPassword does not match',
      '',
      '422',
    );
  }

  async sendEmailVerificationEmail(
    details: EmailVerificationMail,
  ): Promise<FindeetAppResponse> {
    const { email } = details;

    const user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      return FindeetAppResponse.BadRequest(
        'Email not registered',
        'invalid Email',
        '',
        '404',
      );
    }

    if (user.emailVerified == true) {
      return FindeetAppResponse.Ok('', 'Email Already Verified', '200');
    }

    const processToken = this.jwtService.sign({ id: user.id });

    const completeProcessURL = `${this.configService.get<string>(
      configConstants.service.root,
    )}/api/v1/auth/complete-email-verification?processToken=${processToken}`;

    await this.sendEmail({
      recipients: [email],
      emailType: EmailTypes.EMAIL_VERIFICATION,
      subject: 'Email Verification',
      redirectTo: completeProcessURL,
    });

    return FindeetAppResponse.Ok('', 'Email verification mail sent', '201');
  }

  async completeEmailVerification(
    processToken: string,
  ): Promise<FindeetAppResponse> {
    const decoded = this.jwtService.decode(
      processToken,
    ) as decodedProcessTokenDTO;

    if (decoded) {
      await this.userRepository.update(
        { id: decoded.id },
        { emailVerified: true },
      );
      return FindeetAppResponse.Ok('', 'Email Verified', 200);
    }

    return FindeetAppResponse.OkFailue(
      '',
      'Verification Process Failed, Invalid Token',
      '422',
      '',
    );
  }

  async login(user: loginDTO): Promise<FindeetAppResponse> {
    const fetchedUser = await this.validate(user.email, user.password);

    if (!fetchedUser) {
      return FindeetAppResponse.BadRequest(
        '',
        'Invalid creadentials',
        '',
        '406',
      );
    }

    if (fetchedUser && fetchedUser.authProvider == AuthProviders.local) {
      if (!fetchedUser.emailVerified) {
        return FindeetAppResponse.NotFoundRequest(
          'Unverified Email',
          'Please Verify your Email',
          '',
          '406',
        );
      }
    }

    const otp = createOTP();

    //ten minutes time
    const OTPExpires = new Date(Date.now() + 1000 * 60 * 10);

    await this.userRepository.update(
      { email: fetchedUser.email },
      { loginOtp: otp, loginOtpExpires: OTPExpires },
    );

    await this.sendEmail({
      recipients: [fetchedUser.email],
      emailType: EmailTypes.LOGIN_OTP,
      subject: 'Login OTP',
      otp: otp,
      username: `${fetchedUser.firstName} ${fetchedUser.lastName}`,
    });

    return FindeetAppResponse.Ok('', 'Login OTP sent to email', '201');
  }

  async completeLoginWithOTP(
    details: CompleteLoginWithOTP,
  ): Promise<FindeetAppResponse> {
    const { email, otp } = details;

    const user = await this.userService.getUserByEmail(email);

    if (!user) {
      return FindeetAppResponse.NotFoundRequest(
        'Invalid User',
        'Email not registered',
        '',
        '404',
      );
    }

    if (!user.loginOtp) {
      return FindeetAppResponse.NotFoundRequest(
        '',
        'No Login OTP found for user',
        '',
        '404',
      );
    }

    const OTPValid = +user.loginOtpExpires > Date.now() && user.loginOtp == otp;

    if (OTPValid) {
      const payload = {
        email: user.email,
        id: user.id,
      };

      await this.userRepository.update(
        { email: user.email },
        { loginOtp: null, loginOtpExpires: null },
      );

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

    return FindeetAppResponse.OkFailue('', 'OTP has Expired', '406', '');
  }

  OAuthLogin(req, userRole: string) {
    if (!req.user) {
      return 'No user from provider';
    }

    return {
      message: 'User information from provider',
      user: { ...req.user, userRole },
    };
  }
}

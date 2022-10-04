import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { SharedModule } from 'src/shared/shared.modules';
import { configConstants } from '../constants/configConstants';
import { UserModule } from '../user/user.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { GoogleStrategy } from './strategies/google.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { ClientsModule } from '@nestjs/microservices/module/clients.module';
import { Transport } from '@nestjs/microservices/enums/transport.enum';

@Module({
  imports: [
    UserModule,
    ClientsModule.register([
      {
        name: 'NOTIF_SERVICE',
        transport: Transport.RMQ,
        options: {
          urls: [process.env.RABBITMQ_URL],
          queue: 'NOTIFICATION',
          queueOptions: {
            durable: false,
          },
        },
      },
    ]),
    SharedModule,
    PassportModule.register({
      defaultStrategy: 'jwt',
    }),

    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configServeice: ConfigService) => ({
        secret: configServeice.get(configConstants.jwt.secret),
        signOptions: { expiresIn: 3600 },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, GoogleStrategy],
})
export class AuthModule {}

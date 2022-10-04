import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as session from 'express-session';
import { Transport } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';
import { configConstants } from './constants/configConstants';
import { MicroserviceOptions } from '@nestjs/microservices';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const configService = app.get(ConfigService);

  app.use(
    session({
      secret: 'dimgba',
      resave: false,
      saveUninitialized: false,
      cookie: { maxAge: 300000 },
    }),
  );

  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
    }),
  );

  app.setGlobalPrefix('/api/v1');

  const config = new DocumentBuilder()
    .setTitle('Findeet Auth')
    .setDescription('This Application handles user authentication')
    .setVersion('1.0')
    .addBearerAuth()
    .addTag('Users')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api-doc', app, document);

  await app.listen(configService.get<string>('PORT'));
}
bootstrap();

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import {ConfigService} from "@nestjs/config";
import cookieParser from "cookie-parser";
import {ValidationPipe} from "@nestjs/common";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const config = app.get(ConfigService);

  app.use(cookieParser());

  app.enableCors({
      origin: config.get<string>('CORS_ORIGIN'),
      credentials: true,

  });

  app.useGlobalPipes(new ValidationPipe({whitelist: true, transform: true}));
  await app.listen(process.env.PORT ?? 3000);

}
bootstrap();

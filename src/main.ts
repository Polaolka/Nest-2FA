import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from './common/pipes/Validation.pipe';
import { Environment } from './common/constants/app.enums';
import { swaggerConfig } from './config/swagger/swagger.config';
import { SwaggerModule } from '@nestjs/swagger';
import {
  ResponseFormat,
  ResponseInterceptor,
} from './common/interceptors/response.interceptor';
import { LoggingInterceptor } from './common/interceptors/logger.interceptor';
import { LoggerService } from './common/logger/logger.service';

async function bootstrap() {
  const PORT = process.env.PORT || '7000';
  const ENV = process.env.NODE_ENV;
  const app = await NestFactory.create(AppModule);

  // SWAGGER
  if (ENV !== Environment.Production) {
    const document = SwaggerModule.createDocument(app, swaggerConfig, {
      extraModels: [ResponseFormat],
      deepScanRoutes: true,
    });

    SwaggerModule.setup('/api/docs', app, document);
  }

  // CORS
  app.enableCors({});

  // PIPES
  app.useGlobalPipes(new ValidationPipe());

  // INTERCEPTORS
  app.useGlobalInterceptors(new LoggingInterceptor(new LoggerService()));
  app.useGlobalInterceptors(new ResponseInterceptor());

  app.setGlobalPrefix('api');

  await app.listen(PORT);
}
bootstrap();

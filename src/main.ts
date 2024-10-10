import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from './common/pipes/Validation.pipe';

async function bootstrap() {
  const PORT = process.env.PORT || '7000';
  // const ENV = process.env.NODE_ENV;
  const app = await NestFactory.create(AppModule);

  // CORS
  app.enableCors({});

  // PIPES
  app.useGlobalPipes(new ValidationPipe());

  // INTERCEPTORS

  app.setGlobalPrefix('api');

  await app.listen(PORT);
}
bootstrap();

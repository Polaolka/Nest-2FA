import { DocumentBuilder } from '@nestjs/swagger';

export const swaggerConfig = new DocumentBuilder()
  .setTitle('Nest-2FA')
  .setDescription('Documentation REST API')
  .setVersion('1.0.0')
  .build();

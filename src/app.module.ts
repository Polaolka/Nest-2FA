import { MiddlewareConsumer, Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ControllersModule } from './controllers/controllers.module';
import { ServicesModule } from './services/services.module';
import { RepositoriesModule } from './repositories/repositories.module';
import { EnvConfigModule } from './config/config.module';
import { ExceptionsModule } from './common/exceptions/exceptions.module';
import { JwtUserMiddleware } from './middlewares/jwt-user.middleware/jwt-user.middleware';
import { LoggerModule } from './common/logger/logger.module';
import { APP_PIPE } from '@nestjs/core';
import { ValidationPipe } from './common/pipes/Validation.pipe';
import { AdaptersModule } from './adapters/adapters.module';

@Module({
  imports: [
    MongooseModule.forRoot(process.env.DB_HOST || ''),
    ControllersModule,
    ServicesModule,
    RepositoriesModule,
    EnvConfigModule,
    ExceptionsModule,
    LoggerModule,
    AdaptersModule,
  ],
  controllers: [],
  providers: [
    {
      provide: APP_PIPE,
      useClass: ValidationPipe,
    },
  ],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(JwtUserMiddleware).forRoutes('users');
  }
}

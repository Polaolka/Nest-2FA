import { Module } from '@nestjs/common';
import { UserRepository } from './user.repository';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from 'src/schemas/user.schema';
import { EnvConfigModule } from 'src/config/env/config.module';
import { ExceptionsModule } from 'src/common/exceptions/exceptions.module';
import { LoggerModule } from 'src/common/logger/logger.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    LoggerModule,
    // JwtServiceModule,
    ExceptionsModule,
    EnvConfigModule,
  ],
  controllers: [],
  providers: [UserRepository],
  exports: [UserRepository],
})
export class RepositoriesModule {}

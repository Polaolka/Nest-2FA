import { Module } from '@nestjs/common';
import { AuthController } from './auth/auth.controller';
import { ServicesModule } from 'src/services/services.module';
import { EnvConfigService } from 'src/config/env/env-config.service';
import { RepositoriesModule } from 'src/repositories/repositories.module';
import { LoggerModule } from 'src/common/logger/logger.module';
import { MfaController } from './mfa/mfa.controller';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { AdaptersModule } from 'src/adapters/adapters.module';
import { ExceptionsModule } from 'src/common/exceptions/exceptions.module';
import { ExceptionsService } from 'src/common/exceptions/exceptions.service';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { EnvConfigModule } from 'src/config/env/config.module';

@Module({
  imports: [
    EnvConfigModule,
    ServicesModule,
    RepositoriesModule,
    LoggerModule,
    AdaptersModule,
    ExceptionsModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [EnvConfigModule],
      inject: [EnvConfigService],
      useFactory: (envConfigService: EnvConfigService) => ({
        secret: envConfigService.getMfaSecret(),
        signOptions: { expiresIn: '60s' },
      }),
    }),
  ],
  controllers: [AuthController, MfaController],
  providers: [EnvConfigService, JwtAuthGuard, ExceptionsService],
})
export class ControllersModule {}

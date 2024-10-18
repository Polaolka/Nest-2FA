import { Module } from '@nestjs/common';
import { AuthServise } from './auth.service';
import { RepositoriesModule } from 'src/repositories/repositories.module';
import { EnvConfigService } from 'src/config/env/env-config.service';
import { ExceptionsService } from 'src/common/exceptions/exceptions.service';
import { LoggerModule } from 'src/common/logger/logger.module';
import { AdaptersModule } from 'src/adapters/adapters.module';
import { MfaService } from './mfa.service';

@Module({
  imports: [RepositoriesModule, LoggerModule, AdaptersModule],
  providers: [AuthServise, EnvConfigService, ExceptionsService, MfaService],
  exports: [AuthServise, MfaService],
})
export class ServicesModule {}

import { Module } from '@nestjs/common';
import { UserServise } from './user.service';
import { RepositoriesModule } from 'src/repositories/repositories.module';
import { EnvConfigService } from 'src/config/env/env-config.service';
import { ExceptionsService } from 'src/common/exceptions/exceptions.service';
import { LoggerModule } from 'src/common/logger/logger.module';
import { AdaptersModule } from 'src/adapters/adapters.module';

@Module({
  imports: [RepositoriesModule, LoggerModule, AdaptersModule],
  providers: [UserServise, EnvConfigService, ExceptionsService],
  exports: [UserServise],
})
export class ServicesModule {}

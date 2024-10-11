import { Module } from '@nestjs/common';
import { AuthController } from './auth/auth.controller';
import { ServicesModule } from 'src/services/services.module';
import { EnvConfigService } from 'src/config/env/env-config.service';
import { RepositoriesModule } from 'src/repositories/repositories.module';
import { LoggerModule } from 'src/common/logger/logger.module';

@Module({
  imports: [ServicesModule, RepositoriesModule, LoggerModule],
  controllers: [AuthController],
  providers: [EnvConfigService],
})
export class ControllersModule {}

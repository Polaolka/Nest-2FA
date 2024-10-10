import { Module } from '@nestjs/common';
import { BcryptAdapter } from './bcrypt.adapter';
import { JwtTokenAdapter } from './jwt.adapter';
import { JwtService } from '@nestjs/jwt';
import { EnvConfigModule } from 'src/config/config.module';
@Module({
  imports: [EnvConfigModule],
  providers: [BcryptAdapter, JwtTokenAdapter, JwtService],
  exports: [BcryptAdapter, JwtTokenAdapter],
})
export class AdaptersModule {}

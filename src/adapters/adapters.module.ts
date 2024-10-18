import { Module } from '@nestjs/common';
import { BcryptAdapter } from './bcrypt.adapter';
import { JwtTokenAdapter } from './jwt.adapter';
import { JwtService } from '@nestjs/jwt';
import { EnvConfigModule } from 'src/config/env/config.module';
import { CryptoAdapter } from './crypto.adapter';

@Module({
  imports: [EnvConfigModule],
  providers: [BcryptAdapter, JwtTokenAdapter, JwtService, CryptoAdapter],
  exports: [BcryptAdapter, JwtTokenAdapter, CryptoAdapter],
})
export class AdaptersModule {}

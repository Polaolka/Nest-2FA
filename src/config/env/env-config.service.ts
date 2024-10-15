import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class EnvConfigService {
  constructor(private configService: ConfigService) {}
  getJwtAccessSecret(): string {
    return this.configService.get<string>('JWT_ACCESS_SECRET');
  }
  getJwtRefreshSecret(): string {
    return this.configService.get<string>('JWT_REFRESH_SECRET');
  }
  getDbHost(): string {
    return this.configService.get<string>('DB_HOST');
  }
  getJwtAccessExpirationTime(): string {
    return this.configService.get<string>('JWT_ACCESS_EXPIRATION_TIME');
  }
  getJwtRefreshExpirationTime(): string {
    return this.configService.get<string>('JWT_REFRESH_EXPIRATION_TIME');
  }
  getJwtSalt(): string {
    return this.configService.get<string>('JWT_SALT');
  }
  getMfaSecret(): string {
    return this.configService.get<string>('JWT_MFA_SECRET');
  }
}

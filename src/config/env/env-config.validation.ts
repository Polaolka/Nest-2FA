import { plainToClass } from 'class-transformer';
import { IsEnum, IsString, validateSync } from 'class-validator';

enum Environment {
  Development = 'development',
  Production = 'production',
}

class EnvironmentVariables {
  @IsEnum(Environment)
  NODE_ENV: Environment;

  @IsString()
  JWT_ACCESS_SECRET: string;
  @IsString()
  JWT_REFRESH_SECRET: string;
  @IsString()
  JWT_MFA_SECRET: string;

  @IsString()
  JWT_ACCESS_EXPIRATION_TIME: string;
  @IsString()
  JWT_REFRESH_EXPIRATION_TIME: string;
  @IsString()
  JWT_SALT: string;
  // DATABASE
  @IsString()
  DB_HOST: string;
}
export function validate(config: Record<string, unknown>) {
  const validatedConfig = plainToClass(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });

  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false,
  });

  if (errors.length > 0) {
    throw new Error(errors.toString());
  }
  return validatedConfig;
}

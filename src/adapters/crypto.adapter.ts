import { Injectable } from '@nestjs/common';

import * as crypto from 'crypto';
import { EnvConfigService } from 'src/config/env/env-config.service';

interface HashingService {
  encryptSecret(secret: string, secretKey: string): string;
  decryptSecret(hash: string, secretKey: string): string;
}

@Injectable()
export class CryptoAdapter implements HashingService {
  constructor(private readonly envConfig: EnvConfigService) {}

  private readonly algorithm = 'aes-256-ctr';

  // initialization vector
  private generateIV(): Buffer {
    return crypto.randomBytes(16);
  }

  // Encryption of the TOTP secret
  encryptSecret(secret: string, secretKey: string): string {
    const hexKey = crypto.createHash('sha256').update(secretKey).digest();
    const iv = this.generateIV();

    const cipher = crypto.createCipheriv(this.algorithm, hexKey, iv);
    const encrypted = Buffer.concat([cipher.update(secret), cipher.final()]);

    return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
  }

  // Decrypting the TOTP secret
  decryptSecret(hash: string, secretKey: string): string {
    const [iv, encrypted] = hash.split(':');
    const hexKey = crypto.createHash('sha256').update(secretKey).digest();
    const decipher = crypto.createDecipheriv(
      this.algorithm,
      hexKey,
      Buffer.from(iv, 'hex'),
    );
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encrypted, 'hex')),
      decipher.final(),
    ]);

    return decrypted.toString();
  }
}

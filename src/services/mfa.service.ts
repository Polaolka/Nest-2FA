import { Injectable } from '@nestjs/common';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import * as crypto from 'crypto';
import { UserRepository } from 'src/repositories/user.repository';
import { ExceptionsService } from 'src/common/exceptions/exceptions.service';
import { BcryptAdapter } from 'src/adapters/bcrypt.adapter';
import { EnvConfigService } from 'src/config/env/env-config.service';
import { CryptoAdapter } from 'src/adapters/crypto.adapter';

@Injectable()
export class MfaService {
  constructor(
    private userRepository: UserRepository,
    private readonly exceptionsService: ExceptionsService,
    private readonly bcryptAdapter: BcryptAdapter,
    private readonly cryptoAdapter: CryptoAdapter,
    private readonly envConfig: EnvConfigService,
  ) {}

  private readonly mfaSecretKey = this.envConfig.getMfaSecret();
  private readonly codeSecretKey = this.envConfig.getMfaCodeSecret();

  // Generate recovery codes
  private generateRecoveryCodes(): string[] {
    const recoveryCodes = [...Array(5)].map(() => {
      return crypto.randomBytes(4).toString('hex');
    });

    return recoveryCodes;
  }

  private hachRecoveryCodes(recoveryCodes: string[]): string[] {
    const hashedRecoveryCodes = recoveryCodes.map((code) =>
      this.cryptoAdapter.encryptSecret(code, this.codeSecretKey),
    );
    return hashedRecoveryCodes;
  }

  async verifyMfaCode(secret: string, token: string) {
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
    });
    return verified;
  }

  // GENERATE MFA
  async generate2FA(user: any) {
    const secret = speakeasy.generateSecret({
      name: `Nest-2FA (${user.email})`,
      length: 20,
    });

    const existUser = await this.userRepository.getUserById(user.id);

    if (!existUser) {
      this.exceptionsService.BAD_REQUEST_EXCEPTION({
        status: 'Failed',
        message: `Generate mfa failed, user not found`,
        statusCode: 400,
      });
    }

    const encryptedSecret = this.cryptoAdapter.encryptSecret(
      secret.base32,
      this.mfaSecretKey,
    );

    const updatedUser = await this.userRepository.updateById(user.id, {
      tempTwoFactorSecret: encryptedSecret,
    });
    if (!updatedUser) {
      {
        this.exceptionsService.INTERNAL_ERROR_EXCEPTION({
          status: 'Failed',
          message: `Generate mfa failed`,
          statusCode: 500,
        });
      }
    }

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    return {
      qrCodeUrl,
    };
  }

  // MFA ACTIVATION
  async updateMfa({ email, code }: { email: string; code: string }) {
    const user = await this.userRepository.getUserByEmail(email);
    if (!user) {
      this.exceptionsService.BAD_REQUEST_EXCEPTION({
        status: 'Failed',
        message: `Update mfa failed, user not found`,
        statusCode: 400,
      });
    }
    const secret = user.tempTwoFactorSecret;
    const decryptedSecret = this.cryptoAdapter.decryptSecret(
      secret,
      this.mfaSecretKey,
    );
    const isValid = await this.verifyMfaCode(decryptedSecret, code);
    if (!isValid) {
      this.exceptionsService.BAD_REQUEST_EXCEPTION({
        status: 'Failed',
        message: `Update mfa failed, Invalid MFA code`,
        statusCode: 400,
      });
    }

    const recoveryCodes = this.generateRecoveryCodes();
    const hashedRecoveryCodes = this.hachRecoveryCodes(recoveryCodes);

    // Оновлення стану MFA
    const updatedUser = await this.userRepository.updateById(user._id, {
      twoFactorSecret: user.tempTwoFactorSecret,
      tempTwoFactorSecret: '',
      isMfaEnable: true,
      recoveryCodes: hashedRecoveryCodes,
    });
    if (!updatedUser) {
      this.exceptionsService.INTERNAL_ERROR_EXCEPTION({
        status: 'Failed',
        message: `Update mfa failed internal error`,
        statusCode: 500,
      });
    }
    return { message: 'MFA updated', recoveryCodes };
  }
}

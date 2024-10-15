import { Injectable } from '@nestjs/common';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { UserRepository } from 'src/repositories/user.repository';
import { ExceptionsService } from 'src/common/exceptions/exceptions.service';

@Injectable()
export class MfaService {
  constructor(
    private userRepository: UserRepository,
    private readonly exceptionsService: ExceptionsService,
  ) {}

  // GENERATE
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
    const updatedUser = await this.userRepository.updateById(user.id, {
      tempTwoFactorSecret: secret.base32,
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
      secret: secret.base32,
      qrCodeUrl,
    };
  }

  // Перевірка TOTP-коду і активація 2FA
  async verify2FA(user: any, token: string) {
    const existUser = await this.userRepository.getUserById(user.id);
    console.log('existUser:', existUser.tempTwoFactorSecret);
    const verified = speakeasy.totp.verify({
      secret: existUser.tempTwoFactorSecret,
      encoding: 'base32',
      token,
    });
    console.log('verified:', verified);
    if (verified) {
      // Активація 2FA
      await this.userRepository.updateById(user.id, {
        twoFactorSecret: existUser.tempTwoFactorSecret,
        isMfaEnable: true,
        tempTwoFactorSecret: '',
      });
      return { message: '2FA enabled successfully' };
    } else {
      return { message: 'Invalid token', status: 401 };
    }
  }
}

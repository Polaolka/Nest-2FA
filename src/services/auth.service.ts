import { Injectable } from '@nestjs/common';
import { EnvConfigService } from 'src/config/env/env-config.service';
import { UserRepository } from 'src/repositories/user.repository';
import { ExceptionsService } from 'src/common/exceptions/exceptions.service';
import { BcryptAdapter } from 'src/adapters/bcrypt.adapter';
import { JwtTokenAdapter } from 'src/adapters/jwt.adapter';
import { UserResponse } from 'src/interfaces/user.iterface';
import { MfaService } from './mfa.service';
import { CryptoAdapter } from 'src/adapters/crypto.adapter';

interface JwtPayload {
  id: string;
  email: string;
}

@Injectable()
export class AuthServise {
  constructor(
    private userRepository: UserRepository,
    private readonly envConfig: EnvConfigService,
    private readonly exceptionsService: ExceptionsService,
    private readonly bcryptAdapter: BcryptAdapter,
    private readonly jwtTokenAdapter: JwtTokenAdapter,
    private readonly mfaService: MfaService,
    private readonly cryptoAdapter: CryptoAdapter,
  ) {}

  private readonly mfaSecretKey = this.envConfig.getMfaSecret(); // ключ для шифрування

  private readonly codeSecretKey = this.envConfig.getMfaCodeSecret(); // ключ для шифрування

  private async verifyRecoveryCode(
    userId: string,
    recoveryCode: string,
  ): Promise<boolean> {
    // Отримуємо користувача з бази даних
    const user = await this.userRepository.getUserById(userId);

    if (!user || !user.recoveryCodes) {
      return false;
    }

    // Перевіряємо чи існує цей recovery код
    const recoveryCodes = user.recoveryCodes;
    const decriptedRecoverycodes = recoveryCodes.map((code) =>
      this.cryptoAdapter.decryptSecret(code, this.codeSecretKey),
    );
    const codeIndex = decriptedRecoverycodes.findIndex(
      (code) => code === recoveryCode,
    );

    if (codeIndex === -1) {
      return false;
    }

    // Видаляємо код після використання
    recoveryCodes.splice(codeIndex, 1);
    await this.userRepository.updateById(userId, { recoveryCodes }); // Оновлюємо базу даних

    return true;
  }

  private async createMfaToken(payload: JwtPayload) {
    const MfaToken = this.jwtTokenAdapter.createToken(
      payload,
      this.envConfig.getMfaSecret(),
      this.envConfig.getMfaExpirationTime(),
    );
    return MfaToken;
  }

  private async createTokens(payload: JwtPayload) {
    const access = this.jwtTokenAdapter.createToken(
      payload,
      this.envConfig.getJwtAccessSecret(),
      this.envConfig.getJwtAccessExpirationTime(),
    );

    const refresh = this.jwtTokenAdapter.createToken(
      payload,
      this.envConfig.getJwtRefreshSecret(),
      this.envConfig.getJwtRefreshExpirationTime(),
    );

    return { access, refresh };
  }

  // ---- CREATE NEW USER ----
  async createUser({
    email,
    password,
    name,
  }: {
    email: string;
    password: string;
    name: string;
  }): Promise<Partial<UserResponse>> {
    const existUser = await this.userRepository.getUserByEmail(email);
    if (existUser) {
      this.exceptionsService.BAD_REQUEST_EXCEPTION({
        status: 'Failed',
        message: `User creation failed, email already in use`,
        statusCode: 400,
      });
    }
    const salt = Number(this.envConfig.getJwtSalt());
    const hashedPassword = await this.bcryptAdapter.hash(password, salt);
    const newUser = await this.userRepository.createUser({
      email,
      password: hashedPassword,
      name,
    });
    if (!newUser) {
      this.exceptionsService.INTERNAL_ERROR_EXCEPTION({
        status: 'Failed',
        message: `User creation failed`,
        statusCode: 500,
      });
    }
    const payload = {
      id: newUser._id.toString(),
      email: newUser.email,
    };

    const accessToken = await this.jwtTokenAdapter.createToken(
      payload,
      this.envConfig.getJwtAccessSecret(),
      this.envConfig.getJwtAccessExpirationTime(),
    );
    const refreshToken = await this.jwtTokenAdapter.createToken(
      payload,
      this.envConfig.getJwtRefreshSecret(),
      this.envConfig.getJwtRefreshExpirationTime(),
    );

    const updatedUser = await this.userRepository.updateById(newUser._id, {
      accessToken,
      refreshToken,
    });

    return updatedUser;
  }

  // ---- LOGIN USER ----
  async login({ email, password }: { email: string; password: string }) {
    const user = await this.userRepository.getUserByEmail(email);
    if (!user) {
      this.exceptionsService.BAD_REQUEST_EXCEPTION({
        message: 'Invalid credentials',
      });
    }

    if (user.isMfaEnable) {
      const payload = { id: user._id.toString(), email: user.email };
      const mfaToken = await this.createMfaToken(payload);
      this.exceptionsService.FORBIDDEN_EXCEPTION({
        message: '2FA required',
        data: mfaToken,
      });
    }

    const isPassword = await this.bcryptAdapter.compare(
      password,
      user.password,
    );

    if (!isPassword) {
      this.exceptionsService.BAD_REQUEST_EXCEPTION({
        message: 'Invalid credentials',
      });
    }

    const payload = {
      id: user._id.toString(),
      email: user.email,
    };
    const { access, refresh } = await this.createTokens(payload);

    const updatedUser = await this.userRepository.updateById(user._id, {
      accessToken: access,
      refreshToken: refresh,
    });

    return updatedUser;
  }

  // ---- LOGOUT USER ----
  async logout(_id: string) {
    await this.userRepository.updateById(_id, {
      accessToken: '',
      refreshToken: '',
    });

    return { message: 'Logout success' };
  }

  // ---- REFRESH USER ----
  async refreshUser(refreshToken: string) {
    try {
      const result = await this.jwtTokenAdapter.verifyToken(
        refreshToken,
        this.envConfig.getJwtRefreshSecret(),
      );
      if (!result) {
        this.exceptionsService.UNAUTHORIZED_EXCEPTION({
          message: 'token invalid',
        });
      }
      if (result.payload.id) {
        const user = await this.userRepository.getUserByToken(refreshToken);
        if (!user || user._id.toString() !== result.payload.id) {
          throw this.exceptionsService.FORBIDDEN_EXCEPTION({
            status: 'Failed',
            message: 'User not found, refresh token invalid',
            statusCode: 404,
          });
        }

        const newAccessToken = this.jwtTokenAdapter.createToken(
          { id: result.payload.id, email: result.payload.email },
          this.envConfig.getJwtAccessSecret(),
          this.envConfig.getJwtAccessExpirationTime(),
        );
        const newRefreshToken = this.jwtTokenAdapter.createToken(
          { id: result.payload.id, email: result.payload.email },
          this.envConfig.getJwtRefreshSecret(),
          this.envConfig.getJwtRefreshExpirationTime(),
        );

        await this.userRepository.updateById(user._id, {
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        });
        return { accessToken: newAccessToken, refreshToken: newRefreshToken };
      } else {
        throw this.exceptionsService.FORBIDDEN_EXCEPTION({
          status: 'Failed',
          message: 'Refresh token invalid',
          statusCode: 403,
        });
      }
    } catch (error) {
      throw error;
    }
  }

  // ---- LOGIN USER WITH MFA ----
  async loginMfa(mfaToken: string, code: string) {
    // Верифікуємо MFA-токен
    const user = await this.jwtTokenAdapter.verifyToken(
      mfaToken,
      this.envConfig.getMfaSecret(),
    );
    if (!user) {
      this.exceptionsService.FORBIDDEN_EXCEPTION({
        message: 'mfa token expired or invalid',
      });
    }
    const userId = user.payload.id;

    // Отримуємо секрет
    const exsistUser = await this.userRepository.getUserById(userId);
    if (!exsistUser) {
      this.exceptionsService.BAD_REQUEST_EXCEPTION({
        message: 'User not found',
      });
    }
    const secret = exsistUser.twoFactorSecret;
    const decriptedSecret = this.cryptoAdapter.decryptSecret(
      secret,
      this.envConfig.getMfaSecret(),
    );

    // Перевіряємо MFA-код
    const isValid = await this.mfaService.verifyMfaCode(decriptedSecret, code);

    if (!isValid) {
      this.exceptionsService.BAD_REQUEST_EXCEPTION({
        message: 'Invalid MFA code',
      });
    }

    // Генеруємо нові токени для користувача після успішного MFA login
    const { access, refresh } = await this.createTokens(user.payload);

    const updatedUser = await this.userRepository.updateById(userId, {
      accessToken: access,
      refreshToken: refresh,
    });
    return updatedUser;
  }

  // ---- LOGIN USER WITH RECOVERY CODE ----
  async loginWithRecoveryCode(mfaToken: string, recoveryCode: string) {
    const user = await this.jwtTokenAdapter.verifyToken(
      mfaToken,
      this.envConfig.getMfaSecret(),
    );
    if (!user) {
      this.exceptionsService.FORBIDDEN_EXCEPTION({
        message: 'mfa token expired or invalid',
      });
    }
    const userId = user.payload.id;

    const isValid = await this.verifyRecoveryCode(userId, recoveryCode);

    if (!isValid) {
      this.exceptionsService.BAD_REQUEST_EXCEPTION({
        message: 'Invalid recovery code',
      });
    }

    // Генеруємо нові токени доступу
    const { access, refresh } = await this.createTokens(user.payload);

    const updatedUser = await this.userRepository.updateById(userId, {
      accessToken: access,
      refreshToken: refresh,
    });
    return updatedUser;
  }
}

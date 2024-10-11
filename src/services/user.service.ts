import { Injectable } from '@nestjs/common';
import { EnvConfigService } from 'src/config/env/env-config.service';
import { UserRepository } from 'src/repositories/user.repository';
// import * as bcrypt from 'bcrypt';
// import * as jwt from 'jsonwebtoken';
import { ExceptionsService } from 'src/common/exceptions/exceptions.service';
import { BcryptAdapter } from 'src/adapters/bcrypt.adapter';
import { JwtTokenAdapter } from 'src/adapters/jwt.adapter';
import { UserResponse } from 'src/interfaces/user.iterface';

interface JwtPayload {
  id: string;
  email: string;
}

@Injectable()
export class UserServise {
  constructor(
    private userRepository: UserRepository,
    private readonly envConfig: EnvConfigService,
    private readonly exceptionsService: ExceptionsService,
    private readonly bcryptAdapter: BcryptAdapter,
    private readonly jwtTokenAdapter: JwtTokenAdapter,
  ) {}

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

  async login({ email, password }: { email: string; password: string }) {
    const user = await this.userRepository.getUserByEmail(email);
    if (!user) {
      this.exceptionsService.BAD_REQUEST_EXCEPTION({
        message: 'Invalid credentials',
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

    const updatedUser = await this.userRepository.updateById(user._id, {
      accessToken,
      refreshToken,
    });

    return updatedUser;
  }

  async logout(_id: string) {
    await this.userRepository.updateById(_id, {
      accessToken: '',
      refreshToken: '',
    });

    return { message: 'Logout success' };
  }

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
}

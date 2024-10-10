import { Injectable } from '@nestjs/common';
import { EnvConfigService } from 'src/config/env-config.service';
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
    const { access, refresh } = await this.createTokens(payload);

    const updatedUser = await this.userRepository.updateById(newUser._id, {
      accessToken: access.token,
      refreshToken: refresh.token,
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
    const { access, refresh } = await this.createTokens(payload);

    const updatedUser = await this.userRepository.updateById(user._id, {
      accessToken: access.token,
      refreshToken: refresh.token,
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
}

import { Body, Controller, Headers, HttpCode, Post } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { AuthServise } from 'src/services/auth.service';
import {
  CreateUserDto,
  LoginMfaDto,
  LoginRecoveryCodeDto,
  LoginUserDto,
  LogoutUserDto,
  RefresUserDto,
} from './auth.dto';
import {
  AuthLoginPresenter,
  UserLogoutPresenter,
  UserRefreshPresenter,
} from './user.presenter';
import { Public } from 'src/common/decorators/public.decorator';

@ApiTags('User controller')
@Controller('auth')
export class AuthController {
  constructor(private authServise: AuthServise) {}

  // ---- CREATE NEW USER ----
  @ApiOperation({ summary: 'Create user' })
  @Post('register')
  async register(@Body() data: CreateUserDto) {
    return this.authServise.createUser(data);
  }

  // ---- LOGIN USER ----
  @HttpCode(200)
  @ApiResponse({ status: 200, type: AuthLoginPresenter })
  @ApiOperation({ summary: 'User login' })
  @Post('login')
  async login(@Body() data: LoginUserDto) {
    const user = await this.authServise.login(data);
    const responce = new AuthLoginPresenter();
    responce._id = user._id.toString();
    responce.email = user.email;
    responce.name = user.name;
    responce.accessToken = user.accessToken;
    responce.refreshToken = user.refreshToken;
    return responce;
  }

  // ---- LOGOUT USER ----
  @HttpCode(200)
  @ApiResponse({ status: 200, type: UserLogoutPresenter })
  @ApiOperation({ summary: 'User logout' })
  @Post('logout')
  async logout(@Body() data: LogoutUserDto) {
    const result = await this.authServise.logout(data._id);
    const responce = new UserLogoutPresenter();
    responce.message = result.message;
    return responce;
  }

  // ---- REFRESH USER----
  @Public()
  @ApiOperation({ summary: 'Refresh users' })
  @ApiResponse({ status: 200, type: UserRefreshPresenter })
  @Post('refresh')
  async refreshUser(@Body() data: RefresUserDto) {
    const result = await this.authServise.refreshUser(data.refreshToken);
    const responce = new UserRefreshPresenter();
    responce.accessToken = result.accessToken;
    responce.refreshToken = result.refreshToken;
    return responce;
  }

  // ---- LOGIN 2FA USER----
  @Public()
  @ApiOperation({ summary: 'Refresh users' })
  @ApiResponse({ status: 200, type: UserRefreshPresenter })
  @Post('mfa/verify')
  async loginMfa(
    @Headers('MFA-Token') mfaToken: string,
    @Body() mfaDto: LoginMfaDto,
  ) {
    const user = await this.authServise.loginMfa(mfaToken, mfaDto.code);
    const responce = new AuthLoginPresenter();
    responce._id = user._id.toString();
    responce.email = user.email;
    responce.name = user.name;
    responce.accessToken = user.accessToken;
    responce.refreshToken = user.refreshToken;
    return responce;
  }

  // ---- LOGIN USER WITH RECOVERY CODE---
  @Public()
  @ApiOperation({ summary: 'Refresh users' })
  @ApiResponse({ status: 200, type: UserRefreshPresenter })
  async verifyRecoveryCode(
    @Headers('MFA-Token') mfaToken: string,
    @Body() data: LoginRecoveryCodeDto,
  ) {
    const user = await this.authServise.loginWithRecoveryCode(
      mfaToken,
      data.recoveryCode,
    );
    const responce = new AuthLoginPresenter();
    responce._id = user._id.toString();
    responce.email = user.email;
    responce.name = user.name;
    responce.accessToken = user.accessToken;
    responce.refreshToken = user.refreshToken;
    return responce;
  }
}

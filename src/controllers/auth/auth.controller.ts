import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { UserServise } from 'src/services/user.service';
import { CreateUserDto, LoginUserDto, RefresUserDto } from './auth.dto';
import {
  AuthLoginPresenter,
  UserLogoutPresenter,
  UserRefreshPresenter,
} from './user.presenter';
import { Public } from 'src/common/decorators/public.decorator';

@ApiTags('User controller')
@Controller('auth')
export class AuthController {
  constructor(private userService: UserServise) {}

  // ---- CREATE NEW USER ----
  @ApiOperation({ summary: 'Create user' })
  @Post('register')
  async register(@Body() data: CreateUserDto) {
    return this.userService.createUser(data);
  }

  // ---- LOGIN USER ----
  @HttpCode(200)
  @ApiResponse({ status: 200, type: AuthLoginPresenter })
  @ApiOperation({ summary: 'User login' })
  @Post('login')
  async login(@Body() data: LoginUserDto) {
    return this.userService.login(data);
  }

  // ---- LOGOUT USER ----
  @HttpCode(200)
  @ApiResponse({ status: 200, type: UserLogoutPresenter })
  @ApiOperation({ summary: 'User logout' })
  @Post('logout')
  async logout(@Body() _id: string) {
    return this.userService.logout(_id);
  }

  // ---- REFRESH USER----
  @Public()
  // @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Refresh users' })
  @ApiResponse({ status: 200, type: UserRefreshPresenter })
  @Post('/refresh')
  refreshUser(@Body() refresUserDto: RefresUserDto) {
    return this.userService.refreshUser(refresUserDto.refreshToken);
  }
}

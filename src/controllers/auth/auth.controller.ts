import { Body, Controller, Post } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { UserServise } from 'src/services/user.service';
import { CreateUserDto, LoginUserDto } from './auth.dto';
import { AuthLoginPresenter, UserLogoutRespDto } from './user.presenter';

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
  @ApiResponse({ status: 200, type: AuthLoginPresenter })
  @ApiOperation({ summary: 'User login' })
  @Post('login')
  async login(@Body() data: LoginUserDto) {
    return this.userService.login(data);
  }

  // ---- LOGOUT USER ----
  @ApiResponse({ status: 200, type: UserLogoutRespDto })
  @ApiOperation({ summary: 'User logout' })
  @Post('logout')
  async logout(@Body() _id: string) {
    return this.userService.logout(_id);
  }
}

import { ApiProperty, PickType } from '@nestjs/swagger';

export default class UserBaseData {
  @ApiProperty({ example: '123', description: 'user id' })
  _id: string;

  @ApiProperty({ example: 'ex@mail.com', description: 'user mail' })
  email: string;

  @ApiProperty({ example: 'John Strong', description: 'user name' })
  name: string;

  @ApiProperty({ example: 'string', description: 'user`s access token' })
  accessToken: string;

  @ApiProperty({ example: 'string', description: 'user`s refresh token' })
  refreshToken: string;

  @ApiProperty({ example: true, description: 'is Mfa enable' })
  isMfaEnable: boolean;

  constructor(user: Partial<UserBaseData>) {
    Object.assign(this, user);
  }
}

export class AuthLoginPresenter extends PickType(UserBaseData, [
  '_id',
  'email',
  'name',
  'isMfaEnable',
  'accessToken',
  'refreshToken',
] as const) {}

export class UserLogoutPresenter {
  @ApiProperty({ example: 'Logou Success', description: 'userlogout message' })
  message: string;
}

export class UserRefreshPresenter {
  accessToken: string;
  refreshToken: string;
}

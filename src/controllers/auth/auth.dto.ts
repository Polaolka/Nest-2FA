import { IsString, IsNotEmpty, IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty({ example: '123QWE', description: 'user password' })
  @IsNotEmpty()
  @IsString()
  password: string;

  @ApiProperty({ example: 'ex@mail.com', description: 'user mail' })
  @IsNotEmpty()
  @IsEmail()
  readonly email: string;

  @ApiProperty({ example: 'Kuzia', description: 'user name' })
  @IsNotEmpty()
  @IsString()
  readonly name: string;
}

export class LoginUserDto {
  @ApiProperty({ example: 'ex@mail.com', description: 'user mail' })
  @IsNotEmpty()
  @IsString()
  readonly email: string;

  @ApiProperty({ example: '123QWE', description: 'user password' })
  @IsNotEmpty()
  @IsString()
  password: string;
}

export class LogoutUserDto {
  @ApiProperty({ example: '123', description: 'user id' })
  @IsNotEmpty()
  @IsString()
  _id: string;
}

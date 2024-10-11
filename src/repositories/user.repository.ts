import { Model } from 'mongoose';
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from 'src/schemas/user.schema';
import { LoggerService } from 'src/common/logger/logger.service';
import { UserResponse } from 'src/interfaces/user.iterface';

@Injectable()
export class UserRepository {
  constructor(
    private readonly loggerService: LoggerService,
    @InjectModel(User.name) private userModel: Model<User>,
  ) {}

  // ---- GET USER BY EMAIL ----
  async getUserByEmail(email: string): Promise<UserResponse> {
    const user = await this.userModel.findOne({
      email,
    });
    return user;
  }

  // ---- GET USER BY REFRESHTOKEN ----
  async getUserByToken(refreshToken: string): Promise<UserResponse> {
    const user = await this.userModel.findOne({
      refreshToken,
    });
    return user;
  }

  // ---- GET USER BY ID ----
  async getUserById(id: string): Promise<UserResponse> {
    const user = await this.userModel.findById(id);
    return user;
  }

  // ---- GET ALL USERS ----
  async findAllUsers(): Promise<UserResponse[]> {
    const allUsers = await this.userModel
      .find()
      .select('-password -accessToken -refreshToken -createdAt -updatedAt');
    return allUsers;
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
  }): Promise<UserResponse> {
    const newUser = await this.userModel.create({
      email,
      password,
      name,
    });
    return newUser;
  }
  // ---- UPDATE USER BY ID ----
  async updateById(id, payload): Promise<UserResponse> {
    const user = await this.userModel
      .findByIdAndUpdate(id, payload, { new: true })
      .select('-password -createdAt -updatedAt');
    return user;
  }
}

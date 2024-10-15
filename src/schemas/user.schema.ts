import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

@Schema({ versionKey: false })
export class User {
  @Prop({ required: true })
  password: string;

  @Prop({ required: true })
  name: string;

  @Prop({ required: true })
  email: string;

  @Prop()
  accessToken: string;

  @Prop()
  refreshToken: string;

  @Prop({ default: false })
  isMfaEnable: boolean;

  @Prop({ default: '' })
  recoveryCode: string;

  @Prop({ default: '' })
  tempTwoFactorSecret: string;

  @Prop({ default: '' })
  twoFactorSecret: string;
}

export const UserSchema = SchemaFactory.createForClass(User);

import { Types } from 'mongoose';
import { User } from 'src/schemas/user.schema';

export interface UserResponse extends User {
  _id: Types.ObjectId;
}

export interface UserPayload {
  id: string;
  email: string;
}

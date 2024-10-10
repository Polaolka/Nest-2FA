import { Injectable } from '@nestjs/common';

import * as bcrypt from 'bcrypt';

interface HashingService {
  hash(text: string, saltRounds: number): Promise<string>;
  compare(current: string, hashed: string): Promise<boolean>;
}

@Injectable()
export class BcryptAdapter implements HashingService {
  async hash(text: string, saltRounds: number = 10) {
    return await bcrypt.hash(text, saltRounds);
  }
  async compare(current: string, hashed: string) {
    return await bcrypt.compare(current, hashed);
  }
}

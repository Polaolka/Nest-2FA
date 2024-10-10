import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

interface JwtPayload {
  id: string;
  email: string;
}

interface JwtTokenOperations {
  createToken(
    { id, email }: JwtPayload,
    secret: string,
    expiresIn: string,
  ): { expirationDate: Date; token: string };
  verifyToken(token: string, secret: string): Promise<unknown>;
}

@Injectable()
export class JwtTokenAdapter implements JwtTokenOperations {
  constructor(private readonly jwtService: JwtService) {}

  async verifyToken(
    token: string,
    secret: string,
  ): Promise<{ expirationDate: Date; payload: JwtPayload } | null> {
    try {
      const verified = await this.jwtService.verifyAsync(token, {
        secret,
      });
      console.log('VERIFIED', verified);
      const { payload, exp } = verified;
      const { id, email } = payload || verified;
      const expirationDate = new Date(exp * 1000);
      return { expirationDate, payload: { id, email } };
    } catch ({ message }) {
      console.log(message);
      return null;
    }
  }

  createToken(
    payload: JwtPayload,
    secret: string,
    expiresIn: string,
  ): { expirationDate: Date; token: string } {
    const token = this.jwtService.sign(payload, { secret, expiresIn });
    const decoded = this.jwtService.decode(token);

    const expirationDate = new Date(decoded.exp * 1000);
    return { expirationDate, token };
  }
}

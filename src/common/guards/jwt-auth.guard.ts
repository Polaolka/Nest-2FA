import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { JwtTokenAdapter } from 'src/adapters/jwt.adapter';
import { ExceptionsService } from '../exceptions/exceptions.service';
import { EnvConfigService } from 'src/config/env/env-config.service';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtTokenAdapter,
    private readonly exceptionService: ExceptionsService,
    private readonly envConfigService: EnvConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    try {
      const authHeader = req.headers.Authorization || req.headers.authorization;
      if (!authHeader) {
        this.exceptionService.UNAUTHORIZED_EXCEPTION({
          statusCode: 401,
          message: 'Authorization header is required',
        });
      }

      const [bearer, token]: string[] = authHeader.split(' ');
      if (bearer !== 'Bearer' || !token || token.length < 10) {
        this.exceptionService.UNAUTHORIZED_EXCEPTION({
          statusCode: 401,
          message: 'Token required or invalid token',
        });
      }
      const secret = this.envConfigService.getJwtAccessSecret();
      const user = await this.jwtService.verifyToken(token, secret);

      if (!user) {
        this.exceptionService.FORBIDDEN_EXCEPTION({
          message: 'jwt token expired or invalid',
        });
      }
      console.log('USER', user);
      req.user = user.payload;

      return true;
    } catch (e) {
      console.log('ERROR', e);
      this.exceptionService.FORBIDDEN_EXCEPTION({
        message: e.message,
      });
    }
  }
}

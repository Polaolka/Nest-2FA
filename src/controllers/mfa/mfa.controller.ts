import { Controller, Post, Body, UseGuards, Req, Param } from '@nestjs/common';

import { Request } from 'express';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { MfaService } from 'src/services/mfa.service';

interface ExtendedRequest extends Request {
  user?: any;
}

@Controller('mfa')
export class MfaController {
  constructor(private readonly mfaService: MfaService) {}

  // GENERATE 2FA SECRET, QR-CODE
  @Post('generate')
  @UseGuards(JwtAuthGuard)
  async generate2FA(@Req() request: ExtendedRequest) {
    const user = request.user;
    return this.mfaService.generate2FA(user);
  }

  // ACTIVATE 2FA
  // @Post('verify')
  // @UseGuards(JwtAuthGuard)
  // async verify2FA(
  //   @Req() request: ExtendedRequest,
  //   @Body() body: { token: string },
  // ) {
  //   const user = request.user;
  //   return this.mfaService.verify2FA(user, body.token);
  // }

  @Post('verify/:email')
  @UseGuards(JwtAuthGuard)
  async turnOnMfa(
    @Param('email') email: string,
    @Body() body: { code: string },
  ) {
    return this.mfaService.updateMfa({ email, code: body.code });
  }
}

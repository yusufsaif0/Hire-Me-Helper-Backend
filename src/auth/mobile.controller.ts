import { Body, Controller, Get, HttpCode, Post, Req, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { AuthService } from './service';
import { requestSchema, verifySchema, refreshSchema } from './contracts';
import {
  AccessGuard,
  type AuthRequest,
  validate,
  metadata,
  bearer,
  bodyShape,
  textField,
  sessionShape,
  userShape,
} from './http';
@ApiTags('Identity')
@Controller('auth')
export class MobileAuthController {
  constructor(private readonly auth: AuthService) {}
  @Post('otp/request')
  @HttpCode(202)
  @ApiBody({
    schema: bodyShape(['phone', 'purpose'], {
      phone: textField,
      purpose: { type: 'string', enum: ['CUSTOMER_LOGIN', 'WORKER_LOGIN'] },
    }),
  })
  @ApiResponse({
    status: 202,
    description: 'Challenge credential; never includes OTP.',
    schema: {
      type: 'object',
      required: [
        'challengeId',
        'challengeToken',
        'resendAfterSeconds',
        'expiresInSeconds',
        'maskedPhone',
      ],
      properties: {
        challengeId: { type: 'string', format: 'uuid' },
        challengeToken: textField,
        resendAfterSeconds: { type: 'integer' },
        expiresInSeconds: { type: 'integer' },
        maskedPhone: textField,
      },
    },
  })
  request(@Body() input: unknown, @Req() request: Request) {
    const body = validate(requestSchema, input);
    return this.auth.requestOtp(body.phone, body.purpose, metadata(request));
  }
  @Post('otp/verify')
  @HttpCode(200)
  @ApiBody({
    schema: bodyShape(['challengeId', 'challengeToken', 'code'], {
      challengeId: textField,
      challengeToken: textField,
      code: textField,
    }),
  })
  @ApiResponse({ status: 200, schema: sessionShape })
  async verify(@Body() input: unknown, @Req() request: Request) {
    const body = validate(verifySchema, input);
    const result = await this.auth.verifyOtp(
      body.challengeId,
      body.challengeToken,
      body.code,
      metadata(request),
    );
    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      expiresInSeconds: result.expiresInSeconds,
      user: result.user,
    };
  }
  @Post('refresh')
  @HttpCode(200)
  @ApiBody({ schema: bodyShape(['refreshToken'], { refreshToken: textField }) })
  @ApiResponse({ status: 200, schema: sessionShape })
  async refresh(@Body() input: unknown) {
    const body = validate(refreshSchema, input);
    const result = await this.auth.refresh(body.refreshToken);
    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      expiresInSeconds: result.expiresInSeconds,
      user: result.user,
    };
  }
  @Post('logout')
  @HttpCode(204)
  @UseGuards(AccessGuard)
  @ApiBearerAuth('access')
  @ApiResponse({ status: 204 })
  async logout(@Req() request: Request) {
    await this.auth.logout(bearer(request));
  }
  @Post('logout-all')
  @HttpCode(204)
  @UseGuards(AccessGuard)
  @ApiBearerAuth('access')
  @ApiResponse({ status: 204 })
  async logoutAll(@Req() request: Request) {
    await this.auth.logout(bearer(request), true);
  }
  @Get('me')
  @UseGuards(AccessGuard)
  @ApiBearerAuth('access')
  @ApiResponse({ status: 200, schema: userShape })
  me(@Req() request: AuthRequest) {
    return request.authenticated?.user;
  }
}

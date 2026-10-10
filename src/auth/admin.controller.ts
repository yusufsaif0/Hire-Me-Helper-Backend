import { Body, Controller, Get, HttpCode, Post, Req, Res, UseGuards } from '@nestjs/common';
import { ApiBody, ApiCookieAuth, ApiHeader, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { AuthService, AuthError } from './service';
import { loginSchema, mfaSchema } from './contracts';
import {
  AccessGuard,
  type AuthRequest,
  validate,
  metadata,
  cookie,
  bodyShape,
  textField,
  userShape,
} from './http';
@ApiTags('Admin identity')
@Controller('admin/auth')
export class AdminAuthController {
  constructor(private readonly auth: AuthService) {}
  private origin(request: Request) {
    if (request.header('origin') !== new URL(this.auth.settings.env.CORS_ORIGIN).origin)
      throw new AuthError('FORBIDDEN', 403);
  }
  private cookies(response: Response, result: Awaited<ReturnType<AuthService['refresh']>>) {
    const options = {
      httpOnly: true,
      sameSite: 'strict' as const,
      secure: this.auth.settings.env.CORS_ORIGIN.startsWith('https://'),
      path: '/',
    };
    response.cookie('admin_access', result.accessToken, {
      ...options,
      maxAge: result.expiresInSeconds * 1000,
    });
    response.cookie('admin_refresh', result.refreshToken, {
      ...options,
      maxAge: this.auth.settings.values.AUTH_REFRESH_TTL_SECONDS * 1000,
    });
    response.cookie('admin_csrf', result.csrfToken, {
      ...options,
      httpOnly: false,
      maxAge: this.auth.settings.values.AUTH_REFRESH_TTL_SECONDS * 1000,
    });
    return { user: result.user, csrfToken: result.csrfToken };
  }
  @Post('login')
  @HttpCode(200)
  @ApiBody({
    schema: bodyShape(['phone', 'password'], {
      phone: textField,
      password: { type: 'string', maxLength: 128 },
    }),
  })
  @ApiResponse({
    status: 200,
    description: 'First factor only. No authenticated session.',
    schema: {
      type: 'object',
      required: ['mfaChallengeId', 'mfaToken', 'expiresInSeconds'],
      properties: {
        mfaChallengeId: { type: 'string', format: 'uuid' },
        mfaToken: textField,
        expiresInSeconds: { type: 'integer' },
      },
    },
  })
  login(@Body() input: unknown, @Req() request: Request) {
    this.origin(request);
    const body = validate(loginSchema, input);
    return this.auth.adminLogin(body.phone, body.password, metadata(request));
  }
  @Post('mfa/verify')
  @HttpCode(200)
  @ApiBody({
    schema: bodyShape(['mfaChallengeId', 'mfaToken', 'code'], {
      mfaChallengeId: textField,
      mfaToken: textField,
      code: textField,
    }),
  })
  @ApiResponse({
    status: 200,
    description: 'MFA-complete session in HttpOnly cookies.',
    schema: { type: 'object', properties: { user: userShape, csrfToken: textField } },
  })
  async mfa(
    @Body() input: unknown,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    this.origin(request);
    const body = validate(mfaSchema, input);
    return this.cookies(
      response,
      await this.auth.verifyMfa(body.mfaChallengeId, body.mfaToken, body.code, metadata(request)),
    );
  }
  @Post('refresh')
  @HttpCode(200)
  @ApiCookieAuth('refresh')
  @ApiHeader({ name: 'X-CSRF-Token', required: true })
  @ApiResponse({
    status: 200,
    schema: { type: 'object', properties: { user: userShape, csrfToken: textField } },
  })
  async refresh(@Req() request: Request, @Res({ passthrough: true }) response: Response) {
    this.origin(request);
    return this.cookies(
      response,
      await this.auth.refresh(cookie(request, 'admin_refresh'), request.header('x-csrf-token')),
    );
  }
  @Post('logout')
  @HttpCode(204)
  @UseGuards(AccessGuard)
  @ApiCookieAuth('accessCookie')
  @ApiHeader({ name: 'X-CSRF-Token', required: true })
  @ApiResponse({ status: 204 })
  async logout(@Req() request: Request, @Res({ passthrough: true }) response: Response) {
    this.origin(request);
    await this.auth.logout(cookie(request, 'admin_access'), false, request.header('x-csrf-token'));
    for (const name of ['admin_access', 'admin_refresh', 'admin_csrf'])
      response.clearCookie(name, {
        path: '/',
        sameSite: 'strict',
        secure: this.auth.settings.env.CORS_ORIGIN.startsWith('https://'),
        httpOnly: name !== 'admin_csrf',
      });
  }
  @Get('me')
  @UseGuards(AccessGuard)
  @ApiCookieAuth('accessCookie')
  @ApiResponse({
    status: 200,
    schema: { type: 'object', properties: { user: userShape, csrfToken: textField } },
  })
  me(@Req() request: AuthRequest) {
    return { user: request.authenticated?.user, csrfToken: request.authenticated?.csrfToken };
  }
}

import { Injectable, type CanActivate, type ExecutionContext } from '@nestjs/common';
import type { Request } from 'express';
import type { z } from 'zod';
import { AuthService, AuthError } from './service';
export function validate<T>(schema: z.ZodType<T>, input: unknown): T {
  const result = schema.safeParse(input);
  if (!result.success) throw new AuthError('VALIDATION_ERROR', 400);
  return result.data;
}
export function metadata(request: Request) {
  return {
    ip: request.ip ?? request.socket.remoteAddress ?? 'unknown',
    device: request.header('user-agent')?.slice(0, 300) ?? 'unknown',
  };
}
export function cookie(request: Request, name: string): string {
  const entry = (request.header('cookie') ?? '')
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  try {
    return entry ? decodeURIComponent(entry.slice(name.length + 1)) : '';
  } catch {
    return '';
  }
}
export function bearer(request: Request): string {
  const value = request.header('authorization');
  if (!value?.startsWith('Bearer ') || value.length > 4096)
    throw new AuthError('INVALID_SESSION', 401);
  return value.slice(7);
}
export type AuthRequest = Request & {
  authenticated?: Awaited<ReturnType<AuthService['authenticate']>>;
};
@Injectable()
export class AccessGuard implements CanActivate {
  constructor(private readonly auth: AuthService) {}
  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest<AuthRequest>();
    request.authenticated = await this.auth.authenticate(
      this.auth.settings.role === 'ADMIN' ? cookie(request, 'admin_access') : bearer(request),
    );
    return true;
  }
}
export const bodyShape = (
  required: string[],
  properties: Record<string, { type: 'string'; enum?: string[]; maxLength?: number }>,
) => ({ type: 'object' as const, additionalProperties: false, required, properties });
export const textField = { type: 'string' as const };
export const userShape = {
  type: 'object' as const,
  required: ['id', 'role', 'maskedPhone', 'onboardingStatus'],
  properties: {
    id: { type: 'string' as const, format: 'uuid' },
    role: { type: 'string' as const, enum: ['CUSTOMER', 'WORKER', 'ADMIN', 'SUPER_ADMIN'] },
    maskedPhone: textField,
    onboardingStatus: { type: 'string' as const, enum: ['NOT_APPLICABLE', 'PENDING_ONBOARDING'] },
  },
};
export const sessionShape = {
  type: 'object' as const,
  required: ['accessToken', 'refreshToken', 'expiresInSeconds', 'user'],
  properties: {
    accessToken: textField,
    refreshToken: textField,
    expiresInSeconds: { type: 'integer' as const },
    user: userShape,
  },
};

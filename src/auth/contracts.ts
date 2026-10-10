import { z } from 'zod';
export const phoneSchema = z
  .string()
  .max(40)
  .transform((value) => value.replace(/[\s()-]/g, ''))
  .pipe(z.string().regex(/^\+[1-9]\d{7,14}$/));
export const requestSchema = z
  .object({ phone: phoneSchema, purpose: z.enum(['CUSTOMER_LOGIN', 'WORKER_LOGIN']) })
  .strict();
export const verifySchema = z
  .object({
    challengeId: z.uuid(),
    challengeToken: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    code: z.string().regex(/^\d{6}$/),
  })
  .strict();
export const refreshSchema = z
  .object({
    refreshToken: z
      .string()
      .max(150)
      .regex(/^[a-f0-9-]{36}\.[A-Za-z0-9_-]{43}$/),
  })
  .strict();
export const loginSchema = z
  .object({ phone: phoneSchema, password: z.string().min(1).max(128) })
  .strict();
export const mfaSchema = z
  .object({
    mfaChallengeId: z.uuid(),
    mfaToken: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    code: z.string().regex(/^\d{6}$/),
  })
  .strict();
export const userSchema = z.object({
  id: z.uuid(),
  role: z.enum(['CUSTOMER', 'WORKER', 'ADMIN', 'SUPER_ADMIN']),
  maskedPhone: z.string(),
  onboardingStatus: z.enum(['NOT_APPLICABLE', 'PENDING_ONBOARDING']),
});
export const claimsSchema = z.object({
  sub: z.uuid(),
  sid: z.uuid(),
  role: z.enum(['CUSTOMER', 'WORKER', 'ADMIN', 'SUPER_ADMIN']),
  mfa: z.boolean(),
  iat: z.number(),
  exp: z.number(),
  iss: z.string(),
  aud: z.string(),
});
export const maskPhone = (phone: string) =>
  `${phone.slice(0, 3)}${'*'.repeat(Math.max(0, phone.length - 7))}${phone.slice(-4)}`;

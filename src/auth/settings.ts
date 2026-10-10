import { z } from 'zod';
import { parseBackendEnvironment } from '../environment';
export type Role = 'CUSTOMER' | 'WORKER' | 'ADMIN' | 'SUPER_ADMIN';
export type BackendRole = 'CUSTOMER' | 'WORKER' | 'ADMIN';
const seconds = (value: number) => z.coerce.number().int().positive().default(value);
const schema = z.object({
  AUTH_ENABLED: z.enum(['true', 'false']).default('false'),
  AUTH_DIGEST_KEY: z
    .string()
    .regex(/^[a-f0-9]{64}$/i)
    .optional(),
  AUTH_ENCRYPTION_KEY: z
    .string()
    .regex(/^[a-f0-9]{64}$/i)
    .optional(),
  AUTH_PRIVATE_KEY: z.string().optional(),
  AUTH_PUBLIC_KEY: z.string().optional(),
  AUTH_ACCESS_TTL_SECONDS: seconds(900),
  AUTH_REFRESH_TTL_SECONDS: seconds(2592000),
  AUTH_OTP_TTL_SECONDS: seconds(300),
  AUTH_OTP_MAX_ATTEMPTS: seconds(5),
  AUTH_RESEND_SECONDS: seconds(60),
  AUTH_LIMIT_WINDOW_SECONDS: seconds(600),
  AUTH_PHONE_LIMIT: seconds(5),
  AUTH_IP_LIMIT: seconds(20),
  AUTH_ADMIN_LOGIN_LIMIT: seconds(10),
});
export class AuthSettings {
  readonly env;
  readonly values;
  readonly audience;
  readonly issuer;
  readonly keyId;
  constructor(
    readonly role: BackendRole,
    input: Record<string, unknown> = process.env,
  ) {
    this.env = parseBackendEnvironment(input);
    this.values = schema.parse(input);
    this.audience = `hire-me:${role.toLowerCase()}`;
    this.issuer = `trusted-assistance-${role.toLowerCase()}-api`;
    this.keyId = `${role.toLowerCase()}-v1`;
    if (
      this.enabled &&
      (!this.values.AUTH_DIGEST_KEY ||
        !this.values.AUTH_ENCRYPTION_KEY ||
        !this.values.AUTH_PRIVATE_KEY ||
        !this.values.AUTH_PUBLIC_KEY)
    )
      throw new Error('Authentication keys are missing. Run the restricted auth setup command.');
  }
  get enabled() {
    return this.values.AUTH_ENABLED === 'true';
  }
  get digestKey() {
    return this.values.AUTH_DIGEST_KEY ?? '';
  }
  get encryptionKey() {
    return this.values.AUTH_ENCRYPTION_KEY ?? '';
  }
  get privateKey() {
    return Buffer.from(this.values.AUTH_PRIVATE_KEY ?? '', 'base64').toString('utf8');
  }
  get publicKey() {
    return Buffer.from(this.values.AUTH_PUBLIC_KEY ?? '', 'base64').toString('utf8');
  }
}

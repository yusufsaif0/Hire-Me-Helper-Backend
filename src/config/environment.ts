import { z } from 'zod';
export const environmentSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().min(1).max(65535).default(4000),
    HOST: z.string().default('127.0.0.1'),
    INTEGRATIONS_MODE: z.literal('mock').default('mock'),
    CORS_ORIGIN: z.url().default('http://localhost:3000'),
    MONGODB_URI: z
      .string()
      .regex(/^mongodb(?:\+srv)?:\/\/.+$/, 'Expected a MongoDB connection URI')
      .default('mongodb://127.0.0.1:27017/?replicaSet=rs0&directConnection=true'),
    MONGODB_DB_NAME: z
      .string()
      .regex(/^[a-zA-Z0-9_-]+$/)
      .default('hire_me'),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production')
      ctx.addIssue({
        code: 'custom',
        path: ['NODE_ENV'],
        message: 'Mock-only development cannot run as production.',
      });
  });
export type Environment = z.infer<typeof environmentSchema>;
export function parseEnvironment(input: Record<string, unknown>): Environment {
  return environmentSchema.parse({ ...input, MONGODB_URI: input.MONGODB_URL ?? input.MONGODB_URI });
}

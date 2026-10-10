import { z } from 'zod';
export const apiServiceSchema = z.enum([
  'trusted-assistance-admin-api',
  'trusted-assistance-customer-api',
  'trusted-assistance-worker-api',
]);
export type ApiService = z.infer<typeof apiServiceSchema>;
export const healthResponseSchema = z.object({
  status: z.literal('ok'),
  service: apiServiceSchema,
  version: z.literal('0.1.0'),
  phase: z.literal(0),
  integrations: z.literal('mock'),
  timestamp: z.iso.datetime(),
});
export type HealthResponse = z.infer<typeof healthResponseSchema>;
export function healthResponseSchemaFor(service: ApiService) {
  return healthResponseSchema.extend({ service: z.literal(service) });
}
export const errorResponseSchema = z.object({
  statusCode: z.number().int(),
  message: z.string(),
  requestId: z.uuid(),
});
export type ErrorResponse = z.infer<typeof errorResponseSchema>;

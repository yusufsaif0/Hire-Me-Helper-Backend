export const backendRole = 'WORKER' as const;
import { parseEnvironment } from './config/environment';
export const serviceId = 'trusted-assistance-worker-api' as const;
export function parseBackendEnvironment(input: Record<string, unknown>) {
  return parseEnvironment({ PORT: 4002, CORS_ORIGIN: 'http://localhost:8082', ...input });
}

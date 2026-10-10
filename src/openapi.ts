import type { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
export function createOpenApi(app: INestApplication) {
  const document = SwaggerModule.createDocument(
    app,
    new DocumentBuilder()
      .setTitle('Trusted Assistance Worker API')
      .setDescription(
        'Phase 1 identity and access. Mock SMS only; no production startup. Health retains its Phase 0 liveness contract. Responses include an x-request-id UUID header.',
      )
      .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }, 'access')
      .addCookieAuth(
        'admin_access',
        { type: 'apiKey', in: 'cookie', name: 'admin_access' },
        'accessCookie',
      )
      .addCookieAuth(
        'admin_refresh',
        { type: 'apiKey', in: 'cookie', name: 'admin_refresh' },
        'refresh',
      )
      .setVersion('0.2.0')
      .build(),
  );
  for (const [path, item] of Object.entries(document.paths)) {
    if (!path.includes('/auth/')) continue;
    for (const method of ['get', 'post'] as const) {
      const operation = item[method];
      if (!operation) continue;
      for (const status of [400, 401, 403, 429, 503]) {
        operation.responses[status] = {
          description:
            status === 429
              ? 'Rate limited; retry after the indicated seconds.'
              : 'Correlated, redacted authentication error. See IDENTITY_API.md for codes.',
          headers: {
            'X-Request-ID': { schema: { type: 'string', format: 'uuid' } },
            ...(status === 429
              ? { 'Retry-After': { schema: { type: 'integer', minimum: 1 } } }
              : {}),
          },
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['statusCode', 'code', 'message', 'requestId'],
                properties: {
                  statusCode: { type: 'integer' },
                  code: { type: 'string' },
                  message: { type: 'string' },
                  requestId: { type: 'string', format: 'uuid' },
                },
              },
            },
          },
        };
      }
    }
  }
  return document;
}
export function configureOpenApi(app: INestApplication): void {
  SwaggerModule.setup('docs', app, createOpenApi(app));
}

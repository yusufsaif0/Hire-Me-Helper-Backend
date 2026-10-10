import { AuthError } from './auth/service';
import { randomUUID } from 'node:crypto';
import {
  Catch,
  HttpException,
  type ArgumentsHost,
  type ExceptionFilter,
  type INestApplication,
} from '@nestjs/common';
import type { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import type { Environment } from './config/environment';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
@Catch()
class HttpErrorFilter implements ExceptionFilter {
  catch(error: unknown, host: ArgumentsHost): void {
    const response = host.switchToHttp().getResponse<Response>();
    const statusCode = error instanceof HttpException ? error.getStatus() : 500;
    const detail = error instanceof HttpException ? error.getResponse() : null;
    const code =
      typeof detail === 'object' && detail !== null && 'code' in detail
        ? String(detail.code)
        : 'HTTP_ERROR';
    if (error instanceof AuthError && error.retryAfter)
      response.setHeader('Retry-After', String(error.retryAfter));
    response.setHeader('Cache-Control', 'no-store');
    response.status(statusCode).json({
      code,
      statusCode,
      message: error instanceof HttpException ? error.message : 'Internal server error',
      requestId: response.getHeader('x-request-id'),
    });
  }
}
export function configureHttp(app: INestApplication, env: Environment): void {
  app.setGlobalPrefix('v1');
  app.use(helmet());
  app.use((_request: Request, response: Response, next: NextFunction) => {
    response.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.enableCors({
    credentials: true,
    origin: env.CORS_ORIGIN,
    exposedHeaders: ['x-request-id', 'retry-after'],
  });
  app.use((request: Request, response: Response, next: NextFunction) => {
    const supplied = request.header('x-request-id');
    const requestId = supplied && uuid.test(supplied) ? supplied : randomUUID();
    response.setHeader('x-request-id', requestId);
    const started = performance.now();
    response.on('finish', () =>
      console.info(
        JSON.stringify({
          event: 'http_request',
          requestId,
          method: request.method,
          path: request.path,
          status: response.statusCode,
          durationMs: Math.round(performance.now() - started),
        }),
      ),
    );
    next();
  });
  app.useGlobalFilters(new HttpErrorFilter());
  app.enableShutdownHooks();
}

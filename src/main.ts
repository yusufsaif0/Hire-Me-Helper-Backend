import 'reflect-metadata';
import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { parseBackendEnvironment } from './environment';
import { AppModule } from './app.module';
import { configureHttp } from './http';
import { configureOpenApi } from './openapi';
async function bootstrap(): Promise<void> {
  const env = parseBackendEnvironment(process.env);
  const app = await NestFactory.create(AppModule);
  configureHttp(app, env);
  configureOpenApi(app);
  await app.listen(env.PORT, env.HOST);
}
void bootstrap().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : 'Startup failed');
  process.exitCode = 1;
});

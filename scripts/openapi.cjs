require('reflect-metadata');
const fs = require('node:fs');
const path = require('node:path');
const { NestFactory } = require('@nestjs/core');
const { AppModule } = require('../dist/app.module');
const { configureHttp } = require('../dist/http');
const { createOpenApi } = require('../dist/openapi');
const { parseBackendEnvironment } = require('../dist/environment');
(async () => {
  const app = await NestFactory.create(AppModule, { logger: false });
  try {
    configureHttp(app, parseBackendEnvironment({ NODE_ENV: 'test' }));
    fs.mkdirSync(path.resolve(__dirname, '../docs'), { recursive: true });
    fs.writeFileSync(
      path.resolve(__dirname, '../docs/openapi.json'),
      JSON.stringify(createOpenApi(app), null, 2) + '\n',
    );
  } finally {
    await app.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

require('reflect-metadata');
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { Test } = require('@nestjs/testing');
const request = require('supertest');
const { AppModule } = require('../dist/app.module');
const { configureHttp } = require('../dist/http');
const { createOpenApi } = require('../dist/openapi');
const { parseBackendEnvironment, serviceId } = require('../dist/environment');
const { healthResponseSchema, errorResponseSchema } = require('../dist/lib/contracts');
let app;
before(async () => {
  const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
  app = module.createNestApplication();
  configureHttp(app, parseBackendEnvironment({ NODE_ENV: 'test' }));
  await app.init();
});
after(async () => {
  await app?.close();
});
test('health response conforms to local contract and security headers', async () => {
  const response = await request(app.getHttpServer()).get('/v1/health').expect(200);
  healthResponseSchema.parse(response.body);
  assert.equal(response.body.service, serviceId);
  assert.match(response.headers['x-request-id'], /^[\da-f-]{36}$/);
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
  assert.match(response.headers['access-control-expose-headers'], /retry-after/i);
});
test('valid correlation ID is preserved; unsafe values are replaced', async () => {
  const id = '8f1dc90a-cfa3-4c5a-b747-ce9d06f01fb3';
  const response = await request(app.getHttpServer()).get('/v1/health').set('x-request-id', id);
  assert.equal(response.headers['x-request-id'], id);
  const invalid = await request(app.getHttpServer())
    .get('/v1/health')
    .set('x-request-id', 'private-information');
  assert.notEqual(invalid.headers['x-request-id'], 'private-information');
});
test('errors carry the same correlation ID and unknown routes are not exposed', async () => {
  const response = await request(app.getHttpServer()).get('/v1/bookings').expect(404);
  errorResponseSchema.parse(response.body);
  assert.equal(response.body.requestId, response.headers['x-request-id']);
});
test('OpenAPI exposes health and only the corresponding identity routes', () => {
  const paths = Object.keys(createOpenApi(app).paths);
  assert.ok(paths.includes('/v1/health'));
  assert.equal(paths.length, 7 - (serviceId.includes('-admin-') ? 1 : 0));
  assert.equal(
    paths.some((path) => path.includes('register')),
    false,
  );
  assert.equal(
    paths.some((path) => path.includes('/admin/auth/')),
    serviceId.includes('-admin-'),
  );
});

test('backend owns its port and origin while using shared MongoDB settings', () => {
  const env = parseBackendEnvironment({ NODE_ENV: 'test' });
  assert.equal(env.PORT, 4002);
  assert.equal(env.CORS_ORIGIN, 'http://localhost:8082');
  assert.equal(env.MONGODB_DB_NAME, 'hire_me');
  assert.equal(env.MONGODB_URI, 'mongodb://127.0.0.1:27017/?replicaSet=rs0&directConnection=true');
  assert.equal(parseBackendEnvironment({ PORT: '4900' }).PORT, 4900);
});

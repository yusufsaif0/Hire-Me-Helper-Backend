const { test } = require('node:test');
const assert = require('node:assert/strict');
const { parseEnvironment } = require('../dist/config/environment');
test('local defaults are safe and port strings are parsed', () => {
  assert.equal(parseEnvironment({ PORT: '4100' }).PORT, 4100);
  assert.equal(parseEnvironment({}).HOST, '127.0.0.1');
});
test('invalid ports, live integrations and production mocks fail closed', () => {
  for (const env of [
    { PORT: 0 },
    { PORT: 65536 },
    { PORT: 'abc' },
    { INTEGRATIONS_MODE: 'live' },
    { NODE_ENV: 'production' },
    { CORS_ORIGIN: 'invalid' },
    { MONGODB_URI: 'http://localhost' },
    { MONGODB_DB_NAME: 'invalid/database' },
  ])
    assert.throws(() => parseEnvironment(env));
});

test('Atlas URL input is validated and selects the shared app database', () => {
  const url = 'mongodb+srv://example.mongodb.net/hire_me?retryWrites=true&w=majority';
  const env = parseEnvironment({ MONGODB_URL: url });
  assert.equal(env.MONGODB_URI, url);
  assert.equal(env.MONGODB_DB_NAME, 'hire_me');
  assert.throws(() => parseEnvironment({ MONGODB_URL: 'https://example.com' }));
  assert.equal(parseEnvironment({ MONGODB_URI: url }).MONGODB_URI, url);
});

require('reflect-metadata');
require('dotenv/config');
const { randomUUID, randomBytes, generateKeyPairSync } = require('node:crypto');
const { MongoClient } = require('mongodb');
const { Test } = require('@nestjs/testing');
const { migrate } = require('../test/fixtures/identity-schema.cjs');
const { backendRole, parseBackendEnvironment } = require('../dist/environment');
const { AppModule } = require('../dist/app.module');
const { configureHttp } = require('../dist/http');
const { AuthSettings } = require('../dist/auth/settings');
const { AuthRepository } = require('../dist/auth/repository');
const { AuthService } = require('../dist/auth/service');
const { MockSms } = require('../dist/auth/mock-sms');
const { seal } = require('../dist/auth/crypto');
const dbName = `hire_me_test_ui_${backendRole.toLowerCase()}_${randomUUID().replaceAll('-', '')}`;
const uri =
  process.env.TEST_MONGODB_URL ?? 'mongodb://127.0.0.1:27018/?replicaSet=rs0&directConnection=true';
let app, repo;
let clockOffset = 0;
const client = new MongoClient(uri, { serverSelectionTimeoutMS: 4000 });
let stopped = false;
async function shutdown() {
  if (stopped) return;
  stopped = true;
  await app?.close();
  await repo?.onModuleDestroy();
  if (/^hire_me_test_ui_(admin|customer|worker)_[a-f0-9]{32}$/.test(dbName))
    await client.db(dbName).dropDatabase();
  await client.close();
  process.exit(0);
}
(async () => {
  if (
    process.env.NODE_ENV !== 'test' ||
    !['127.0.0.1', 'localhost'].includes(new URL(uri).hostname)
  )
    throw new Error('UI fixtures require explicit test mode and local MongoDB');
  const keys = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  const input = {
    ...process.env,
    NODE_ENV: 'test',
    MONGODB_URL: uri,
    MONGODB_DB_NAME: dbName,
    AUTH_ENABLED: 'true',
    AUTH_DIGEST_KEY: randomBytes(32).toString('hex'),
    AUTH_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
    AUTH_PRIVATE_KEY: Buffer.from(keys.privateKey).toString('base64'),
    AUTH_PUBLIC_KEY: Buffer.from(keys.publicKey).toString('base64'),
    AUTH_RESEND_SECONDS: '2',
    AUTH_ADMIN_LOGIN_LIMIT: '100',
    AUTH_IP_LIMIT: '100',
  };
  await client.connect();
  await migrate(client, dbName);
  const settings = new AuthSettings(backendRole, input);
  repo = new AuthRepository(settings);
  const sms = new MockSms(settings, true);
  const auth = new AuthService(
    settings,
    repo,
    sms,
    () => Date.now() + clockOffset,
    () => '456789',
  );
  if (backendRole === 'ADMIN') {
    const provisionSettings = new AuthSettings('ADMIN', { ...input, NODE_ENV: 'development' }),
      provisionRepo = new AuthRepository(provisionSettings);
    try {
      await new AuthService(
        provisionSettings,
        provisionRepo,
        new MockSms(provisionSettings),
      ).provisionAdmin('+919998887777', 'Phase1-UI-test-only-password!');
    } finally {
      await provisionRepo.onModuleDestroy();
    }
    await client
      .db(dbName)
      .collection('admin_credentials')
      .updateOne(
        {},
        {
          $set: {
            totpSealed: seal(
              settings.encryptionKey,
              Buffer.from('12345678901234567890').toString('hex'),
            ),
          },
        },
      );
  }
  const module = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(AuthSettings)
    .useValue(settings)
    .overrideProvider(AuthRepository)
    .useValue(repo)
    .overrideProvider(MockSms)
    .useValue(sms)
    .overrideProvider(AuthService)
    .useValue(auth)
    .compile();
  app = module.createNestApplication();
  configureHttp(app, parseBackendEnvironment(input));
  await app.listen(Number(process.env.E2E_BACKEND_PORT), '127.0.0.1');
  console.log('UI_FIXTURE_READY');
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    const command = chunk.trim();
    if (command === 'shutdown') void shutdown();
    if (command === 'advance') {
      clockOffset += 61000;
      console.log('UI_FIXTURE_ADVANCED');
    }
    if (command === 'revoke')
      void client
        .db(dbName)
        .collection('sessions')
        .updateMany({}, { $set: { revokedAt: new Date() } })
        .then(() => console.log('UI_FIXTURE_REVOKED'));
  });
  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());
})().catch(async () => {
  console.error('UI fixture server failed; no secrets printed.');
  await app?.close();
  await repo?.onModuleDestroy();
  if (/^hire_me_test_ui_(admin|customer|worker)_[a-f0-9]{32}$/.test(dbName))
    await client
      .db(dbName)
      .dropDatabase()
      .catch(() => {});
  await client.close();
  process.exitCode = 1;
});

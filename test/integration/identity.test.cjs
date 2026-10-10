require('reflect-metadata');
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, randomBytes, generateKeyPairSync } = require('node:crypto');
const { MongoClient } = require('mongodb');
const { Test } = require('@nestjs/testing');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const { migrate } = require('../fixtures/identity-schema.cjs');
const { AuthSettings } = require('../../dist/auth/settings');
const { AuthRepository } = require('../../dist/auth/repository');
const { AuthService } = require('../../dist/auth/service');
const { MockSms } = require('../../dist/auth/mock-sms');
const { totp } = require('../../dist/auth/crypto');
const { AppModule } = require('../../dist/app.module');
const { backendRole, parseBackendEnvironment } = require('../../dist/environment');
const { configureHttp } = require('../../dist/http');
const dbName = `hire_me_test_${backendRole.toLowerCase()}_${randomUUID().replaceAll('-', '')}`;
const uri =
  process.env.TEST_MONGODB_URL ?? 'mongodb://127.0.0.1:27018/?replicaSet=rs0&directConnection=true';
const client = new MongoClient(uri, { serverSelectionTimeoutMS: 4000 });
const commonDigest = randomBytes(32).toString('hex');
const settings = {},
  services = {},
  repos = {},
  sms = {};
let app,
  db,
  phoneSequence = 100000;
const freshPhone = () => `+919999${phoneSequence++}`;
const meta = { ip: 'test-loopback', device: 'test-fixture' };
function config(role, changes = {}) {
  const keys = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return {
    NODE_ENV: 'test',
    AUTH_ENABLED: 'true',
    MONGODB_URL: uri,
    MONGODB_DB_NAME: dbName,
    AUTH_DIGEST_KEY: commonDigest,
    AUTH_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
    AUTH_PRIVATE_KEY: Buffer.from(keys.privateKey).toString('base64'),
    AUTH_PUBLIC_KEY: Buffer.from(keys.publicKey).toString('base64'),
    AUTH_IP_LIMIT: '500',
    AUTH_ADMIN_LOGIN_LIMIT: '500',
    CORS_ORIGIN:
      role === 'ADMIN'
        ? 'http://localhost:3000'
        : `http://localhost:${role === 'CUSTOMER' ? 8081 : 8082}`,
    ...changes,
  };
}
async function login(role, phone = freshPhone()) {
  const challenge = await services[role].requestOtp(phone, `${role}_LOGIN`, meta);
  return services[role].verifyOtp(
    challenge.challengeId,
    challenge.challengeToken,
    sms[role].capturedCode(challenge.challengeId),
    meta,
  );
}
before(async () => {
  if (!uri.startsWith('mongodb://') || !['127.0.0.1', 'localhost'].includes(new URL(uri).hostname))
    throw new Error('Integration tests require isolated local MongoDB, never Atlas');
  await client.connect();
  db = client.db(dbName);
  await migrate(client, dbName);
  for (const role of ['CUSTOMER', 'WORKER', 'ADMIN']) {
    settings[role] = new AuthSettings(role, config(role));
    repos[role] = new AuthRepository(settings[role]);
    sms[role] = new MockSms(settings[role], true);
    services[role] = new AuthService(settings[role], repos[role], sms[role]);
  }
  const module = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(AuthSettings)
    .useValue(settings[backendRole])
    .overrideProvider(AuthRepository)
    .useValue(repos[backendRole])
    .overrideProvider(MockSms)
    .useValue(sms[backendRole])
    .overrideProvider(AuthService)
    .useValue(services[backendRole])
    .compile();
  app = module.createNestApplication();
  configureHttp(
    app,
    parseBackendEnvironment({
      NODE_ENV: 'test',
      CORS_ORIGIN: settings[backendRole].env.CORS_ORIGIN,
    }),
  );
  await app.init();
});
after(async () => {
  await app?.close();
  for (const repo of Object.values(repos)) await repo.onModuleDestroy();
  if (!/^hire_me_test_(admin|customer|worker)_[a-f0-9]{32}$/.test(dbName))
    throw new Error('Unsafe test cleanup');
  if (db) await db.dropDatabase();
  await client.close();
});
test('real schema enforces identity/membership uniqueness and TTL cleanup indexes', async () => {
  const challengeIndexes = await db.collection('otp_challenges').indexes();
  assert.equal(
    challengeIndexes.find((index) => index.name === 'challenge_expiry').expireAfterSeconds,
    0,
  );
  assert.equal(
    (await db.collection('sessions').indexes()).find((index) => index.name === 'session_expiry')
      .expireAfterSeconds,
    0,
  );
  const identity = await login('CUSTOMER');
  const stored = await db.collection('identities').findOne({ _id: identity.user.id });
  await assert.rejects(
    () => db.collection('identities').insertOne({ ...stored, _id: randomUUID() }),
    (error) => error.code === 11000,
  );
});
test('concurrent customer/worker enrollment shares one identity with separate memberships', async () => {
  const phone = freshPhone();
  const challenges = await Promise.all(
    ['CUSTOMER', 'WORKER'].map((role) => services[role].requestOtp(phone, `${role}_LOGIN`, meta)),
  );
  const results = await Promise.all(
    ['CUSTOMER', 'WORKER'].map((role, index) =>
      services[role].verifyOtp(
        challenges[index].challengeId,
        challenges[index].challengeToken,
        sms[role].capturedCode(challenges[index].challengeId),
        meta,
      ),
    ),
  );
  assert.equal(results[0].user.id, results[1].user.id);
  assert.equal(await db.collection('identities').countDocuments({ phone }), 1);
  assert.equal(
    await db.collection('role_memberships').countDocuments({ identityId: results[0].user.id }),
    2,
  );
  assert.equal(results[1].user.onboardingStatus, 'PENDING_ONBOARDING');
});
test('challenge secret, attempts, expiry and one-time consumption are enforced', async () => {
  const service = services.CUSTOMER;
  let challenge = await service.requestOtp(freshPhone(), 'CUSTOMER_LOGIN', meta);
  const code = sms.CUSTOMER.capturedCode(challenge.challengeId);
  assert.equal('code' in challenge, false);
  const stored = await db.collection('otp_challenges').findOne({ _id: challenge.challengeId });
  assert.notEqual(stored.codeDigest, code);
  assert.equal('code' in stored, false);
  await assert.rejects(
    () =>
      service.verifyOtp(challenge.challengeId, randomBytes(32).toString('base64url'), code, meta),
    (error) => error.code === 'INVALID_CHALLENGE',
  );
  const outcomes = await Promise.allSettled([
    service.verifyOtp(challenge.challengeId, challenge.challengeToken, code, meta),
    service.verifyOtp(challenge.challengeId, challenge.challengeToken, code, meta),
  ]);
  assert.equal(outcomes.filter((outcome) => outcome.status === 'fulfilled').length, 1);
  challenge = await service.requestOtp(freshPhone(), 'CUSTOMER_LOGIN', meta);
  for (let count = 0; count < 5; count++)
    await assert.rejects(
      () => service.verifyOtp(challenge.challengeId, challenge.challengeToken, 'invalid', meta),
      (error) => error.code === 'INVALID_CHALLENGE',
    );
  await assert.rejects(
    () =>
      service.verifyOtp(
        challenge.challengeId,
        challenge.challengeToken,
        sms.CUSTOMER.capturedCode(challenge.challengeId),
        meta,
      ),
    (error) => error.code === 'INVALID_CHALLENGE',
  );
  challenge = await service.requestOtp(freshPhone(), 'CUSTOMER_LOGIN', meta);
  await db
    .collection('otp_challenges')
    .updateOne({ _id: challenge.challengeId }, { $set: { expiresAt: new Date(0) } });
  await assert.rejects(
    () =>
      service.verifyOtp(
        challenge.challengeId,
        challenge.challengeToken,
        sms.CUSTOMER.capturedCode(challenge.challengeId),
        meta,
      ),
    (error) => error.code === 'INVALID_CHALLENGE',
  );
});
test('resend cooldown and configurable IP/phone limits survive a repository restart', async () => {
  const phone = freshPhone();
  await services.CUSTOMER.requestOtp(phone, 'CUSTOMER_LOGIN', meta);
  await assert.rejects(
    () => services.CUSTOMER.requestOtp(phone, 'CUSTOMER_LOGIN', meta),
    (error) => error.code === 'RATE_LIMITED',
  );
  const limited = new AuthSettings('CUSTOMER', config('CUSTOMER', { AUTH_IP_LIMIT: '1' }));
  const repo = new AuthRepository(limited),
    capture = new MockSms(limited, true),
    service = new AuthService(limited, repo, capture);
  try {
    const restricted = { ip: randomUUID(), device: 'fixture' };
    await service.requestOtp(freshPhone(), 'CUSTOMER_LOGIN', restricted);
    await repo.onModuleDestroy();
    const reopened = new AuthRepository(limited);
    try {
      await assert.rejects(
        () =>
          new AuthService(limited, reopened, capture).requestOtp(
            freshPhone(),
            'CUSTOMER_LOGIN',
            restricted,
          ),
        (error) => error.code === 'RATE_LIMITED',
      );
    } finally {
      await reopened.onModuleDestroy();
    }
  } finally {
    await repo.onModuleDestroy();
  }
});
test('refresh rotation detects reuse and concurrent refresh revokes the winning family', async () => {
  let session = await login('CUSTOMER');
  const rotated = await services.CUSTOMER.refresh(session.refreshToken);
  assert.notEqual(rotated.refreshToken, session.refreshToken);
  await assert.rejects(
    () => services.CUSTOMER.refresh(session.refreshToken),
    (error) => error.code === 'INVALID_SESSION',
  );
  await assert.rejects(
    () => services.CUSTOMER.authenticate(rotated.accessToken),
    (error) => error.code === 'INVALID_SESSION',
  );
  session = await login('CUSTOMER');
  const outcomes = await Promise.allSettled([
    services.CUSTOMER.refresh(session.refreshToken),
    services.CUSTOMER.refresh(session.refreshToken),
  ]);
  assert.equal(outcomes.filter((result) => result.status === 'fulfilled').length, 1);
  const winner = outcomes.find((result) => result.status === 'fulfilled').value;
  await assert.rejects(
    () => services.CUSTOMER.authenticate(winner.accessToken),
    (error) => error.code === 'INVALID_SESSION',
  );
});
test('logout, role-scoped logout-all and session status persist across connection restart', async () => {
  const phone = freshPhone();
  let session = await login('CUSTOMER', phone);
  const reopened = new AuthRepository(settings.CUSTOMER);
  try {
    assert.equal(
      (
        await new AuthService(settings.CUSTOMER, reopened, sms.CUSTOMER).authenticate(
          session.accessToken,
        )
      ).user.id,
      session.user.id,
    );
  } finally {
    await reopened.onModuleDestroy();
  }
  await services.CUSTOMER.logout(session.accessToken);
  await assert.rejects(() => services.CUSTOMER.authenticate(session.accessToken));
  await db.collection('auth_limits').deleteOne({
    _id: `${settings.CUSTOMER.audience}:cooldown:${require('../../dist/auth/crypto').digest(commonDigest, 'phone', phone)}`,
  });
  session = await login('CUSTOMER', phone);
  const worker = await login('WORKER', phone);
  await services.CUSTOMER.logout(session.accessToken, true);
  await assert.rejects(() => services.CUSTOMER.authenticate(session.accessToken));
  assert.equal((await services.WORKER.authenticate(worker.accessToken)).user.role, 'WORKER');
});
test('JWT signature, issuer/audience, role, expiry and membership revocation are checked', async () => {
  const customer = await login('CUSTOMER'),
    worker = await login('WORKER');
  await assert.rejects(() => services.CUSTOMER.authenticate(worker.accessToken));
  await assert.rejects(() => services.WORKER.authenticate(customer.accessToken));
  await assert.rejects(() => services.ADMIN.authenticate(customer.accessToken));
  const original = jwt.decode(customer.accessToken);
  const sign = (changes) =>
    jwt.sign({ ...original, ...changes }, settings.CUSTOMER.privateKey, {
      algorithm: 'RS256',
      keyid: settings.CUSTOMER.keyId,
    });
  for (const changes of [
    { role: 'ADMIN' },
    { aud: 'hire-me:worker' },
    { iss: 'wrong' },
    { exp: 1 },
  ])
    await assert.rejects(() => services.CUSTOMER.authenticate(sign(changes)));
  await db
    .collection('role_memberships')
    .updateOne(
      { identityId: customer.user.id, role: 'CUSTOMER' },
      { $set: { status: 'DISABLED' } },
    );
  await assert.rejects(() => services.CUSTOMER.authenticate(customer.accessToken));
  await assert.rejects(() => services.CUSTOMER.refresh(customer.refreshToken));
});
test('admin provisioning is restricted, password alone grants no session, TOTP cannot replay', async () => {
  const phone = freshPhone(),
    password = 'Fixture-only admin password, not a real account';
  await assert.rejects(() => services.CUSTOMER.provisionAdmin(phone, password));
  await assert.rejects(() => services.ADMIN.requestOtp(phone, 'CUSTOMER_LOGIN', meta));
  const setup = new AuthSettings('ADMIN', {
    ...settings.ADMIN.env,
    ...settings.ADMIN.values,
    NODE_ENV: 'development',
  });
  const setupRepo = new AuthRepository(setup);
  let seed;
  try {
    seed = await new AuthService(setup, setupRepo, new MockSms(setup)).provisionAdmin(
      phone,
      password,
    );
  } finally {
    await setupRepo.onModuleDestroy();
  }
  await assert.rejects(
    () => services.ADMIN.adminLogin(phone, 'wrong', meta),
    (error) => error.code === 'INVALID_CREDENTIALS',
  );
  const challenge = await services.ADMIN.adminLogin(phone, password, meta);
  assert.equal('accessToken' in challenge, false);
  assert.equal(await db.collection('sessions').countDocuments({ role: 'ADMIN' }), 0);
  await assert.rejects(() =>
    services.ADMIN.verifyMfa(challenge.mfaChallengeId, challenge.mfaToken, 'wrong', meta),
  );
  const code = totp(seed, Math.floor(Date.now() / 30000));
  const session = await services.ADMIN.verifyMfa(
    challenge.mfaChallengeId,
    challenge.mfaToken,
    code,
    meta,
  );
  assert.equal((await services.ADMIN.authenticate(session.accessToken)).user.role, 'ADMIN');
  await assert.rejects(() =>
    services.ADMIN.verifyMfa(challenge.mfaChallengeId, challenge.mfaToken, code, meta),
  );
  const next = await services.ADMIN.adminLogin(phone, password, meta);
  await assert.rejects(() =>
    services.ADMIN.verifyMfa(next.mfaChallengeId, next.mfaToken, code, meta),
  );
  await assert.rejects(
    () => services.ADMIN.refresh(session.refreshToken, 'invalid'),
    (error) => error.code === 'FORBIDDEN',
  );
  const rotated = await services.ADMIN.refresh(session.refreshToken, session.csrfToken);
  await services.ADMIN.logout(rotated.accessToken, false, rotated.csrfToken);
});
test('actual HTTP routes validate input, keep codes out of responses/logs and exclude admin registration', async () => {
  const http = request(app.getHttpServer());
  await http.post('/v1/admin/auth/register').send({ phone: freshPhone() }).expect(404);
  if (backendRole === 'ADMIN') {
    await http
      .post('/v1/auth/otp/request')
      .send({ phone: freshPhone(), purpose: 'CUSTOMER_LOGIN' })
      .expect(404);
    await http.get('/v1/admin/auth/me').expect(401);
    await http
      .post('/v1/admin/auth/login')
      .set('Origin', 'https://untrusted.example')
      .send({ phone: freshPhone(), password: 'fixture' })
      .expect(403);
  } else {
    await http
      .post('/v1/auth/otp/request')
      .send({ phone: 'invalid', purpose: `${backendRole}_LOGIN` })
      .expect(400);
    const logged = [];
    const original = console.info;
    console.info = (line) => logged.push(JSON.parse(line));
    try {
      const challenge = await http
        .post('/v1/auth/otp/request')
        .send({ phone: freshPhone(), purpose: `${backendRole}_LOGIN` })
        .expect(202);
      assert.equal('code' in challenge.body, false);
      const signed = await http
        .post('/v1/auth/otp/verify')
        .send({ ...challenge.body, code: '123456' })
        .expect(400);
      assert.equal(signed.body.code, 'VALIDATION_ERROR');
      assert.ok(
        logged.every(
          (record) =>
            Object.keys(record).sort().join(',') ===
            'durationMs,event,method,path,requestId,status',
        ),
      );
      const result = await http
        .post('/v1/auth/otp/verify')
        .send({
          challengeId: challenge.body.challengeId,
          challengeToken: challenge.body.challengeToken,
          code: sms[backendRole].capturedCode(challenge.body.challengeId),
        })
        .expect(200);
      await http
        .get('/v1/auth/me')
        .set('Authorization', `Bearer ${result.body.accessToken}`)
        .expect(200);
      assert.equal(result.headers['cache-control'], 'no-store');
    } finally {
      console.info = original;
    }
  }
});

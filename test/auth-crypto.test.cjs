const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const {
  digest,
  same,
  seal,
  unseal,
  hashPassword,
  verifyPassword,
  totp,
  matchTotp,
  base32,
} = require('../dist/auth/crypto');
const { phoneSchema } = require('../dist/auth/contracts');
test('phone normalization is international and rejects ambiguous or oversized input', () => {
  assert.equal(phoneSchema.parse('+91 (90000) 12345'), '+919000012345');
  for (const value of ['9000012345', '+0123456789', '+12', '+1234567890123456', '+91<script>'])
    assert.equal(phoneSchema.safeParse(value).success, false);
});
test('keyed code hashes separate domains and protected values reject tampering', () => {
  const key = randomBytes(32).toString('hex');
  assert.notEqual(digest(key, 'otp:one', '123456'), digest(key, 'otp:two', '123456'));
  const encrypted = seal(key, 'fixture');
  assert.equal(unseal(key, encrypted), 'fixture');
  assert.throws(() => unseal(randomBytes(32).toString('hex'), encrypted));
  assert.equal(same('abc', 'ab'), false);
});
test('salted password hashes verify without retaining plaintext', async () => {
  const password = 'Test-only password, never a seeded admin';
  const hash = await hashPassword(password);
  assert.notEqual(hash, await hashPassword(password));
  assert.equal(await verifyPassword(password, hash), true);
  assert.equal(await verifyPassword('incorrect', hash), false);
});
test('TOTP follows the RFC 6238 SHA-1 test vector and narrow clock window', () => {
  const seed = Buffer.from('12345678901234567890').toString('hex');
  assert.equal(totp(seed, 1), '287082');
  assert.equal(matchTotp(seed, '287082', 59000), 1);
  assert.equal(matchTotp(seed, '287082', 180000), null);
  assert.equal(base32(seed), 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
});

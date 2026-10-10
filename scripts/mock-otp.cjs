require('dotenv/config');
const fs = require('node:fs');
const path = require('node:path');
const { backendRole } = require('../dist/environment');
const { AuthSettings } = require('../dist/auth/settings');
const { unseal } = require('../dist/auth/crypto');
try {
  const settings = new AuthSettings(backendRole);
  const id = process.argv[2];
  if (
    !process.stdout.isTTY ||
    !settings.enabled ||
    settings.env.NODE_ENV !== 'development' ||
    settings.env.HOST !== '127.0.0.1' ||
    !/^[a-f0-9-]{36}$/.test(id ?? '')
  )
    throw new Error('Private local development terminal required');
  const filename = path.resolve('.cache/mock-sms', `${id}.json`);
  const message = JSON.parse(fs.readFileSync(filename, 'utf8'));
  if (Date.parse(message.expiresAt) <= Date.now()) {
    fs.unlinkSync(filename);
    throw new Error('Expired');
  }
  process.stdout.write(
    `Development test code: ${unseal(settings.encryptionKey, message.sealed)}\n`,
  );
  fs.unlinkSync(filename);
} catch {
  console.error(
    'Mock code unavailable. Requires local development, an interactive terminal and a current challenge ID.',
  );
  process.exitCode = 1;
}

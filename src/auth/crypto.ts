import {
  createHmac,
  timingSafeEqual,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  scrypt,
} from 'node:crypto';
export function digest(key: string, domain: string, value: string): string {
  return createHmac('sha256', Buffer.from(key, 'hex')).update(`${domain}\0${value}`).digest('hex');
}
export function same(left: string, right: string): boolean {
  const a = Buffer.from(left),
    b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}
export function seal(key: string, value: string): string {
  const iv = randomBytes(12),
    cipher = createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
  const body = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), body].map((part) => part.toString('base64url')).join('.');
}
export function unseal(key: string, value: string): string {
  const parts = value.split('.').map((part) => Buffer.from(part, 'base64url'));
  const [iv, tag, body] = parts;
  if (parts.length !== 3 || !iv || !tag || !body) throw new Error('Invalid protected value');
  const cipher = createDecipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
  cipher.setAuthTag(tag);
  return Buffer.concat([cipher.update(body), cipher.final()]).toString('utf8');
}
async function derive(password: string, salt: string): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scrypt(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 67108864 }, (error, result) =>
      error ? reject(error) : resolve(result),
    ),
  );
}
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(32).toString('hex');
  return `${salt}:${(await derive(password, salt)).toString('hex')}`;
}
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash || !/^[a-f0-9]{64}$/.test(salt) || !/^[a-f0-9]{128}$/.test(hash)) return false;
  return same((await derive(password, salt)).toString('hex'), hash);
}
export function totp(seedHex: string, counter: number): string {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', Buffer.from(seedHex, 'hex')).update(bytes).digest();
  const offset = (mac[mac.length - 1] ?? 0) & 15;
  return ((mac.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
}
export function matchTotp(seed: string, code: string, now: number): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const counter = Math.floor(now / 30000);
  for (const offset of [0, -1, 1])
    if (counter + offset >= 0 && same(totp(seed, counter + offset), code)) return counter + offset;
  return null;
}
export function base32(hex: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0,
    value = 0,
    output = '';
  for (const byte of Buffer.from(hex, 'hex')) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += alphabet[(value >>> bits) & 31];
    }
  }
  if (bits) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

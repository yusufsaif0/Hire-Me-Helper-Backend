import { HttpException } from '@nestjs/common';
import { randomUUID, randomBytes, randomInt } from 'node:crypto';
import jwt from 'jsonwebtoken';
import type { ClientSession, Document } from 'mongodb';
import { AuthSettings, type Role } from './settings';
import {
  AuthRepository,
  type Identity,
  type Membership,
  type Challenge,
  type Session,
  type AdminCredential,
  type MfaChallenge,
} from './repository';
import { MockSms } from './mock-sms';
import { digest, same, seal, unseal, verifyPassword, matchTotp, hashPassword } from './crypto';
import { claimsSchema, maskPhone, phoneSchema } from './contracts';
export class AuthError extends HttpException {
  constructor(
    readonly code: string,
    status: number,
    readonly retryAfter = 0,
  ) {
    super(
      {
        code,
        message:
          status === 503
            ? 'Authentication is unavailable.'
            : status === 429
              ? 'Try again later.'
              : status === 400
                ? 'Invalid request.'
                : 'Authentication request denied.',
      },
      status,
    );
  }
}
type RequestMeta = { ip: string; device: string };
export class AuthService {
  private readonly generateOtp: () => string;
  constructor(
    readonly settings: AuthSettings,
    readonly repo: AuthRepository,
    readonly sms: MockSms,
    private readonly now: () => number = Date.now,
    generateOtp?: () => string,
  ) {
    if (generateOtp && settings.env.NODE_ENV !== 'test')
      throw new Error('OTP fixture injection is test-only');
    this.generateOtp = generateOtp ?? (() => randomInt(1000000).toString().padStart(6, '0'));
  }
  private hash(domain: string, value: string) {
    return digest(this.settings.digestKey, domain, value);
  }
  private roleAllowed(role: Role) {
    return this.settings.role === 'ADMIN'
      ? role === 'ADMIN' || role === 'SUPER_ADMIN'
      : role === this.settings.role;
  }
  async ready() {
    try {
      await this.repo.ready();
    } catch {
      throw new AuthError('AUTH_UNAVAILABLE', 503);
    }
  }
  private async audit(
    event: string,
    identityId: string | null,
    session: ClientSession | undefined = undefined,
  ) {
    await (
      await this.repo.collection('security_events')
    ).insertOne(
      { event, identityId, audience: this.settings.audience, createdAt: new Date(this.now()) },
      session ? { session } : {},
    );
  }
  private async limit(kind: string, value: string, max: number) {
    const window = this.settings.values.AUTH_LIMIT_WINDOW_SECONDS * 1000;
    const bucket = Math.floor(this.now() / window);
    const id = `${this.settings.audience}:${kind}:${this.hash(kind, value)}:${bucket}`;
    const limits = await this.repo.collection<Document & { _id: string }>('auth_limits');
    const result = await limits.findOneAndUpdate(
      { _id: id },
      { $inc: { count: 1 }, $setOnInsert: { expiresAt: new Date((bucket + 2) * window) } },
      { upsert: true, returnDocument: 'after' },
    );
    if (!result || result.count > max)
      throw new AuthError(
        'RATE_LIMITED',
        429,
        Math.ceil(((bucket + 1) * window - this.now()) / 1000),
      );
  }
  async requestOtp(phone: string, purpose: string, meta: RequestMeta) {
    await this.ready();
    if (this.settings.role === 'ADMIN' || purpose !== `${this.settings.role}_LOGIN`)
      throw new AuthError('FORBIDDEN', 403);
    phone = phoneSchema.parse(phone);
    await this.limit('ip', meta.ip, this.settings.values.AUTH_IP_LIMIT);
    await this.limit('phone', phone, this.settings.values.AUTH_PHONE_LIMIT);
    const cooldown = await this.repo.collection<Document & { _id: string }>('auth_limits');
    const cooldownId = `${this.settings.audience}:cooldown:${this.hash('phone', phone)}`;
    try {
      await cooldown.findOneAndUpdate(
        { _id: cooldownId, nextAllowedAt: { $lte: new Date(this.now()) } },
        {
          $set: {
            nextAllowedAt: new Date(this.now() + this.settings.values.AUTH_RESEND_SECONDS * 1000),
            expiresAt: new Date(this.now() + 86400000),
          },
        },
        { upsert: true },
      );
    } catch (error: unknown) {
      if (typeof error === 'object' && error !== null && 'code' in error && error.code === 11000)
        throw new AuthError('RATE_LIMITED', 429, this.settings.values.AUTH_RESEND_SECONDS);
      throw error;
    }
    const id = randomUUID(),
      token = randomBytes(32).toString('base64url'),
      code = this.generateOtp();
    if (!/^\d{6}$/.test(code)) throw new Error('Invalid mock challenge generator');
    const expiresAt = new Date(this.now() + this.settings.values.AUTH_OTP_TTL_SECONDS * 1000);
    await (
      await this.repo.collection<Challenge>('otp_challenges')
    ).insertOne({
      _id: id,
      phoneDigest: this.hash('phone', phone),
      phoneSealed: seal(this.settings.encryptionKey, phone),
      tokenDigest: this.hash('challenge', token),
      codeDigest: this.hash(`otp:${id}`, code),
      audience: this.settings.audience,
      purpose,
      expiresAt,
      attempts: 0,
      consumedAt: null,
      createdAt: new Date(this.now()),
      ipDigest: this.hash('ip', meta.ip),
    });
    await this.sms.send(id, code, expiresAt);
    await this.audit('OTP_REQUESTED', null);
    return {
      challengeId: id,
      challengeToken: token,
      resendAfterSeconds: this.settings.values.AUTH_RESEND_SECONDS,
      expiresInSeconds: this.settings.values.AUTH_OTP_TTL_SECONDS,
      maskedPhone: maskPhone(phone),
    };
  }
  private async newSession(
    identityId: string,
    role: Role,
    mfa: boolean,
    meta: RequestMeta,
    transaction: ClientSession,
  ) {
    const id = randomUUID(),
      secret = randomBytes(32).toString('base64url');
    const refreshToken = `${id}.${secret}`;
    const csrf = this.hash('csrf', id);
    const document: Session = {
      _id: id,
      identityId,
      role,
      audience: this.settings.audience,
      familyId: randomUUID(),
      refreshDigest: this.hash('refresh', refreshToken),
      usedRefreshDigests: [],
      rotation: 0,
      expiresAt: new Date(this.now() + this.settings.values.AUTH_REFRESH_TTL_SECONDS * 1000),
      revokedAt: null,
      mfa,
      csrfDigest: this.hash('csrf-token', csrf),
      deviceDigest: this.hash('device', meta.device),
      createdAt: new Date(this.now()),
      updatedAt: new Date(this.now()),
    };
    await (
      await this.repo.collection<Session>('sessions')
    ).insertOne(document, { session: transaction });
    return { document, refreshToken };
  }
  private async output(session: Session, refreshToken: string) {
    const identity = await (
      await this.repo.collection<Identity>('identities')
    ).findOne({ _id: session.identityId, status: 'ACTIVE' });
    if (!identity) throw new AuthError('INVALID_SESSION', 401);
    const accessToken = jwt.sign(
      {
        sub: identity._id,
        sid: session._id,
        role: session.role,
        mfa: session.mfa,
        iat: Math.floor(this.now() / 1000),
      },
      this.settings.privateKey,
      {
        algorithm: 'RS256',
        issuer: this.settings.issuer,
        audience: this.settings.audience,
        keyid: this.settings.keyId,
        expiresIn: this.settings.values.AUTH_ACCESS_TTL_SECONDS,
      },
    );
    return {
      accessToken,
      refreshToken,
      expiresInSeconds: this.settings.values.AUTH_ACCESS_TTL_SECONDS,
      user: this.user(identity, session.role),
      csrfToken: this.hash('csrf', session._id),
    };
  }
  private user(identity: Identity, role: Role) {
    return {
      id: identity._id,
      role,
      maskedPhone: maskPhone(identity.phone),
      onboardingStatus:
        role === 'WORKER' ? ('PENDING_ONBOARDING' as const) : ('NOT_APPLICABLE' as const),
    };
  }
  async verifyOtp(id: string, token: string, code: string, meta: RequestMeta) {
    await this.ready();
    if (this.settings.role === 'ADMIN') throw new AuthError('FORBIDDEN', 403);
    const challenges = await this.repo.collection<Challenge>('otp_challenges');
    const challenge = await challenges.findOneAndUpdate(
      {
        _id: id,
        audience: this.settings.audience,
        purpose: `${this.settings.role}_LOGIN`,
        tokenDigest: this.hash('challenge', token),
        consumedAt: null,
        expiresAt: { $gt: new Date(this.now()) },
        attempts: { $lt: this.settings.values.AUTH_OTP_MAX_ATTEMPTS },
      },
      { $inc: { attempts: 1 } },
      { returnDocument: 'after' },
    );
    if (!challenge || !same(challenge.codeDigest, this.hash(`otp:${id}`, code))) {
      await this.audit('OTP_REJECTED', null);
      throw new AuthError('INVALID_CHALLENGE', 401);
    }
    const result = await this.repo.transaction(async (transaction) => {
      const consumed = await challenges.updateOne(
        { _id: id, consumedAt: null, expiresAt: { $gt: new Date(this.now()) } },
        { $set: { consumedAt: new Date(this.now()) } },
        { session: transaction },
      );
      if (consumed.modifiedCount !== 1) throw new AuthError('INVALID_CHALLENGE', 401);
      const phone = unseal(this.settings.encryptionKey, challenge.phoneSealed);
      const identities = await this.repo.collection<Identity>('identities');
      const identity = await identities.findOneAndUpdate(
        { phone },
        {
          $setOnInsert: {
            _id: randomUUID(),
            phone,
            status: 'ACTIVE',
            createdAt: new Date(this.now()),
          },
          $set: { verifiedAt: new Date(this.now()), updatedAt: new Date(this.now()) },
        },
        { upsert: true, returnDocument: 'after', session: transaction },
      );
      if (!identity || identity.status !== 'ACTIVE')
        throw new AuthError('INVALID_CREDENTIALS', 401);
      const memberships = await this.repo.collection<Membership>('role_memberships');
      const membership = await memberships.findOneAndUpdate(
        { identityId: identity._id, role: this.settings.role },
        {
          $setOnInsert: {
            _id: randomUUID(),
            identityId: identity._id,
            role: this.settings.role,
            status: 'ACTIVE',
            createdAt: new Date(this.now()),
          },
        },
        { upsert: true, returnDocument: 'after', session: transaction },
      );
      if (!membership || membership.status !== 'ACTIVE') throw new AuthError('FORBIDDEN', 403);
      const created = await this.newSession(
        identity._id,
        this.settings.role,
        false,
        meta,
        transaction,
      );
      await this.audit('SIGNED_IN', identity._id, transaction);
      return created;
    });
    return this.output(result.document, result.refreshToken);
  }
  async authenticate(token: string) {
    await this.ready();
    let claims;
    try {
      const decoded = jwt.decode(token, { complete: true });
      if (decoded?.header.kid !== this.settings.keyId) throw new Error('Wrong key');
      claims = claimsSchema.parse(
        jwt.verify(token, this.settings.publicKey, {
          algorithms: ['RS256'],
          issuer: this.settings.issuer,
          audience: this.settings.audience,
          clockTimestamp: Math.floor(this.now() / 1000),
        }),
      );
    } catch {
      throw new AuthError('INVALID_SESSION', 401);
    }
    if (!this.roleAllowed(claims.role)) throw new AuthError('FORBIDDEN', 403);
    const session = await (
      await this.repo.collection<Session>('sessions')
    ).findOne({
      _id: claims.sid,
      identityId: claims.sub,
      role: claims.role,
      audience: this.settings.audience,
      revokedAt: null,
      expiresAt: { $gt: new Date(this.now()) },
    });
    const identity = await (
      await this.repo.collection<Identity>('identities')
    ).findOne({ _id: claims.sub, status: 'ACTIVE' });
    const membership = await (
      await this.repo.collection<Membership>('role_memberships')
    ).findOne({ identityId: claims.sub, role: claims.role, status: 'ACTIVE' });
    if (!session || !identity || !membership) throw new AuthError('INVALID_SESSION', 401);
    if (this.settings.role === 'ADMIN' && (!claims.mfa || !session.mfa))
      throw new AuthError('MFA_REQUIRED', 401);
    return {
      session,
      user: this.user(identity, claims.role),
      csrfToken: this.hash('csrf', session._id),
    };
  }
  async refresh(refreshToken: string, csrfToken?: string) {
    await this.ready();
    const id = refreshToken.split('.')[0];
    if (!id || !/^[a-f0-9-]{36}$/.test(id) || refreshToken.length > 150)
      throw new AuthError('INVALID_SESSION', 401);
    const sessions = await this.repo.collection<Session>('sessions');
    const previous = await sessions.findOne({
      _id: id,
      audience: this.settings.audience,
      revokedAt: null,
      expiresAt: { $gt: new Date(this.now()) },
    });
    if (!previous || !this.roleAllowed(previous.role)) throw new AuthError('INVALID_SESSION', 401);
    if (this.settings.role === 'ADMIN') this.csrf(previous, csrfToken ?? '');
    const hash = this.hash('refresh', refreshToken);
    const membership = await (
      await this.repo.collection<Membership>('role_memberships')
    ).findOne({ identityId: previous.identityId, role: previous.role, status: 'ACTIVE' });
    const identity = await (
      await this.repo.collection<Identity>('identities')
    ).findOne({ _id: previous.identityId, status: 'ACTIVE' });
    if (!membership || !identity || (this.settings.role === 'ADMIN' && !previous.mfa))
      throw new AuthError('INVALID_SESSION', 401);
    const rotatedToken = `${id}.${randomBytes(32).toString('base64url')}`;
    const rotated = await sessions.findOneAndUpdate(
      {
        _id: id,
        refreshDigest: hash,
        audience: this.settings.audience,
        revokedAt: null,
        expiresAt: { $gt: new Date(this.now()) },
        rotation: { $lt: 4096 },
      },
      {
        $set: {
          refreshDigest: this.hash('refresh', rotatedToken),
          updatedAt: new Date(this.now()),
        },
        $inc: { rotation: 1 },
        $push: { usedRefreshDigests: hash },
      },
      { returnDocument: 'after' },
    );
    if (!rotated) {
      const current = await sessions.findOne({ _id: id, audience: this.settings.audience });
      if (current?.usedRefreshDigests.includes(hash)) {
        await sessions.updateMany(
          { familyId: current.familyId, audience: this.settings.audience },
          { $set: { revokedAt: new Date(this.now()) } },
        );
        await this.audit('REFRESH_REUSE_REVOKED', current.identityId);
      }
      throw new AuthError('INVALID_SESSION', 401);
    }
    await this.audit('SESSION_REFRESHED', rotated.identityId);
    return this.output(rotated, rotatedToken);
  }
  csrf(session: Session, supplied: string) {
    if (!same(session.csrfDigest, this.hash('csrf-token', supplied)))
      throw new AuthError('FORBIDDEN', 403);
  }
  async logout(token: string, all = false, csrfToken?: string) {
    const auth = await this.authenticate(token);
    if (this.settings.role === 'ADMIN') this.csrf(auth.session, csrfToken ?? '');
    await (
      await this.repo.collection<Session>('sessions')
    ).updateMany(
      all
        ? {
            identityId: auth.session.identityId,
            audience: this.settings.audience,
            role: auth.session.role,
          }
        : { _id: auth.session._id, audience: this.settings.audience },
      { $set: { revokedAt: new Date(this.now()) } },
    );
    await this.audit(
      all ? 'ALL_ROLE_SESSIONS_REVOKED' : 'SESSION_REVOKED',
      auth.session.identityId,
    );
  }
  async adminLogin(phone: string, password: string, meta: RequestMeta) {
    await this.ready();
    if (this.settings.role !== 'ADMIN') throw new AuthError('FORBIDDEN', 403);
    await this.limit('admin-ip', meta.ip, this.settings.values.AUTH_ADMIN_LOGIN_LIMIT);
    await this.limit('admin-phone', phone, this.settings.values.AUTH_ADMIN_LOGIN_LIMIT);
    const identity = await (
      await this.repo.collection<Identity>('identities')
    ).findOne({ phone, status: 'ACTIVE' });
    const credential = identity
      ? await (
          await this.repo.collection<AdminCredential>('admin_credentials')
        ).findOne({ identityId: identity._id })
      : null;
    const membership = identity
      ? await (
          await this.repo.collection<Membership>('role_memberships')
        ).findOne({
          identityId: identity._id,
          role: { $in: ['ADMIN', 'SUPER_ADMIN'] },
          status: 'ACTIVE',
        })
      : null;
    const dummy = `${'0'.repeat(64)}:${'0'.repeat(128)}`;
    const valid = await verifyPassword(password, credential?.passwordHash ?? dummy);
    if (!identity || !credential || !membership || !valid) {
      await this.audit('ADMIN_LOGIN_REJECTED', null);
      throw new AuthError('INVALID_CREDENTIALS', 401);
    }
    const id = randomUUID(),
      token = randomBytes(32).toString('base64url');
    await (
      await this.repo.collection<MfaChallenge>('mfa_challenges')
    ).insertOne({
      _id: id,
      identityId: identity._id,
      tokenDigest: this.hash('mfa', token),
      attempts: 0,
      consumedAt: null,
      expiresAt: new Date(this.now() + 300000),
    });
    return { mfaChallengeId: id, mfaToken: token, expiresInSeconds: 300 };
  }
  async verifyMfa(id: string, token: string, code: string, meta: RequestMeta) {
    await this.ready();
    if (this.settings.role !== 'ADMIN') throw new AuthError('FORBIDDEN', 403);
    const challenges = await this.repo.collection<MfaChallenge>('mfa_challenges');
    const challenge = await challenges.findOneAndUpdate(
      {
        _id: id,
        tokenDigest: this.hash('mfa', token),
        consumedAt: null,
        expiresAt: { $gt: new Date(this.now()) },
        attempts: { $lt: 5 },
      },
      { $inc: { attempts: 1 } },
      { returnDocument: 'after' },
    );
    if (!challenge) throw new AuthError('INVALID_CHALLENGE', 401);
    const credentials = await this.repo.collection<AdminCredential>('admin_credentials');
    const credential = await credentials.findOne({ identityId: challenge.identityId });
    const counter = credential
      ? matchTotp(unseal(this.settings.encryptionKey, credential.totpSealed), code, this.now())
      : null;
    if (!credential || counter === null) {
      await this.audit('MFA_REJECTED', challenge.identityId);
      throw new AuthError('INVALID_CHALLENGE', 401);
    }
    const result = await this.repo.transaction(async (transaction) => {
      const accepted = await credentials.updateOne(
        { _id: credential._id, lastCounter: { $lt: counter } },
        { $set: { lastCounter: counter } },
        { session: transaction },
      );
      const consumed = await challenges.updateOne(
        { _id: id, consumedAt: null, expiresAt: { $gt: new Date(this.now()) } },
        { $set: { consumedAt: new Date(this.now()) } },
        { session: transaction },
      );
      if (!accepted.modifiedCount || !consumed.modifiedCount)
        throw new AuthError('INVALID_CHALLENGE', 401);
      const identity = await (
        await this.repo.collection<Identity>('identities')
      ).findOne({ _id: credential.identityId, status: 'ACTIVE' }, { session: transaction });
      const member = await (
        await this.repo.collection<Membership>('role_memberships')
      ).findOne(
        {
          identityId: credential.identityId,
          role: { $in: ['ADMIN', 'SUPER_ADMIN'] },
          status: 'ACTIVE',
        },
        { session: transaction },
      );
      if (!identity || !member) throw new AuthError('FORBIDDEN', 403);
      const created = await this.newSession(identity._id, member.role, true, meta, transaction);
      await this.audit('ADMIN_MFA_SIGNED_IN', identity._id, transaction);
      return created;
    });
    return this.output(result.document, result.refreshToken);
  }
  async provisionAdmin(phone: string, password: string, role: 'ADMIN' | 'SUPER_ADMIN' = 'ADMIN') {
    await this.ready();
    if (
      this.settings.role !== 'ADMIN' ||
      this.settings.env.NODE_ENV !== 'development' ||
      password.length < 16 ||
      password.length > 128
    )
      throw new AuthError('FORBIDDEN', 403);
    phone = phoneSchema.parse(phone);
    const passwordHash = await hashPassword(password),
      seed = randomBytes(20).toString('hex');
    await this.repo.transaction(async (transaction) => {
      const identities = await this.repo.collection<Identity>('identities');
      const identity = await identities.findOneAndUpdate(
        { phone },
        {
          $setOnInsert: {
            _id: randomUUID(),
            phone,
            status: 'ACTIVE',
            verifiedAt: new Date(this.now()),
            createdAt: new Date(this.now()),
            updatedAt: new Date(this.now()),
          },
        },
        { upsert: true, returnDocument: 'after', session: transaction },
      );
      if (!identity || identity.status !== 'ACTIVE') throw new AuthError('FORBIDDEN', 403);
      await (
        await this.repo.collection<AdminCredential>('admin_credentials')
      ).insertOne(
        {
          _id: randomUUID(),
          identityId: identity._id,
          passwordHash,
          totpSealed: seal(this.settings.encryptionKey, seed),
          lastCounter: -1,
          createdAt: new Date(this.now()),
        },
        { session: transaction },
      );
      await (
        await this.repo.collection<Membership>('role_memberships')
      ).insertOne(
        {
          _id: randomUUID(),
          identityId: identity._id,
          role,
          status: 'ACTIVE',
          createdAt: new Date(this.now()),
        },
        { session: transaction },
      );
      await this.audit('ADMIN_PROVISIONED', identity._id, transaction);
    });
    return seed;
  }
}

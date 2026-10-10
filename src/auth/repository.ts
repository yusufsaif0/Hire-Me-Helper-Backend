import { MongoClient, type Db, type Collection, type ClientSession, type Document } from 'mongodb';
import { AuthSettings, type Role } from './settings';
export interface Identity {
  _id: string;
  phone: string;
  status: 'ACTIVE' | 'DISABLED';
  verifiedAt: Date;
  createdAt: Date;
  updatedAt: Date;
}
export interface Membership {
  _id: string;
  identityId: string;
  role: Role;
  status: 'ACTIVE' | 'DISABLED';
  createdAt: Date;
}
export interface Challenge {
  _id: string;
  phoneDigest: string;
  phoneSealed: string;
  tokenDigest: string;
  codeDigest: string;
  purpose: string;
  audience: string;
  expiresAt: Date;
  attempts: number;
  consumedAt: Date | null;
  createdAt: Date;
  ipDigest: string;
}
export interface Session {
  _id: string;
  identityId: string;
  role: Role;
  audience: string;
  familyId: string;
  refreshDigest: string;
  usedRefreshDigests: string[];
  rotation: number;
  expiresAt: Date;
  revokedAt: Date | null;
  mfa: boolean;
  csrfDigest: string;
  deviceDigest: string;
  createdAt: Date;
  updatedAt: Date;
}
export interface AdminCredential {
  _id: string;
  identityId: string;
  passwordHash: string;
  totpSealed: string;
  lastCounter: number;
  createdAt: Date;
}
export interface MfaChallenge {
  _id: string;
  identityId: string;
  tokenDigest: string;
  attempts: number;
  consumedAt: Date | null;
  expiresAt: Date;
}
export class AuthRepository {
  readonly client: MongoClient;
  private connected: Promise<Db> | null = null;
  constructor(readonly settings: AuthSettings) {
    this.client = new MongoClient(settings.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 5000,
      maxPoolSize: 10,
    });
  }
  async ready(): Promise<Db> {
    if (!this.settings.enabled) throw new Error('Authentication is disabled');
    if (!this.connected)
      this.connected = this.client
        .connect()
        .then(async () => {
          const db = this.client.db(this.settings.env.MONGODB_DB_NAME);
          const migration = await db.collection('schema_migrations').findOne({ version: '0001' });
          if (!migration) throw new Error('Identity migration required');
          return db;
        })
        .catch((error: unknown) => {
          this.connected = null;
          throw error;
        });
    return this.connected;
  }
  async collection<T extends Document>(name: string): Promise<Collection<T>> {
    return (await this.ready()).collection<T>(name);
  }
  async transaction<T>(fn: (session: ClientSession) => Promise<T>): Promise<T> {
    await this.ready();
    for (let attempt = 0; ; attempt++) {
      const session = this.client.startSession();
      try {
        return await session.withTransaction(() => fn(session), {
          readConcern: { level: 'snapshot' },
          writeConcern: { w: 'majority' },
          maxCommitTimeMS: 10000,
        });
      } catch (error: unknown) {
        if (
          attempt >= 3 ||
          typeof error !== 'object' ||
          error === null ||
          !('code' in error) ||
          error.code !== 11000
        )
          throw error;
      } finally {
        await session.endSession();
      }
    }
  }
  async onModuleDestroy() {
    await this.client.close();
  }
}

async function migrate(client, dbName) {
  const db = client.db(dbName);
  const hello = await db.admin().command({ hello: 1 });
  if (!hello.setName && hello.msg !== 'isdbgrid')
    throw new Error('Authentication requires a replica set or sharded deployment');
  const indexes = {
    identities: [[{ phone: 1 }, { unique: true, name: 'unique_phone' }]],
    role_memberships: [
      [
        { identityId: 1, role: 1 },
        { unique: true, name: 'unique_identity_role' },
      ],
    ],
    otp_challenges: [
      [{ expiresAt: 1 }, { expireAfterSeconds: 0, name: 'challenge_expiry' }],
      [{ audience: 1, phoneDigest: 1 }, { name: 'challenge_owner' }],
    ],
    sessions: [
      [{ expiresAt: 1 }, { expireAfterSeconds: 0, name: 'session_expiry' }],
      [{ identityId: 1, audience: 1 }, { name: 'session_owner' }],
      [{ familyId: 1, audience: 1 }, { name: 'session_family' }],
    ],
    auth_limits: [[{ expiresAt: 1 }, { expireAfterSeconds: 0, name: 'limit_expiry' }]],
    admin_credentials: [[{ identityId: 1 }, { unique: true, name: 'unique_admin_identity' }]],
    mfa_challenges: [[{ expiresAt: 1 }, { expireAfterSeconds: 0, name: 'mfa_expiry' }]],
    security_events: [
      [{ createdAt: 1 }, { expireAfterSeconds: 7776000, name: 'security_event_retention' }],
    ],
    schema_migrations: [[{ version: 1 }, { unique: true, name: 'unique_migration' }]],
  };
  await db
    .collection('schema_migrations')
    .createIndex({ version: 1 }, { unique: true, name: 'unique_migration' });
  for (const [name, specs] of Object.entries(indexes))
    for (const [keys, options] of specs) await db.collection(name).createIndex(keys, options);
  await db
    .collection('schema_migrations')
    .updateOne(
      { version: '0001' },
      { $setOnInsert: { version: '0001', appliedAt: new Date(), owner: 'admin-panel/backend' } },
      { upsert: true },
    );
}
module.exports = { migrate };

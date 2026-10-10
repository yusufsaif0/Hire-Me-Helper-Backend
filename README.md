# Worker app backend

Independent NestJS API, Node 22.13+. Run commands inside this module.

```powershell
npm.cmd ci --ignore-scripts
npm.cmd run dev
```

Use ci for a fresh installation; dependencies already exist on this machine.
Health: http://127.0.0.1:4002/v1/health; Swagger: http://127.0.0.1:4002/docs.

Configured private .env uses Atlas database hire_me. MONGODB_URL overrides legacy
MONGODB_URI; MONGODB_DB_NAME selects the database. Never copy credentials into frontend
variables, source or documents. AUTH_ENABLED defaults false in examples. The admin
auth:setup command generates/preserves private keys in all three backend environment files.
Only admin-panel/backend owns schema migrations; this API never creates indexes at startup.

```powershell
npm.cmd run check
npm.cmd run format:check
npm.cmd run test:integration
npm.cmd run openapi
```

Integration checks require local Compose MongoDB on port 27018 (or TEST_MONGODB_URL).
They use uniquely named disposable databases and refuse remote/Atlas test URLs.
Read a development mock SMS using npm.cmd run auth:mock-otp -- CHALLENGE_ID in a private interactive terminal. No real SMS is sent.

See [runbook](docs/project/PHASE_1_RUNBOOK.md), [API contracts](docs/project/IDENTITY_API.md),
[ownership ADR](docs/project/adr/0004-identity-ownership.md) and [acceptance](docs/project/ACCEPTANCE.md).
No sibling runtime imports. Local CI applies when this module is the GitHub repository root.

## Current Phase 2

Read [Phase 2 handover](docs/project/PHASE_2_HANDOVER.md), [domain specification](docs/project/PHASE_2_SPEC.md) and [API guide](docs/project/PHASE_2_API.md). Worker identity/pending onboarding is unchanged, with no recipient routes or features.

## GitHub setup

See [repository mapping and clone instructions](docs/project/GITHUB_REPOSITORIES.md). Private environment files are local only; use .env.example when setting up a new clone.

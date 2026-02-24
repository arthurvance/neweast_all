#!/usr/bin/env node
const { randomUUID } = require('node:crypto');
const { setTimeout: sleep } = require('node:timers/promises');
const { connectMySql } = require('../src/infrastructure/mysql-client');
const { createMySqlAuthStore } = require('../src/modules/auth/auth.store.mysql');

const asNumber = (value, fallback) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return parsed;
};

const parseArgs = (argv) => {
  const values = {
    durationSec: asNumber(process.env.STRESS_DURATION_SEC, 20),
    syncWorkers: asNumber(process.env.STRESS_SYNC_WORKERS, 24),
    writeWorkers: asNumber(process.env.STRESS_WRITE_WORKERS, 4),
    writerSleepMs: asNumber(process.env.STRESS_WRITER_SLEEP_MS, 3),
    syncSleepMs: asNumber(process.env.STRESS_SYNC_SLEEP_MS, 1),
    userId: String(process.env.STRESS_USER_ID || 'stress-user-platform'),
    rolePoolSize: asNumber(process.env.STRESS_ROLE_POOL_SIZE, 6),
    dbHost: process.env.DB_HOST || '127.0.0.1',
    dbPort: asNumber(process.env.DB_PORT, 3306),
    dbUser: process.env.DB_USER || 'neweast',
    dbPassword: process.env.DB_PASSWORD || 'neweast',
    dbName: process.env.DB_NAME || 'neweast'
  };

  for (const arg of argv) {
    if (!arg.startsWith('--')) {
      continue;
    }
    const [rawKey, rawValue] = arg.slice(2).split('=');
    const key = String(rawKey || '').trim();
    const value = String(rawValue || '').trim();
    if (!key || !value) {
      continue;
    }
    if (key === 'duration-sec') values.durationSec = asNumber(value, values.durationSec);
    if (key === 'sync-workers') values.syncWorkers = asNumber(value, values.syncWorkers);
    if (key === 'write-workers') values.writeWorkers = asNumber(value, values.writeWorkers);
    if (key === 'writer-sleep-ms') values.writerSleepMs = asNumber(value, values.writerSleepMs);
    if (key === 'sync-sleep-ms') values.syncSleepMs = asNumber(value, values.syncSleepMs);
    if (key === 'user-id') values.userId = value;
    if (key === 'role-pool-size') values.rolePoolSize = asNumber(value, values.rolePoolSize);
    if (key === 'db-host') values.dbHost = value;
    if (key === 'db-port') values.dbPort = asNumber(value, values.dbPort);
    if (key === 'db-user') values.dbUser = value;
    if (key === 'db-password') values.dbPassword = value;
    if (key === 'db-name') values.dbName = value;
  }

  values.durationSec = Math.max(1, values.durationSec);
  values.syncWorkers = Math.max(1, values.syncWorkers);
  values.writeWorkers = Math.max(1, values.writeWorkers);
  values.writerSleepMs = Math.max(0, values.writerSleepMs);
  values.syncSleepMs = Math.max(0, values.syncSleepMs);
  values.rolePoolSize = Math.max(1, values.rolePoolSize);
  return values;
};

const createRoleTemplates = (size) => {
  const templates = [];
  for (let i = 0; i < size; i += 1) {
    templates.push({
      role_id: `stress-role-${i + 1}`,
      status: i % 5 === 0 ? 'disabled' : 'active',
      can_view_user_management: i % 2 === 0 ? 1 : 0,
      can_operate_user_management: i % 3 === 0 ? 1 : 0,
      can_view_organization_management: i % 2 === 1 ? 1 : 0,
      can_operate_organization_management: i % 4 === 0 ? 1 : 0
    });
  }
  return templates;
};

const pickRoles = (templates) => {
  const selected = [];
  for (const role of templates) {
    if (Math.random() < 0.45) {
      selected.push(role);
    }
  }
  if (Math.random() < 0.2) {
    return [];
  }
  if (selected.length === 0) {
    return [templates[Math.floor(Math.random() * templates.length)]];
  }
  return selected;
};

const aggregateExpectedPermission = (roles) => {
  let canViewUserManagement = 0;
  let canOperateUserManagement = 0;
  let canViewOrganizationManagement = 0;
  let canOperateOrganizationManagement = 0;

  for (const role of roles) {
    if (!role || !['active', 'enabled'].includes(String(role.status || '').toLowerCase())) {
      continue;
    }
    canViewUserManagement = canViewUserManagement || Number(role.can_view_user_management ? 1 : 0);
    canOperateUserManagement = canOperateUserManagement || Number(role.can_operate_user_management ? 1 : 0);
    canViewOrganizationManagement = canViewOrganizationManagement || Number(role.can_view_organization_management ? 1 : 0);
    canOperateOrganizationManagement = canOperateOrganizationManagement || Number(role.can_operate_organization_management ? 1 : 0);
  }

  return {
    can_view_user_management: canViewUserManagement,
    can_operate_user_management: canOperateUserManagement,
    can_view_organization_management: canViewOrganizationManagement,
    can_operate_organization_management: canOperateOrganizationManagement
  };
};

const createDbClient = ({ dbHost, dbPort, dbUser, dbPassword, dbName }) =>
  connectMySql({
    host: dbHost,
    port: dbPort,
    user: dbUser,
    password: dbPassword,
    database: dbName,
    connectTimeoutMs: 3000
  });

const isDeadlockError = (error) =>
  String(error?.code || '').toUpperCase() === 'ER_LOCK_DEADLOCK'
  || Number(error?.errno || 0) === 1213;

const executeWithDeadlockRetry = async ({ work, maxRetries = 3, retryDelayMs = 1, onRetry }) => {
  let attempt = 0;
  while (attempt <= maxRetries) {
    try {
      return await work();
    } catch (error) {
      if (!isDeadlockError(error) || attempt === maxRetries) {
        throw error;
      }
      if (typeof onRetry === 'function') {
        onRetry(error);
      }
      attempt += 1;
      if (retryDelayMs > 0) {
        await sleep(retryDelayMs);
      }
    }
  }
  return null;
};

const resetTargetUserData = async ({ dbClient, userId }) => {
  await dbClient.query(
    `
      INSERT INTO auth_user_domain_access (
        user_id,
        domain,
        status,
        can_view_user_management,
        can_operate_user_management,
        can_view_organization_management,
        can_operate_organization_management
      )
      VALUES (?, 'platform', 'active', 0, 0, 0, 0)
      ON DUPLICATE KEY UPDATE
        status = 'active',
        can_view_user_management = 0,
        can_operate_user_management = 0,
        can_view_organization_management = 0,
        can_operate_organization_management = 0,
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [userId]
  );
  await dbClient.query('DELETE FROM auth_user_platform_roles WHERE user_id = ?', [userId]);
};

const writeRoleFacts = async ({ dbClient, userId, roles }) => {
  await dbClient.inTransaction(async (tx) => {
    await tx.query('DELETE FROM auth_user_platform_roles WHERE user_id = ?', [userId]);
    for (const role of roles) {
      await tx.query(
        `
          INSERT INTO auth_user_platform_roles (
            user_id,
            role_id,
            status,
            can_view_user_management,
            can_operate_user_management,
            can_view_organization_management,
            can_operate_organization_management
          )
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `,
        [
          userId,
          role.role_id,
          role.status,
          Number(role.can_view_user_management ? 1 : 0),
          Number(role.can_operate_user_management ? 1 : 0),
          Number(role.can_view_organization_management ? 1 : 0),
          Number(role.can_operate_organization_management ? 1 : 0)
        ]
      );
    }
  });
};

const readCurrentSnapshot = async ({ dbClient, userId }) => {
  const rows = await dbClient.query(
    `
      SELECT can_view_user_management,
             can_operate_user_management,
             can_view_organization_management,
             can_operate_organization_management
      FROM auth_user_domain_access
      WHERE user_id = ? AND domain = 'platform' AND status IN ('active', 'enabled')
      LIMIT 1
    `,
    [userId]
  );
  const row = rows?.[0] || {};
  return {
    can_view_user_management: Number(row.can_view_user_management ? 1 : 0),
    can_operate_user_management: Number(row.can_operate_user_management ? 1 : 0),
    can_view_organization_management: Number(row.can_view_organization_management ? 1 : 0),
    can_operate_organization_management: Number(row.can_operate_organization_management ? 1 : 0)
  };
};

const run = async () => {
  const config = parseArgs(process.argv.slice(2));
  const scenarioId = `stress-${randomUUID()}`;
  const startedAt = Date.now();
  const stopAt = startedAt + config.durationSec * 1000;
  const roleTemplates = createRoleTemplates(config.rolePoolSize);
  const counters = {
    writerUpdates: 0,
    syncCalls: 0,
    syncErrors: 0,
    writerErrors: 0,
    reasons: {},
    syncErrorCodes: {},
    writerErrorCodes: {},
    syncDeadlockRetries: 0,
    writerDeadlockRetries: 0
  };
  let lastWriterRoleSet = [];

  const seedClient = await createDbClient(config);
  try {
    await resetTargetUserData({
      dbClient: seedClient,
      userId: config.userId
    });
  } finally {
    await seedClient.close();
  }

  const workerClients = [];
  const workerStores = [];
  const writerClients = [];

  for (let i = 0; i < config.syncWorkers; i += 1) {
    const client = await createDbClient(config);
    workerClients.push(client);
    workerStores.push(createMySqlAuthStore({ dbClient: client }));
  }
  for (let i = 0; i < config.writeWorkers; i += 1) {
    const client = await createDbClient(config);
    writerClients.push(client);
  }

  const writerTasks = writerClients.map((client) =>
    (async () => {
      while (Date.now() < stopAt) {
        const roles = pickRoles(roleTemplates);
        try {
          await executeWithDeadlockRetry({
            work: () =>
              writeRoleFacts({
                dbClient: client,
                userId: config.userId,
                roles
              }),
            maxRetries: 4,
            retryDelayMs: 1,
            onRetry: () => {
              counters.writerDeadlockRetries += 1;
            }
          });
          counters.writerUpdates += 1;
          lastWriterRoleSet = roles;
        } catch (_error) {
          counters.writerErrors += 1;
          const errorCode = String(_error?.code || _error?.errno || 'UNKNOWN');
          counters.writerErrorCodes[errorCode] = Number(counters.writerErrorCodes[errorCode] || 0) + 1;
        }
        if (config.writerSleepMs > 0) {
          await sleep(config.writerSleepMs);
        }
      }
    })()
  );

  const syncTasks = workerStores.map((store) =>
    (async () => {
      while (Date.now() < stopAt) {
        try {
          const result = await executeWithDeadlockRetry({
            work: () =>
              store.syncPlatformPermissionSnapshotByUserId({
                userId: config.userId,
                forceWhenNoRoleFacts: true
              }),
            maxRetries: 3,
            retryDelayMs: 1,
            onRetry: () => {
              counters.syncDeadlockRetries += 1;
            }
          });
          counters.syncCalls += 1;
          const reason = String(result?.reason || 'unknown');
          counters.reasons[reason] = Number(counters.reasons[reason] || 0) + 1;
        } catch (_error) {
          counters.syncErrors += 1;
          const errorCode = String(_error?.code || _error?.errno || 'UNKNOWN');
          counters.syncErrorCodes[errorCode] = Number(counters.syncErrorCodes[errorCode] || 0) + 1;
        }
        if (config.syncSleepMs > 0) {
          await sleep(config.syncSleepMs);
        }
      }
    })()
  );

  await Promise.all([...writerTasks, ...syncTasks]);

  // Quiesce with deterministic final state and validate snapshot consistency.
  const finalClient = await createDbClient(config);
  const finalStore = createMySqlAuthStore({ dbClient: finalClient });
  try {
    await writeRoleFacts({
      dbClient: finalClient,
      userId: config.userId,
      roles: lastWriterRoleSet
    });
    await finalStore.syncPlatformPermissionSnapshotByUserId({
      userId: config.userId,
      forceWhenNoRoleFacts: true
    });
    const expected = aggregateExpectedPermission(lastWriterRoleSet);
    const actual = await readCurrentSnapshot({
      dbClient: finalClient,
      userId: config.userId
    });
    const consistent =
      expected.can_view_user_management === actual.can_view_user_management
      && expected.can_operate_user_management === actual.can_operate_user_management
      && expected.can_view_organization_management === actual.can_view_organization_management
      && expected.can_operate_organization_management === actual.can_operate_organization_management;

    const durationMs = Date.now() - startedAt;
    const result = {
      scenario_id: scenarioId,
      duration_ms: durationMs,
      user_id: config.userId,
      db: {
        host: config.dbHost,
        port: config.dbPort,
        name: config.dbName
      },
      workers: {
        sync: config.syncWorkers,
        write: config.writeWorkers
      },
      totals: {
        writer_updates: counters.writerUpdates,
        writer_errors: counters.writerErrors,
        writer_deadlock_retries: counters.writerDeadlockRetries,
        sync_calls: counters.syncCalls,
        sync_errors: counters.syncErrors,
        sync_deadlock_retries: counters.syncDeadlockRetries,
        sync_tps: Number((counters.syncCalls / Math.max(durationMs / 1000, 0.001)).toFixed(2))
      },
      sync_reason_distribution: counters.reasons,
      sync_error_codes: counters.syncErrorCodes,
      writer_error_codes: counters.writerErrorCodes,
      consistency_check: {
        consistent,
        expected,
        actual
      }
    };

    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (!consistent || counters.syncErrors > 0 || counters.writerErrors > 0) {
      process.exitCode = 1;
    }
  } finally {
    await finalClient.close();
  }

  await Promise.all(workerClients.map((client) => client.close()));
  await Promise.all(writerClients.map((client) => client.close()));
};

run().catch((error) => {
  process.stderr.write(`${error?.stack || error?.message || String(error)}\n`);
  process.exit(1);
});

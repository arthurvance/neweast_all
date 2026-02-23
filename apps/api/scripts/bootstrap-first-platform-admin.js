#!/usr/bin/env node
const { randomBytes, pbkdf2Sync, randomUUID } = require('node:crypto');
const { existsSync, readFileSync } = require('node:fs');
const { readConfig } = require('../src/config/env');
const { connectMySql } = require('../src/infrastructure/mysql-client');
const { log } = require('../src/common/logger');

const PASSWORD_MIN_LENGTH = 6;
const PBKDF2_ITERATIONS = 150000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';
const PLATFORM_ADMIN_OPERATE_PERMISSION = 'platform.member_admin.operate';
const SYS_ADMIN_ROLE_ID = 'sys_admin';

const normalizeNonEmptyText = (value) => {
  if (value === undefined || value === null) {
    return '';
  }
  return String(value).trim();
};

const normalizePhone = (value) => {
  const normalized = normalizeNonEmptyText(value);
  if (!/^1\d{10}$/.test(normalized)) {
    return '';
  }
  return normalized;
};

const assertPassword = (value) => {
  if (typeof value !== 'string' || value.length < PASSWORD_MIN_LENGTH) {
    throw new Error(`password must be at least ${PASSWORD_MIN_LENGTH} characters`);
  }
  return value;
};

const hashPassword = (plainTextPassword) => {
  const salt = randomBytes(16).toString('hex');
  const derived = pbkdf2Sync(
    plainTextPassword,
    salt,
    PBKDF2_ITERATIONS,
    PBKDF2_KEYLEN,
    PBKDF2_DIGEST
  ).toString('hex');
  return `pbkdf2$${PBKDF2_DIGEST}$${PBKDF2_ITERATIONS}$${salt}$${derived}`;
};

const parseArgs = (argv = []) => {
  const args = Array.isArray(argv) ? argv : [];
  const parsed = {
    phone: '',
    password: '',
    force: false,
    help: false
  };
  for (const arg of args) {
    const token = String(arg || '').trim();
    if (!token) {
      continue;
    }
    if (token === '--help' || token === '-h') {
      parsed.help = true;
      continue;
    }
    if (token === '--force') {
      parsed.force = true;
      continue;
    }
    if (token.startsWith('--phone=')) {
      parsed.phone = token.slice('--phone='.length);
      continue;
    }
    if (token.startsWith('--password=')) {
      parsed.password = token.slice('--password='.length);
      continue;
    }
  }
  return parsed;
};

const printHelp = () => {
  process.stdout.write(
    [
      'Usage:',
      '  node apps/api/scripts/bootstrap-first-platform-admin.js --phone=13800000000 --password=Passw0rd! [--force]',
      '',
      'Options:',
      '  --phone=...     Required. Mainland China mobile phone number (11 digits, starts with 1).',
      '  --password=...  Required. Initial password for the admin account.',
      '  --force         Optional. Allow execution even when platform admins already exist.',
      '  --help, -h      Show this help.',
      '',
      'Environment fallback:',
      '  BOOTSTRAP_ADMIN_PHONE',
      '  BOOTSTRAP_ADMIN_PASSWORD',
      '  BOOTSTRAP_ADMIN_FORCE=true'
    ].join('\n') + '\n'
  );
};

const toBool = (value) => {
  const normalized = normalizeNonEmptyText(value).toLowerCase();
  return normalized === 'true' || normalized === '1' || normalized === 'yes';
};

const isContainerRuntime = () => {
  if (existsSync('/.dockerenv')) {
    return true;
  }
  try {
    const cgroup = readFileSync('/proc/1/cgroup', 'utf8');
    return /docker|containerd|kubepods|podman/i.test(cgroup);
  } catch (_error) {
    return false;
  }
};

const resolveBootstrapDbHost = (configuredHost) => {
  const normalizedHost = normalizeNonEmptyText(configuredHost).toLowerCase();
  if (!normalizedHost) {
    return '127.0.0.1';
  }

  const containerAliasHosts = new Set(['mysql', 'mariadb', 'db']);
  if (!isContainerRuntime() && containerAliasHosts.has(normalizedHost)) {
    return '127.0.0.1';
  }

  return configuredHost;
};

const loadSysAdminPermissionFlags = async (queryClient) => {
  const roleRows = await queryClient.query(
    `
      SELECT role_id, status, scope
      FROM platform_role_catalog
      WHERE role_id = ?
      LIMIT 1
    `,
    [SYS_ADMIN_ROLE_ID]
  );
  const roleRow = roleRows?.[0] || null;
  const roleStatus = normalizeNonEmptyText(roleRow?.status).toLowerCase();
  const roleScope = normalizeNonEmptyText(roleRow?.scope).toLowerCase();
  if (!roleRow || roleScope !== 'platform' || (roleStatus !== 'active' && roleStatus !== 'enabled')) {
    throw new Error(
      `required role ${SYS_ADMIN_ROLE_ID} is missing or inactive; run DB migrations first`
    );
  }

  const grantRows = await queryClient.query(
    `
      SELECT permission_code
      FROM platform_role_permission_grants
      WHERE role_id = ?
    `,
    [SYS_ADMIN_ROLE_ID]
  );
  const permissionCodes = new Set(
    (Array.isArray(grantRows) ? grantRows : [])
      .map((row) => normalizeNonEmptyText(row?.permission_code).toLowerCase())
      .filter((code) => code.length > 0)
  );
  const canOperateMemberAdmin = permissionCodes.has('platform.member_admin.operate');
  const canViewMemberAdmin =
    canOperateMemberAdmin || permissionCodes.has('platform.member_admin.view');
  const canOperateBilling = permissionCodes.has('platform.billing.operate');
  const canViewBilling =
    canOperateBilling || permissionCodes.has('platform.billing.view');

  if (!canOperateMemberAdmin) {
    throw new Error(
      `${SYS_ADMIN_ROLE_ID} lacks ${PLATFORM_ADMIN_OPERATE_PERMISSION}; run DB migrations first`
    );
  }

  return {
    canViewMemberAdmin,
    canOperateMemberAdmin,
    canViewBilling,
    canOperateBilling
  };
};

const countExistingPlatformAdmins = async (queryClient) => {
  const rows = await queryClient.query(
    `
      SELECT COUNT(DISTINCT upr.user_id) AS admin_count
      FROM auth_user_platform_roles upr
      INNER JOIN platform_role_catalog prc
        ON prc.role_id = upr.role_id
       AND prc.scope = 'platform'
       AND prc.status IN ('active', 'enabled')
      INNER JOIN platform_role_permission_grants prg
        ON prg.role_id = upr.role_id
       AND prg.permission_code = ?
      INNER JOIN auth_user_domain_access uda
        ON uda.user_id = upr.user_id
       AND uda.domain = 'platform'
       AND uda.status IN ('active', 'enabled')
      INNER JOIN users u
        ON u.id = upr.user_id
       AND u.status IN ('active', 'enabled')
      WHERE upr.status IN ('active', 'enabled')
    `,
    [PLATFORM_ADMIN_OPERATE_PERMISSION]
  );
  const count = Number(rows?.[0]?.admin_count || 0);
  return Number.isFinite(count) && count > 0 ? Math.floor(count) : 0;
};

const upsertPlatformAdminRole = async (tx, { userId, permissionFlags }) => {
  await tx.query(
    `
      INSERT INTO auth_user_platform_roles (
        user_id,
        role_id,
        status,
        can_view_member_admin,
        can_operate_member_admin,
        can_view_billing,
        can_operate_billing
      )
      VALUES (?, ?, 'active', ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        status = 'active',
        can_view_member_admin = VALUES(can_view_member_admin),
        can_operate_member_admin = VALUES(can_operate_member_admin),
        can_view_billing = VALUES(can_view_billing),
        can_operate_billing = VALUES(can_operate_billing),
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [
      userId,
      SYS_ADMIN_ROLE_ID,
      Number(permissionFlags.canViewMemberAdmin),
      Number(permissionFlags.canOperateMemberAdmin),
      Number(permissionFlags.canViewBilling),
      Number(permissionFlags.canOperateBilling)
    ]
  );
};

const upsertPlatformDomainAccess = async (tx, { userId, permissionFlags }) => {
  await tx.query(
    `
      INSERT INTO auth_user_domain_access (
        user_id,
        domain,
        status,
        can_view_member_admin,
        can_operate_member_admin,
        can_view_billing,
        can_operate_billing
      )
      VALUES (?, 'platform', 'active', ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        status = 'active',
        can_view_member_admin = VALUES(can_view_member_admin),
        can_operate_member_admin = VALUES(can_operate_member_admin),
        can_view_billing = VALUES(can_view_billing),
        can_operate_billing = VALUES(can_operate_billing),
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [
      userId,
      Number(permissionFlags.canViewMemberAdmin),
      Number(permissionFlags.canOperateMemberAdmin),
      Number(permissionFlags.canViewBilling),
      Number(permissionFlags.canOperateBilling)
    ]
  );
};

const revokeUserSessions = async (tx, { userId }) => {
  await tx.query(
    `
      UPDATE auth_sessions
      SET status = 'revoked',
          revoked_reason = 'bootstrap-first-admin-password-reset',
          updated_at = CURRENT_TIMESTAMP(3)
      WHERE user_id = ?
        AND status = 'active'
    `,
    [userId]
  );
  await tx.query(
    `
      UPDATE refresh_tokens
      SET status = 'revoked',
          updated_at = CURRENT_TIMESTAMP(3)
      WHERE user_id = ?
        AND status = 'active'
    `,
    [userId]
  );
};

const run = async () => {
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed.help) {
    printHelp();
    return;
  }

  const resolvedPhone = normalizePhone(
    parsed.phone || process.env.BOOTSTRAP_ADMIN_PHONE
  );
  const resolvedPassword = parsed.password || process.env.BOOTSTRAP_ADMIN_PASSWORD || '';
  const force = parsed.force || toBool(process.env.BOOTSTRAP_ADMIN_FORCE);

  if (!resolvedPhone) {
    throw new Error('valid --phone is required (example: 13800000000)');
  }
  assertPassword(resolvedPassword);

  const config = readConfig();
  const resolvedDbHost = resolveBootstrapDbHost(config.DB_HOST);
  if (resolvedDbHost !== config.DB_HOST) {
    log('info', 'Bootstrap first platform admin remapped DB host for local execution', {
      request_id: `bootstrap-first-admin-${randomUUID()}`,
      configured_db_host: config.DB_HOST,
      resolved_db_host: resolvedDbHost
    });
  }
  const dbClient = await connectMySql({
    host: resolvedDbHost,
    port: config.DB_PORT,
    user: config.DB_USER,
    password: config.DB_PASSWORD,
    database: config.DB_NAME,
    connectTimeoutMs: config.DB_CONNECT_TIMEOUT_MS
  });

  try {
    const existingAdminCount = await countExistingPlatformAdmins(dbClient);
    if (existingAdminCount > 0 && !force) {
      throw new Error(
        `bootstrap blocked: ${existingAdminCount} platform admin(s) already exist. Use --force for emergency takeover`
      );
    }

    const permissionFlags = await loadSysAdminPermissionFlags(dbClient);
    const passwordHash = hashPassword(resolvedPassword);
    const result = await dbClient.inTransaction(async (tx) => {
      const existingRows = await tx.query(
        `
          SELECT id, status, session_version
          FROM users
          WHERE phone = ?
          LIMIT 1
          FOR UPDATE
        `,
        [resolvedPhone]
      );
      const existingUser = existingRows?.[0] || null;
      let userId = normalizeNonEmptyText(existingUser?.id);
      let createdUser = false;

      if (!userId) {
        userId = randomUUID();
        await tx.query(
          `
            INSERT INTO users (id, phone, password_hash, status, session_version)
            VALUES (?, ?, ?, 'active', 1)
          `,
          [userId, resolvedPhone, passwordHash]
        );
        createdUser = true;
      } else {
        await tx.query(
          `
            UPDATE users
            SET password_hash = ?,
                status = 'active',
                session_version = session_version + 1,
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE id = ?
          `,
          [passwordHash, userId]
        );
        await revokeUserSessions(tx, { userId });
      }

      await upsertPlatformAdminRole(tx, { userId, permissionFlags });
      await upsertPlatformDomainAccess(tx, { userId, permissionFlags });

      return {
        userId,
        createdUser
      };
    });

    log('info', 'Bootstrap first platform admin succeeded', {
      request_id: `bootstrap-first-admin-${randomUUID()}`,
      phone: resolvedPhone,
      user_id: result.userId,
      created_user: result.createdUser,
      force_mode: force
    });
  } finally {
    await dbClient.close();
  }
};

run().catch((error) => {
  log('error', 'Bootstrap first platform admin failed', {
    request_id: `bootstrap-first-admin-${randomUUID()}`,
    detail: String(error?.message || error || '')
  });
  process.exitCode = 1;
});

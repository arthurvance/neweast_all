const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createCipheriv, createHash, pbkdf2Sync, randomBytes } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const mysql = require('mysql2/promise');
const { createApiApp } = require('../src/app');
const { readConfig } = require('../src/config/env');
const { ROUTE_DEFINITIONS } = require('../src/route-permissions');

const MYSQL_HOST = process.env.AUTH_TEST_MYSQL_HOST || process.env.DB_HOST || '127.0.0.1';
const MYSQL_PORT = Number(process.env.AUTH_TEST_MYSQL_PORT || process.env.DB_PORT || 3306);
const MYSQL_USER = process.env.AUTH_TEST_MYSQL_USER || process.env.DB_USER || 'neweast';
const MYSQL_PASSWORD = process.env.AUTH_TEST_MYSQL_PASSWORD || process.env.DB_PASSWORD || 'neweast';
const MYSQL_DATABASE = process.env.AUTH_TEST_MYSQL_DATABASE || process.env.DB_NAME || 'neweast';

const config = readConfig({
  ALLOW_MOCK_BACKENDS: 'true',
  DB_HOST: MYSQL_HOST,
  DB_PORT: String(MYSQL_PORT),
  DB_USER: MYSQL_USER,
  DB_PASSWORD: MYSQL_PASSWORD,
  DB_NAME: MYSQL_DATABASE
});

const dependencyProbe = async () => ({
  db: { ok: true, detail: 'db ok' },
  redis: { ok: true, detail: 'redis ok' }
});
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TRACEPARENT_PATTERN =
  /^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/i;

const decodeJwtPayload = (token) => {
  const parts = String(token || '').split('.');
  if (parts.length < 2) {
    return {};
  }
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
};

const refreshTokenHash = (token) => {
  const payload = decodeJwtPayload(token);
  return createHash('sha256')
    .update(String(payload.jti || ''))
    .digest('hex');
};

const TEST_USER = {
  id: 'it-user-active',
  phone: '13910000000',
  password: 'Passw0rd!',
  status: 'active'
};
const PLATFORM_USER_MANAGEMENT_VIEW_PERMISSION_CODE = 'platform.user_management.view';
const PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE = 'platform.user_management.operate';
const PLATFORM_TENANT_MANAGEMENT_VIEW_PERMISSION_CODE = 'platform.tenant_management.view';
const PLATFORM_TENANT_MANAGEMENT_OPERATE_PERMISSION_CODE = 'platform.tenant_management.operate';
const AUTH_SESSIONS_REQUIRED_COLUMNS = [
  'session_id',
  'user_id',
  'session_version',
  'entry_domain',
  'active_tenant_id',
  'status',
  'revoked_reason',
  'updated_at'
];
const AUTH_SESSIONS_REQUIRED_COLUMN_ROWS = AUTH_SESSIONS_REQUIRED_COLUMNS.map((columnName) => ({
  column_name: columnName
}));
const AUTH_SESSIONS_REQUIRED_COLUMN_ROWS_UPPER = AUTH_SESSIONS_REQUIRED_COLUMNS.map((columnName) => ({
  COLUMN_NAME: columnName
}));
const AUTH_SESSIONS_REQUIRED_COLUMN_ROWS_WITHOUT_ACTIVE_TENANT = AUTH_SESSIONS_REQUIRED_COLUMNS
  .filter((columnName) => columnName !== 'active_tenant_id')
  .map((columnName) => ({ column_name: columnName }));
const AUTH_USER_TENANTS_REQUIRED_COLUMNS = [
  'user_id',
  'tenant_id',
  'membership_id',
  'tenant_name',
  'status',
  'display_name',
  'department_name',
  'joined_at',
  'left_at',
  'can_view_user_management',
  'can_operate_user_management',
  'can_view_role_management',
  'can_operate_role_management'
];
const AUTH_USER_TENANTS_REQUIRED_COLUMN_ROWS = AUTH_USER_TENANTS_REQUIRED_COLUMNS.map(
  (columnName) => ({
    column_name: columnName
  })
);
const AUTH_USER_TENANTS_REQUIRED_COLUMN_ROWS_UPPER = AUTH_USER_TENANTS_REQUIRED_COLUMNS.map(
  (columnName) => ({
    COLUMN_NAME: columnName
  })
);
const PLATFORM_USER_PROFILES_REQUIRED_COLUMNS = [
  'user_id',
  'name',
  'department',
  'status',
  'created_at',
  'updated_at'
];
const PLATFORM_USER_PROFILES_REQUIRED_COLUMN_ROWS = PLATFORM_USER_PROFILES_REQUIRED_COLUMNS.map(
  (columnName) => ({
    column_name: columnName
  })
);
const PLATFORM_USER_PROFILES_REQUIRED_COLUMN_ROWS_UPPER = PLATFORM_USER_PROFILES_REQUIRED_COLUMNS.map(
  (columnName) => ({
    COLUMN_NAME: columnName
  })
);
const AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMNS = [
  'user_id',
  'role_id',
  'status',
  'can_view_user_management',
  'can_operate_user_management',
  'can_view_tenant_management',
  'can_operate_tenant_management',
  'updated_at'
];
const AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS =
  AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMNS.map((columnName) => ({
    column_name: columnName
  }));
const AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS_UPPER =
  AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMNS.map((columnName) => ({
    COLUMN_NAME: columnName
  }));
const PLATFORM_ROLE_PERMISSION_GRANTS_REQUIRED_COLUMNS = [
  'role_id',
  'permission_code',
  'created_by_user_id',
  'updated_by_user_id',
  'created_at',
  'updated_at'
];
const PLATFORM_ROLE_PERMISSION_GRANTS_REQUIRED_COLUMN_ROWS =
  PLATFORM_ROLE_PERMISSION_GRANTS_REQUIRED_COLUMNS.map((columnName) => ({
    column_name: columnName
  }));
const PLATFORM_ROLE_PERMISSION_GRANTS_REQUIRED_COLUMN_ROWS_UPPER =
  PLATFORM_ROLE_PERMISSION_GRANTS_REQUIRED_COLUMNS.map((columnName) => ({
    COLUMN_NAME: columnName
  }));
const ROUTE_DEFINITIONS_WITH_MISSING_PERMISSION = [
  {
    method: 'GET',
    path: '/health',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'GET',
    path: '/auth/missing-permission',
    access: 'protected',
    permission_code: '',
    scope: 'tenant'
  }
];
const ROUTE_DEFINITIONS_WITH_UNKNOWN_PERMISSION_CODE = [
  {
    method: 'GET',
    path: '/health',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'GET',
    path: '/auth/tenant/user-management/probe',
    access: 'protected',
    permission_code: 'tenant.user_management.operat',
    scope: 'tenant'
  }
];
const ROUTE_DEFINITIONS_WITH_DUPLICATE_ROUTE_KEY = [
  {
    method: 'GET',
    path: '/health',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'GET',
    path: '/health',
    access: 'protected',
    permission_code: 'auth.session.logout',
    scope: 'session'
  }
];
const ROUTE_DEFINITIONS_WITH_INCOMPATIBLE_PERMISSION_SCOPE = [
  {
    method: 'GET',
    path: '/health',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'GET',
    path: '/auth/tenant/user-management/probe',
    access: 'protected',
    permission_code: 'tenant.user_management.operate',
    scope: 'session'
  }
];

const PBKDF2_ITERATIONS = 150000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';

let adminConnection = null;
let mysqlReady = false;
let mysqlSkipReason = 'MySQL test backend unavailable';

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
const deriveSensitiveConfigKey = (decryptionKey) => {
  const normalizedRawKey = String(decryptionKey || '').trim();
  if (!normalizedRawKey) {
    return Buffer.alloc(0);
  }
  if (/^[0-9a-f]{64}$/i.test(normalizedRawKey)) {
    return Buffer.from(normalizedRawKey, 'hex');
  }
  return pbkdf2Sync(normalizedRawKey, 'auth.default_password', 210000, 32, 'sha256');
};
const buildEncryptedSensitiveConfigValue = ({
  plainText,
  decryptionKey
}) => {
  const key = deriveSensitiveConfigKey(decryptionKey);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const cipherText = Buffer.concat([
    cipher.update(String(plainText || ''), 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  return `enc:v1:${iv.toString('base64url')}:${authTag.toString('base64url')}:${cipherText.toString('base64url')}`;
};

const executeSqlStatements = async (connection, sqlContent) => {
  const statements = String(sqlContent || '')
    .split(';')
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);

  for (const statement of statements) {
    await connection.query(statement);
  }
};

const runMigrationSql = async (connection, migrationFile) => {
  const migrationPath = resolve(__dirname, '..', 'migrations', migrationFile);
  const sqlContent = readFileSync(migrationPath, 'utf8');
  await executeSqlStatements(connection, sqlContent);
};

const ensureTables = async () => {
  await adminConnection.execute(
    `
      CREATE TABLE IF NOT EXISTS iam_users (
        id VARCHAR(64) NOT NULL,
        phone VARCHAR(32) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'active',
        session_version INT UNSIGNED NOT NULL DEFAULT 1,
        created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        PRIMARY KEY (id),
        UNIQUE KEY uk_iam_users_phone (phone)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `
  );

  await adminConnection.execute(
    `
      CREATE TABLE IF NOT EXISTS auth_sessions (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        session_id CHAR(36) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        session_version INT UNSIGNED NOT NULL DEFAULT 1,
        entry_domain VARCHAR(16) NOT NULL DEFAULT 'platform',
        active_tenant_id VARCHAR(64) NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'active',
        revoked_reason VARCHAR(128) NULL,
        created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        PRIMARY KEY (id),
        UNIQUE KEY uk_auth_sessions_session_id (session_id),
        KEY idx_auth_sessions_user_id (user_id),
        KEY idx_auth_sessions_status (status)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `
  );

  const [authSessionColumns] = await adminConnection.execute(
    `
      SELECT COLUMN_NAME AS column_name
      FROM information_schema.columns
      WHERE table_schema = DATABASE()
        AND table_name = 'auth_sessions'
        AND column_name IN ('entry_domain', 'active_tenant_id')
    `
  );
  const existingAuthSessionColumns = new Set(
    authSessionColumns.map((row) => row.column_name)
  );
  if (!existingAuthSessionColumns.has('entry_domain')) {
    await adminConnection.execute(
      "ALTER TABLE auth_sessions ADD COLUMN entry_domain VARCHAR(16) NOT NULL DEFAULT 'platform'"
    );
  }
  if (!existingAuthSessionColumns.has('active_tenant_id')) {
    await adminConnection.execute(
      'ALTER TABLE auth_sessions ADD COLUMN active_tenant_id VARCHAR(64) NULL'
    );
  }

  await adminConnection.execute(
    `
      CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        token_hash CHAR(64) NOT NULL,
        session_id CHAR(36) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'active',
        rotated_from_token_hash CHAR(64) NULL,
        rotated_to_token_hash CHAR(64) NULL,
        expires_at TIMESTAMP(3) NOT NULL,
        created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        PRIMARY KEY (id),
        UNIQUE KEY uk_refresh_tokens_token_hash (token_hash),
        KEY idx_refresh_tokens_session_id (session_id),
        KEY idx_refresh_tokens_user_id (user_id),
        KEY idx_refresh_tokens_status (status)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `
  );

  await adminConnection.execute(
    `
      CREATE TABLE IF NOT EXISTS tenant_memberships (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id VARCHAR(64) NOT NULL,
        tenant_id VARCHAR(64) NOT NULL,
        tenant_name VARCHAR(128) NULL,
        can_view_user_management TINYINT(1) NOT NULL DEFAULT 0,
        can_operate_user_management TINYINT(1) NOT NULL DEFAULT 0,
        can_view_role_management TINYINT(1) NOT NULL DEFAULT 0,
        can_operate_role_management TINYINT(1) NOT NULL DEFAULT 0,
        status VARCHAR(16) NOT NULL DEFAULT 'active',
        created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        PRIMARY KEY (id),
        UNIQUE KEY uk_auth_user_tenants_user_tenant (user_id, tenant_id),
        KEY idx_auth_user_tenants_user_status (user_id, status)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `
  );

  const [tenantPermissionColumns] = await adminConnection.execute(
    `
      SELECT COLUMN_NAME AS column_name
      FROM information_schema.columns
      WHERE table_schema = DATABASE()
        AND table_name = 'tenant_memberships'
        AND column_name IN (
          'can_view_user_management',
          'can_operate_user_management',
          'can_view_role_management',
          'can_operate_role_management'
        )
    `
  );

  const existingColumns = new Set(tenantPermissionColumns.map((row) => row.column_name));
  const missingColumnDefinitions = [
    ['can_view_user_management', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['can_operate_user_management', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['can_view_role_management', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['can_operate_role_management', 'TINYINT(1) NOT NULL DEFAULT 0']
  ].filter(([columnName]) => !existingColumns.has(columnName));

  for (const [columnName, columnDefinition] of missingColumnDefinitions) {
    await adminConnection.execute(
      `ALTER TABLE tenant_memberships ADD COLUMN ${columnName} ${columnDefinition}`
    );
  }

  await adminConnection.execute(
    `
      CREATE TABLE IF NOT EXISTS platform_user_roles (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id VARCHAR(64) NOT NULL,
        role_id VARCHAR(64) NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'active',
        can_view_user_management TINYINT(1) NOT NULL DEFAULT 0,
        can_operate_user_management TINYINT(1) NOT NULL DEFAULT 0,
        can_view_tenant_management TINYINT(1) NOT NULL DEFAULT 0,
        can_operate_tenant_management TINYINT(1) NOT NULL DEFAULT 0,
        created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        PRIMARY KEY (id),
        UNIQUE KEY uk_auth_user_platform_roles_user_role (user_id, role_id),
        KEY idx_auth_user_platform_roles_user_status (user_id, status),
        KEY idx_auth_user_platform_roles_role_id_user_id (role_id, user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `
  );

  await adminConnection.execute(
    `
      CREATE TABLE IF NOT EXISTS platform_role_permission_grants (
        role_id VARCHAR(64) NOT NULL,
        permission_code VARCHAR(128) NOT NULL,
        created_by_user_id VARCHAR(64) NULL,
        updated_by_user_id VARCHAR(64) NULL,
        created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        PRIMARY KEY (role_id, permission_code),
        KEY idx_platform_role_permission_grants_permission_code (permission_code)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `
  );

  await runMigrationSql(adminConnection, '0009_platform_role_catalog.sql');
  await runMigrationSql(adminConnection, '0010_platform_role_permission_grants.sql');
  await runMigrationSql(adminConnection, '0012_tenant_member_lifecycle.sql');
  await runMigrationSql(adminConnection, '0013_platform_role_catalog_tenant_isolation.sql');
  await runMigrationSql(adminConnection, '0014_tenant_role_permission_grants.sql');
  await runMigrationSql(adminConnection, '0015_auth_tenant_membership_roles.sql');
  await runMigrationSql(adminConnection, '0016_auth_tenant_member_profile_fields.sql');
  await runMigrationSql(adminConnection, '0018_audit_events.sql');
  await runMigrationSql(adminConnection, '0019_system_sensitive_configs.sql');
  await runMigrationSql(adminConnection, '0025_platform_user.sql');

  const [platformUserStatusColumns] = await adminConnection.execute(
    `
      SELECT COLUMN_NAME AS column_name
      FROM information_schema.columns
      WHERE table_schema = DATABASE()
        AND table_name = 'platform_users'
        AND column_name = 'status'
    `
  );
  if (!platformUserStatusColumns.length) {
    await adminConnection.execute(
      "ALTER TABLE platform_users ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'active'"
    );
  }

  const [platformUserNameColumnRows] = await adminConnection.execute(
    `
      SELECT IS_NULLABLE AS is_nullable
      FROM information_schema.columns
      WHERE table_schema = DATABASE()
        AND table_name = 'platform_users'
        AND column_name = 'name'
      LIMIT 1
    `
  );
  if (String(platformUserNameColumnRows?.[0]?.is_nullable || '').toUpperCase() !== 'YES') {
    await adminConnection.execute('ALTER TABLE platform_users MODIFY COLUMN name VARCHAR(64) NULL');
  }
};

const resetTestData = async () => {
  await adminConnection.execute(
    `
      DELETE prg
      FROM platform_role_permission_grants prg
      INNER JOIN platform_user_roles pur
        ON pur.role_id = prg.role_id
      WHERE pur.user_id = ?
    `,
    [TEST_USER.id]
  );
  await adminConnection.execute('DELETE FROM platform_user_roles WHERE user_id = ?', [
    TEST_USER.id
  ]);
  await adminConnection.execute(
    `
      DELETE FROM platform_role_permission_grants
      WHERE created_by_user_id = ? OR updated_by_user_id = ?
    `,
    [TEST_USER.id, TEST_USER.id]
  );
  await adminConnection.execute(
    `
      DELETE FROM platform_roles
      WHERE is_system = 0
        AND (created_by_user_id = ? OR updated_by_user_id = ?)
    `,
    [TEST_USER.id, TEST_USER.id]
  );
  await adminConnection.execute('DELETE FROM tenant_memberships WHERE user_id = ?', [TEST_USER.id]);
  await adminConnection.execute('DELETE FROM platform_users WHERE user_id = ?', [TEST_USER.id]);
  await adminConnection.execute('DELETE FROM auth_refresh_tokens WHERE user_id = ?', [TEST_USER.id]);
  await adminConnection.execute('DELETE FROM auth_sessions WHERE user_id = ?', [TEST_USER.id]);
  if (await doesTableExist('tenants')) {
    await adminConnection.execute(
      `
        DELETE FROM tenants
        WHERE owner_user_id = ? OR created_by_user_id = ?
      `,
      [TEST_USER.id, TEST_USER.id]
    );
  }
  if (await doesTableExist('system_sensitive_configs')) {
    await adminConnection.execute('DELETE FROM system_sensitive_configs');
  }
  await adminConnection.execute('DELETE FROM iam_users WHERE id = ? OR phone = ?', [
    TEST_USER.id,
    TEST_USER.phone
  ]);
};

const seedTestUser = async () => {
  await adminConnection.execute(
    `
      INSERT INTO iam_users (id, phone, password_hash, status, session_version)
      VALUES (?, ?, ?, ?, 1)
    `,
    [TEST_USER.id, TEST_USER.phone, hashPassword(TEST_USER.password), TEST_USER.status]
  );

  await adminConnection.execute(
    `
      INSERT INTO platform_users (user_id, name, department, status)
      VALUES (?, 'Integration User', NULL, 'active')
      ON DUPLICATE KEY UPDATE
        name = VALUES(name),
        status = VALUES(status),
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [TEST_USER.id]
  );
};

const seedTenantDomainAccess = async () => {
  // Tenant access is derived from active tenant_memberships.
};

const doesTableExist = async (tableName) => {
  const [rows] = await adminConnection.execute(
    `
      SELECT 1 AS table_exists
      FROM information_schema.tables
      WHERE table_schema = DATABASE()
        AND table_name = ?
      LIMIT 1
    `,
    [String(tableName || '').trim()]
  );
  return Array.isArray(rows) && rows.length > 0;
};

const ensureActiveOrgsForTenantIds = async (tenantIds = []) => {
  const normalizedTenantIds = [...new Set(
    (Array.isArray(tenantIds) ? tenantIds : [])
      .map((tenantId) => String(tenantId || '').trim())
      .filter((tenantId) => tenantId.length > 0)
  )];
  if (normalizedTenantIds.length === 0) {
    return;
  }
  if (!(await doesTableExist('tenants'))) {
    return;
  }

  for (const tenantId of normalizedTenantIds) {
    await adminConnection.execute(
      `
        INSERT INTO tenants (
          id,
          name,
          owner_user_id,
          status,
          created_by_user_id
        )
        VALUES (?, ?, ?, 'active', ?)
        ON DUPLICATE KEY UPDATE
          name = VALUES(name),
          owner_user_id = VALUES(owner_user_id),
          status = VALUES(status),
          created_by_user_id = VALUES(created_by_user_id),
          updated_at = CURRENT_TIMESTAMP(3)
      `,
      [tenantId, `Org ${tenantId}`, TEST_USER.id, TEST_USER.id]
    );
  }
};

const seedTenantOptions = async () => {
  await ensureActiveOrgsForTenantIds(['tenant-a', 'tenant-b']);
  await adminConnection.execute(
    `
      INSERT INTO tenant_memberships (
        membership_id,
        user_id,
        tenant_id,
        tenant_name,
        status,
        can_view_user_management,
        can_operate_user_management,
        can_view_role_management,
        can_operate_role_management
      )
      VALUES
        (?, ?, 'tenant-a', 'Tenant A', 'active', 1, 1, 1, 0),
        (?, ?, 'tenant-b', 'Tenant B', 'active', 0, 0, 1, 1)
      ON DUPLICATE KEY UPDATE
        tenant_name = VALUES(tenant_name),
        status = VALUES(status),
        can_view_user_management = VALUES(can_view_user_management),
        can_operate_user_management = VALUES(can_operate_user_management),
        can_view_role_management = VALUES(can_view_role_management),
        can_operate_role_management = VALUES(can_operate_role_management),
        updated_at = CURRENT_TIMESTAMP(3)
      `,
    [
      'membership-seed-tenant-a',
      TEST_USER.id,
      'membership-seed-tenant-b',
      TEST_USER.id
    ]
  );
};

const seedPlatformRoleFacts = async ({
  roleId = 'platform-role-default',
  status = 'active',
  canViewUserManagement = 0,
  canOperateUserManagement = 0,
  canViewTenantManagement = 0,
  canOperateTenantManagement = 0
} = {}) => {
  const normalizedRoleId = String(roleId || '').trim() || 'platform-role-default';
  const normalizedRoleStatus = (() => {
    const normalized = String(status || '').trim().toLowerCase();
    if (normalized === 'disabled') {
      return 'disabled';
    }
    return 'active';
  })();
  const normalizedCode = normalizedRoleId.toLowerCase();
  const permissionCodes = [];
  if (Number(canViewUserManagement) === 1) {
    permissionCodes.push(PLATFORM_USER_MANAGEMENT_VIEW_PERMISSION_CODE);
  }
  if (Number(canOperateUserManagement) === 1) {
    permissionCodes.push(PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE);
  }
  if (Number(canViewTenantManagement) === 1) {
    permissionCodes.push(PLATFORM_TENANT_MANAGEMENT_VIEW_PERMISSION_CODE);
  }
  if (Number(canOperateTenantManagement) === 1) {
    permissionCodes.push(PLATFORM_TENANT_MANAGEMENT_OPERATE_PERMISSION_CODE);
  }

  await adminConnection.execute(
    `
      INSERT INTO platform_roles (
        role_id,
        code,
        code_normalized,
        name,
        status,
        scope,
        tenant_id,
        is_system,
        created_by_user_id,
        updated_by_user_id
      )
      VALUES (?, ?, ?, ?, ?, 'platform', '', 0, ?, ?)
      ON DUPLICATE KEY UPDATE
        code = VALUES(code),
        code_normalized = VALUES(code_normalized),
        name = VALUES(name),
        status = VALUES(status),
        scope = VALUES(scope),
        tenant_id = VALUES(tenant_id),
        updated_by_user_id = VALUES(updated_by_user_id),
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [
      normalizedRoleId,
      normalizedRoleId,
      normalizedCode,
      `Role ${normalizedRoleId}`,
      normalizedRoleStatus,
      null,
      null
    ]
  );

  await adminConnection.execute(
    `
      DELETE FROM platform_role_permission_grants
      WHERE role_id = ?
    `,
    [normalizedRoleId]
  );
  for (const permissionCode of permissionCodes) {
    await adminConnection.execute(
      `
        INSERT INTO platform_role_permission_grants (
          role_id,
          permission_code,
          created_by_user_id,
          updated_by_user_id
        )
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          updated_by_user_id = VALUES(updated_by_user_id),
          updated_at = CURRENT_TIMESTAMP(3)
      `,
      [normalizedRoleId, permissionCode, null, null]
    );
  }

  await adminConnection.execute(
    `
      INSERT INTO platform_user_roles (
        user_id,
        role_id,
        status,
        can_view_user_management,
        can_operate_user_management,
        can_view_tenant_management,
        can_operate_tenant_management
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        status = VALUES(status),
        can_view_user_management = VALUES(can_view_user_management),
        can_operate_user_management = VALUES(can_operate_user_management),
        can_view_tenant_management = VALUES(can_view_tenant_management),
        can_operate_tenant_management = VALUES(can_operate_tenant_management),
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [
      TEST_USER.id,
      normalizedRoleId,
      normalizedRoleStatus,
      Number(canViewUserManagement),
      Number(canOperateUserManagement),
      Number(canViewTenantManagement),
      Number(canOperateTenantManagement)
    ]
  );
};

const clearPlatformRoleFacts = async () => {
  await adminConnection.execute(
    `
      DELETE FROM platform_user_roles
      WHERE user_id = ?
    `,
    [TEST_USER.id]
  );
};

const seedSystemDefaultPasswordConfig = async ({
  encryptedValue,
  updatedByUserId = TEST_USER.id,
  createdByUserId = TEST_USER.id,
  version = 1,
  status = 'active'
} = {}) => {
  const normalizedEncryptedValue = String(encryptedValue || '').trim();
  if (!normalizedEncryptedValue || !(await doesTableExist('system_sensitive_configs'))) {
    return;
  }
  await adminConnection.execute(
    `
      INSERT INTO system_sensitive_configs (
        \`key\`,
        \`value\`,
        remark,
        version,
        status,
        updated_by_user_id,
        created_by_user_id
      )
      VALUES ('auth.default_password', ?, '测试默认密码密文', ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        \`value\` = VALUES(\`value\`),
        remark = VALUES(remark),
        version = VALUES(version),
        status = VALUES(status),
        updated_by_user_id = VALUES(updated_by_user_id),
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [
      normalizedEncryptedValue,
      Number(version) || 1,
      String(status || '').trim().toLowerCase() === 'disabled' ? 'disabled' : 'active',
      updatedByUserId,
      createdByUserId
    ]
  );
};

const readUserSessionVersion = async (userId = TEST_USER.id) => {
  const [rows] = await adminConnection.execute(
    `
      SELECT session_version
      FROM iam_users
      WHERE id = ?
      LIMIT 1
    `,
    [userId]
  );
  return Number(rows?.[0]?.session_version || 0);
};

const requireMySqlOrReady = () => {
  if (!mysqlReady) {
    assert.fail(
      `${mysqlSkipReason}. MySQL backend must be available for auth express integration tests.`
    );
    return false;
  }
  return true;
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const closeConnectionHard = (connection) => {
  if (!connection) {
    return;
  }
  if (typeof connection.destroy === 'function') {
    connection.destroy();
    return;
  }
  if (connection.connection && typeof connection.connection.destroy === 'function') {
    connection.connection.destroy();
  }
};

const connectWithRetry = async () => {
  const maxAttempts = 6;
  let lastError = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const connection = await mysql.createConnection({
        host: MYSQL_HOST,
        port: MYSQL_PORT,
        user: MYSQL_USER,
        password: MYSQL_PASSWORD,
        database: MYSQL_DATABASE,
        connectTimeout: 2000
      });
      await connection.ping();
      return connection;
    } catch (error) {
      lastError = error;
      if (attempt < maxAttempts) {
        const retryDelayMs = Math.min(250 * 2 ** (attempt - 1), 1500);
        await sleep(retryDelayMs);
      }
    }
  }

  throw lastError || new Error('mysql connection failed');
};

before(async () => {
  try {
    adminConnection = await connectWithRetry();
    await ensureTables();
    mysqlReady = true;
  } catch (error) {
    mysqlReady = false;
    mysqlSkipReason = `MySQL integration unavailable: ${error.message}`;
  }
});

after(async () => {
  if (!adminConnection) {
    return;
  }

  try {
    await resetTestData();
  } catch (_error) {
  }

  try {
    await Promise.race([
      adminConnection.end(),
      sleep(3000).then(() => {
        throw new Error('mysql admin connection close timeout');
      })
    ]);
  } catch (_error) {
    closeConnectionHard(adminConnection);
  }

  adminConnection = null;
});

const prepareMySqlState = async () => {
  if (!requireMySqlOrReady()) {
    return false;
  }
  await resetTestData();
  await seedTestUser();
  return true;
};

const createExpressHarness = async (effectiveConfig = config) => {
  const app = await createApiApp(effectiveConfig, {
    dependencyProbe,
    requirePersistentAuthStore: true
  });
  await app.init();
  await app.listen(0, '127.0.0.1');
  const address = app.getHttpServer().address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return {
    app,
    baseUrl: `http://127.0.0.1:${port}`,
    close: async () => {
      await app.close();
    }
  };
};

const parseResponseBody = async (response) => {
  const contentType = response.headers.get('content-type') || '';
  if (
    contentType.includes('application/json') ||
    contentType.includes('application/problem+json')
  ) {
    return response.json();
  }
  return response.text();
};

const invokeRoute = async (harness, { method = 'GET', path, body, headers = {} }) => {
  const normalizedMethod = String(method || 'GET').toUpperCase();
  const requestHeaders = {
    Accept: 'application/json, application/problem+json',
    'x-request-id': `test-${normalizedMethod}-${path}`,
    ...headers
  };

  let requestBody;
  if (body !== undefined && normalizedMethod !== 'GET' && normalizedMethod !== 'HEAD') {
    requestBody = JSON.stringify(body);
    if (!requestHeaders['content-type'] && !requestHeaders['Content-Type']) {
      requestHeaders['content-type'] = 'application/json';
    }
  }

  const response = await fetch(`${harness.baseUrl}${path}`, {
    method: normalizedMethod,
    headers: requestHeaders,
    body: requestBody
  });
  const payload = await parseResponseBody(response);

  return {
    status: response.status,
    headers: {
      'content-type': response.headers.get('content-type') || ''
    },
    body: payload
  };
};

test('express login rejects invalid payload with AUTH-400-INVALID-PAYLOAD', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  const harness = await createExpressHarness();
  try {
    const response = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: { phone: TEST_USER.phone }
    });

    assert.equal(response.status, 400);
    assert.equal(response.headers['content-type'].includes('application/problem+json'), true);
    assert.equal(response.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express refresh rejects invalid payload with AUTH-400-INVALID-PAYLOAD', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  const harness = await createExpressHarness();
  try {
    const response = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/refresh',
      body: {}
    });

    assert.equal(response.status, 400);
    assert.equal(response.headers['content-type'].includes('application/problem+json'), true);
    assert.equal(response.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express platform provision-user creates user with hashed default credential and rejects duplicate relationship requests', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-user-management-provision',
    status: 'active',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'express-provision-default-password-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const provisionConfig = readConfig({
    ALLOW_MOCK_BACKENDS: 'true',
    DB_HOST: MYSQL_HOST,
    DB_PORT: String(MYSQL_PORT),
    DB_USER: MYSQL_USER,
    DB_PASSWORD: MYSQL_PASSWORD,
    DB_NAME: MYSQL_DATABASE,
    AUTH_DEFAULT_PASSWORD_ENCRYPTED: encryptedDefaultPassword,
    AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY: decryptionKey
  });
  await seedSystemDefaultPasswordConfig({
    encryptedValue: encryptedDefaultPassword
  });

  const provisionPhone = '13910000088';
  const harness = await createExpressHarness(provisionConfig);
  try {
    const operatorLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(operatorLogin.status, 200);

    const provisioned = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/user-management/provision-user',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: provisionPhone
      }
    });
    assert.equal(provisioned.status, 200);
    assert.equal(provisioned.body.created_user, true);
    assert.equal(provisioned.body.credential_initialized, true);
    assert.equal(provisioned.body.first_login_force_password_change, false);

    const [createdRows] = await adminConnection.execute(
      `
        SELECT id, password_hash
        FROM iam_users
        WHERE phone = ?
        LIMIT 1
      `,
      [provisionPhone]
    );
    const createdRow = createdRows?.[0] || null;
    assert.ok(createdRow);
    assert.equal(String(createdRow.password_hash).startsWith('pbkdf2$'), true);
    assert.notEqual(createdRow.password_hash, defaultPassword);

    const firstLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: provisionPhone,
        password: defaultPassword,
        entry_domain: 'platform'
      }
    });
    assert.equal(firstLogin.status, 200);

    const duplicateProvision = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/user-management/provision-user',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: provisionPhone
      }
    });
    assert.equal(duplicateProvision.status, 409);
    assert.equal(duplicateProvision.body.error_code, 'AUTH-409-PROVISION-CONFLICT');
  } finally {
    await harness.close();
    const [createdRows] = await adminConnection.execute(
      `
        SELECT id
        FROM iam_users
        WHERE phone = ?
        LIMIT 1
      `,
      [provisionPhone]
    );
    const createdUserId = String(createdRows?.[0]?.id || '').trim();
    if (createdUserId) {
      await adminConnection.execute('DELETE FROM platform_user_roles WHERE user_id = ?', [createdUserId]);
      await adminConnection.execute('DELETE FROM tenant_memberships WHERE user_id = ?', [createdUserId]);
      await adminConnection.execute('DELETE FROM platform_users WHERE user_id = ?', [createdUserId]);
      await adminConnection.execute('DELETE FROM auth_refresh_tokens WHERE user_id = ?', [createdUserId]);
      await adminConnection.execute('DELETE FROM auth_sessions WHERE user_id = ?', [createdUserId]);
      await adminConnection.execute('DELETE FROM iam_users WHERE id = ?', [createdUserId]);
    }
  }
});

test('express platform provision-user rejects tenant_name payload with AUTH-400-INVALID-PAYLOAD', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-user-management-provision-tenant-name-invalid',
    status: 'active',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'express-provision-platform-tenant-name-invalid-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const provisionConfig = readConfig({
    ALLOW_MOCK_BACKENDS: 'true',
    DB_HOST: MYSQL_HOST,
    DB_PORT: String(MYSQL_PORT),
    DB_USER: MYSQL_USER,
    DB_PASSWORD: MYSQL_PASSWORD,
    DB_NAME: MYSQL_DATABASE,
    AUTH_DEFAULT_PASSWORD_ENCRYPTED: encryptedDefaultPassword,
    AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY: decryptionKey
  });

  const harness = await createExpressHarness(provisionConfig);
  try {
    const operatorLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(operatorLogin.status, 200);

    const provisioned = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/user-management/provision-user',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13910000098',
        tenant_name: 'Tenant Should Not Be Accepted'
      }
    });
    assert.equal(provisioned.status, 400);
    assert.equal(provisioned.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express tenant provision-user reuses existing user without mutating password hash and rejects duplicate relationship requests', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedTenantDomainAccess();
  await adminConnection.execute(
    `
      INSERT INTO tenant_memberships (
        membership_id,
        user_id,
        tenant_id,
        tenant_name,
        status,
        can_view_user_management,
        can_operate_user_management,
        can_view_role_management,
        can_operate_role_management
      )
      VALUES (?, ?, 'tenant-provision-a', 'Tenant Provision A', 'active', 1, 1, 0, 0)
      ON DUPLICATE KEY UPDATE
        tenant_name = VALUES(tenant_name),
        status = VALUES(status),
        can_view_user_management = VALUES(can_view_user_management),
        can_operate_user_management = VALUES(can_operate_user_management),
        can_view_role_management = VALUES(can_view_role_management),
        can_operate_role_management = VALUES(can_operate_role_management),
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    ['membership-tenant-provision-a', TEST_USER.id]
  );
  await ensureActiveOrgsForTenantIds(['tenant-provision-a']);

  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'express-tenant-provision-default-password-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const provisionConfig = readConfig({
    ALLOW_MOCK_BACKENDS: 'true',
    DB_HOST: MYSQL_HOST,
    DB_PORT: String(MYSQL_PORT),
    DB_USER: MYSQL_USER,
    DB_PASSWORD: MYSQL_PASSWORD,
    DB_NAME: MYSQL_DATABASE,
    AUTH_DEFAULT_PASSWORD_ENCRYPTED: encryptedDefaultPassword,
    AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY: decryptionKey
  });

  const existingPhone = '13910000090';
  const existingPassword = 'LegacyPass!2026';
  await adminConnection.execute(
    `
      INSERT INTO iam_users (id, phone, password_hash, status, session_version)
      VALUES (?, ?, ?, 'active', 1)
    `,
    ['tenant-provision-reuse-target', existingPhone, hashPassword(existingPassword)]
  );

  const harness = await createExpressHarness(provisionConfig);
  try {
    const operatorLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'tenant'
      }
    });
    assert.equal(operatorLogin.status, 200);
    assert.equal(operatorLogin.body.active_tenant_id, 'tenant-provision-a');

    const [beforeRows] = await adminConnection.execute(
      `
        SELECT id, password_hash
        FROM iam_users
        WHERE phone = ?
        LIMIT 1
      `,
      [existingPhone]
    );
    const beforeRow = beforeRows?.[0] || null;
    assert.ok(beforeRow);

    const provisioned = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/tenant/user-management/provision-user',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: existingPhone,
        tenant_name: 'Tenant Provision A'
      }
    });
    assert.equal(provisioned.status, 200);
    assert.equal(provisioned.body.created_user, false);
    assert.equal(provisioned.body.reused_existing_user, true);
    assert.equal(provisioned.body.active_tenant_id, 'tenant-provision-a');

    const [afterRows] = await adminConnection.execute(
      `
        SELECT password_hash
        FROM iam_users
        WHERE id = ?
        LIMIT 1
      `,
      [beforeRow.id]
    );
    const afterRow = afterRows?.[0] || null;
    assert.ok(afterRow);
    assert.equal(afterRow.password_hash, beforeRow.password_hash);

    const duplicateProvision = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/tenant/user-management/provision-user',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: existingPhone,
        tenant_name: 'Tenant Provision A'
      }
    });
    assert.equal(duplicateProvision.status, 409);
    assert.equal(duplicateProvision.body.error_code, 'AUTH-409-PROVISION-CONFLICT');

    const existingUserLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: existingPhone,
        password: existingPassword,
        entry_domain: 'tenant'
      }
    });
    assert.equal(existingUserLogin.status, 200);
    assert.equal(existingUserLogin.body.active_tenant_id, 'tenant-provision-a');
  } finally {
    await harness.close();
    await adminConnection.execute('DELETE FROM tenant_memberships WHERE user_id = ?', [
      'tenant-provision-reuse-target'
    ]);
    await adminConnection.execute('DELETE FROM platform_users WHERE user_id = ?', [
      'tenant-provision-reuse-target'
    ]);
    await adminConnection.execute('DELETE FROM auth_refresh_tokens WHERE user_id = ?', [
      'tenant-provision-reuse-target'
    ]);
    await adminConnection.execute('DELETE FROM auth_sessions WHERE user_id = ?', [
      'tenant-provision-reuse-target'
    ]);
    await adminConnection.execute('DELETE FROM iam_users WHERE id = ?', ['tenant-provision-reuse-target']);
  }
});

test('express tenant provision-user rejects oversized tenant_name with AUTH-400-INVALID-PAYLOAD', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedTenantDomainAccess();
  await adminConnection.execute(
    `
      INSERT INTO tenant_memberships (
        membership_id,
        user_id,
        tenant_id,
        tenant_name,
        status,
        can_view_user_management,
        can_operate_user_management,
        can_view_role_management,
        can_operate_role_management
      )
      VALUES (?, ?, 'tenant-provision-b', 'Tenant Provision B', 'active', 1, 1, 0, 0)
      ON DUPLICATE KEY UPDATE
        tenant_name = VALUES(tenant_name),
        status = VALUES(status),
        can_view_user_management = VALUES(can_view_user_management),
        can_operate_user_management = VALUES(can_operate_user_management),
        can_view_role_management = VALUES(can_view_role_management),
        can_operate_role_management = VALUES(can_operate_role_management),
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    ['membership-tenant-provision-b', TEST_USER.id]
  );
  await ensureActiveOrgsForTenantIds(['tenant-provision-b']);

  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'express-tenant-provision-name-validation-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const provisionConfig = readConfig({
    ALLOW_MOCK_BACKENDS: 'true',
    DB_HOST: MYSQL_HOST,
    DB_PORT: String(MYSQL_PORT),
    DB_USER: MYSQL_USER,
    DB_PASSWORD: MYSQL_PASSWORD,
    DB_NAME: MYSQL_DATABASE,
    AUTH_DEFAULT_PASSWORD_ENCRYPTED: encryptedDefaultPassword,
    AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY: decryptionKey
  });

  const invalidPhone = '13910000091';
  const harness = await createExpressHarness(provisionConfig);
  try {
    const operatorLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'tenant'
      }
    });
    assert.equal(operatorLogin.status, 200);
    assert.equal(operatorLogin.body.active_tenant_id, 'tenant-provision-b');

    const provisioned = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/tenant/user-management/provision-user',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: invalidPhone,
        tenant_name: 'X'.repeat(129)
      }
    });
    assert.equal(provisioned.status, 400);
    assert.equal(provisioned.body.error_code, 'AUTH-400-INVALID-PAYLOAD');

    const [createdRows] = await adminConnection.execute(
      `
        SELECT id
        FROM iam_users
        WHERE phone = ?
        LIMIT 1
      `,
      [invalidPhone]
    );
    assert.equal(createdRows.length, 0);
  } finally {
    await harness.close();
  }
});

test('express platform provision-user is fail-closed when default password secure config is unavailable', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-user-management-provision-config-fail',
    status: 'active',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const invalidProvisionConfig = readConfig({
    ALLOW_MOCK_BACKENDS: 'true',
    DB_HOST: MYSQL_HOST,
    DB_PORT: String(MYSQL_PORT),
    DB_USER: MYSQL_USER,
    DB_PASSWORD: MYSQL_PASSWORD,
    DB_NAME: MYSQL_DATABASE,
    AUTH_DEFAULT_PASSWORD_ENCRYPTED: '',
    AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY: ''
  });
  const harness = await createExpressHarness(invalidProvisionConfig);
  try {
    const operatorLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(operatorLogin.status, 200);

    const provisionFailed = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/user-management/provision-user',
      headers: {
        authorization: `Bearer ${operatorLogin.body.access_token}`
      },
      body: {
        phone: '13910000089'
      }
    });
    assert.equal(provisionFailed.status, 503);
    assert.equal(provisionFailed.body.error_code, 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE');
  } finally {
    await harness.close();
  }
});

test('express auth flow supports rotation and replay rejection', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: { phone: TEST_USER.phone, password: TEST_USER.password }
    });

    assert.equal(login.status, 200);
    assert.ok(login.body.refresh_token);

    const refresh = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/refresh',
      body: { refresh_token: login.body.refresh_token }
    });

    assert.equal(refresh.status, 200);
    assert.notEqual(refresh.body.refresh_token, login.body.refresh_token);

    const replay = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/refresh',
      body: { refresh_token: login.body.refresh_token }
    });

    assert.equal(replay.status, 401);
    assert.equal(replay.body.error_code, 'AUTH-401-INVALID-REFRESH');

    const chainRevoked = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/refresh',
      body: { refresh_token: refresh.body.refresh_token }
    });

    assert.equal(chainRevoked.status, 401);
    assert.equal(chainRevoked.body.error_code, 'AUTH-401-INVALID-REFRESH');
  } finally {
    await harness.close();
  }
});

test('express refresh persists rotation chain and keeps concurrent sessions isolated', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  const harness = await createExpressHarness();
  try {
    const loginA = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: { phone: TEST_USER.phone, password: TEST_USER.password }
    });
    const loginB = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: { phone: TEST_USER.phone, password: TEST_USER.password }
    });

    assert.equal(loginA.status, 200);
    assert.equal(loginB.status, 200);

    const refreshA = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/refresh',
      body: { refresh_token: loginA.body.refresh_token }
    });
    assert.equal(refreshA.status, 200);
    assert.equal(refreshA.body.session_id, loginA.body.session_id);
    assert.equal(typeof refreshA.body.request_id, 'string');

    const previousHash = refreshTokenHash(loginA.body.refresh_token);
    const nextHash = refreshTokenHash(refreshA.body.refresh_token);
    const [tokenRows] = await adminConnection.execute(
      `
        SELECT token_hash, session_id, status, rotated_from_token_hash, rotated_to_token_hash
        FROM auth_refresh_tokens
        WHERE token_hash IN (?, ?)
      `,
      [previousHash, nextHash]
    );
    const previousRow = tokenRows.find((row) => row.token_hash === previousHash);
    const nextRow = tokenRows.find((row) => row.token_hash === nextHash);

    assert.ok(previousRow);
    assert.ok(nextRow);
    assert.equal(previousRow.session_id, loginA.body.session_id);
    assert.equal(nextRow.session_id, loginA.body.session_id);
    assert.equal(previousRow.status, 'rotated');
    assert.equal(previousRow.rotated_to_token_hash, nextHash);
    assert.equal(nextRow.status, 'active');
    assert.equal(nextRow.rotated_from_token_hash, previousHash);

    const replayA = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/refresh',
      body: { refresh_token: loginA.body.refresh_token }
    });
    assert.equal(replayA.status, 401);
    assert.equal(replayA.body.type, 'about:blank');
    assert.equal(replayA.body.title, 'Unauthorized');
    assert.equal(replayA.body.status, 401);
    assert.equal(replayA.body.detail, '会话已失效，请重新登录');
    assert.equal(replayA.body.error_code, 'AUTH-401-INVALID-REFRESH');
    assert.equal(typeof replayA.body.request_id, 'string');

    const refreshB = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/refresh',
      body: { refresh_token: loginB.body.refresh_token }
    });
    assert.equal(refreshB.status, 200);
    assert.equal(refreshB.body.session_id, loginB.body.session_id);
    assert.equal(typeof refreshB.body.request_id, 'string');
  } finally {
    await harness.close();
  }
});

test('express critical password change bumps session_version and invalidates old access/refresh tokens', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-view-user-management',
    canViewUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);

    const preChangeProbe = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/platform/user-management/probe',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      }
    });
    assert.equal(preChangeProbe.status, 200);

    const sessionVersionBefore = await readUserSessionVersion(TEST_USER.id);

    const changed = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/change-password',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        current_password: TEST_USER.password,
        new_password: 'Passw0rd!2026'
      }
    });
    assert.equal(changed.status, 200);
    assert.equal(changed.body.password_changed, true);
    assert.equal(changed.body.relogin_required, true);

    const sessionVersionAfter = await readUserSessionVersion(TEST_USER.id);
    assert.ok(sessionVersionAfter > sessionVersionBefore);

    const oldAccessProbe = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/platform/user-management/probe',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      }
    });
    assert.equal(oldAccessProbe.status, 401);
    assert.equal(oldAccessProbe.body.error_code, 'AUTH-401-INVALID-ACCESS');

    const oldRefresh = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/refresh',
      body: { refresh_token: login.body.refresh_token }
    });
    assert.equal(oldRefresh.status, 401);
    assert.equal(oldRefresh.body.error_code, 'AUTH-401-INVALID-REFRESH');

    const relogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: 'Passw0rd!2026',
        entry_domain: 'platform'
      }
    });
    assert.equal(relogin.status, 200);
    const oldAccessPayload = decodeJwtPayload(login.body.access_token);
    const newAccessPayload = decodeJwtPayload(relogin.body.access_token);
    assert.ok(Number(newAccessPayload.sv) > Number(oldAccessPayload.sv));

    const postChangeProbe = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/platform/user-management/probe',
      headers: {
        authorization: `Bearer ${relogin.body.access_token}`
      }
    });
    assert.equal(postChangeProbe.status, 200);
  } finally {
    await harness.close();
  }
});

test('express platform role-facts replace converges session and invalidates old access/refresh tokens', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-operate-user-management',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);
    const oldAccessPayload = decodeJwtPayload(login.body.access_token);
    const sessionVersionBefore = await readUserSessionVersion(TEST_USER.id);

    const replaceRoleFacts = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/role-facts/replace',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: TEST_USER.id,
        roles: [{ role_id: 'sys_admin', status: 'active' }]
      }
    });
    assert.equal(replaceRoleFacts.status, 200);
    assert.equal(replaceRoleFacts.body.synced, true);
    assert.equal(replaceRoleFacts.body.reason, 'ok');
    assert.deepEqual(replaceRoleFacts.body.platform_permission_context, {
      scope_label: '平台权限（角色并集）',
      can_view_user_management: true,
      can_operate_user_management: true,
      can_view_tenant_management: true,
      can_operate_tenant_management: true,
      can_view_role_management: false,
      can_operate_role_management: false
    });

    const sessionVersionAfter = await readUserSessionVersion(TEST_USER.id);
    assert.ok(sessionVersionAfter > sessionVersionBefore);

    const oldAccessProbe = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/platform/user-management/probe',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      }
    });
    assert.equal(oldAccessProbe.status, 401);
    assert.equal(oldAccessProbe.body.error_code, 'AUTH-401-INVALID-ACCESS');

    const oldRefresh = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/refresh',
      body: { refresh_token: login.body.refresh_token }
    });
    assert.equal(oldRefresh.status, 401);
    assert.equal(oldRefresh.body.error_code, 'AUTH-401-INVALID-REFRESH');

    const relogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(relogin.status, 200);
    const newAccessPayload = decodeJwtPayload(relogin.body.access_token);
    assert.ok(Number(newAccessPayload.sv) > Number(oldAccessPayload.sv));

    const postReplaceProbe = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/platform/user-management/probe',
      headers: {
        authorization: `Bearer ${relogin.body.access_token}`
      }
    });
    assert.equal(postReplaceProbe.status, 200);
  } finally {
    await harness.close();
  }
});

test('express platform role-facts replace rejects unknown user id with AUTH-400-INVALID-PAYLOAD', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-operate-user-management',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);

    const replaceRoleFacts = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/role-facts/replace',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: 'it-user-missing',
        roles: []
      }
    });

    assert.equal(replaceRoleFacts.status, 400);
    assert.equal(replaceRoleFacts.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express platform role-facts replace rejects missing roles field with AUTH-400-INVALID-PAYLOAD', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-operate-user-management',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);

    const replaceRoleFacts = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/role-facts/replace',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: TEST_USER.id
      }
    });

    assert.equal(replaceRoleFacts.status, 400);
    assert.equal(replaceRoleFacts.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express platform role-facts replace rejects role item missing role_id with AUTH-400-INVALID-PAYLOAD', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-operate-user-management',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);

    const replaceRoleFacts = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/role-facts/replace',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: TEST_USER.id,
        roles: [{ status: 'active' }]
      }
    });

    assert.equal(replaceRoleFacts.status, 400);
    assert.equal(replaceRoleFacts.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express platform role-facts replace rejects unsupported role status with AUTH-400-INVALID-PAYLOAD', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-operate-user-management',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);

    const replaceRoleFacts = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/role-facts/replace',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: TEST_USER.id,
        roles: [
          {
            role_id: 'platform-operate-user-management',
            status: 'pending-approval'
          }
        ]
      }
    });

    assert.equal(replaceRoleFacts.status, 400);
    assert.equal(replaceRoleFacts.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express platform role-facts replace rejects blank role status with AUTH-400-INVALID-PAYLOAD', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-operate-user-management',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);

    const replaceRoleFacts = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/role-facts/replace',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: TEST_USER.id,
        roles: [
          {
            role_id: 'platform-operate-user-management',
            status: '   '
          }
        ]
      }
    });

    assert.equal(replaceRoleFacts.status, 400);
    assert.equal(replaceRoleFacts.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express platform role-facts replace rejects role_id longer than 64 chars', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-operate-user-management',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);

    const replaceRoleFacts = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/role-facts/replace',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: TEST_USER.id,
        roles: [{ role_id: 'r'.repeat(65), status: 'active' }]
      }
    });

    assert.equal(replaceRoleFacts.status, 400);
    assert.equal(replaceRoleFacts.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express platform role-facts replace rejects non-boolean permission flags', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-operate-user-management',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);

    const replaceRoleFacts = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/role-facts/replace',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: TEST_USER.id,
        roles: [
          {
            role_id: 'platform-operate-user-management',
            status: 'active',
            permission: {
              can_operate_user_management: 'true'
            }
          }
        ]
      }
    });

    assert.equal(replaceRoleFacts.status, 400);
    assert.equal(replaceRoleFacts.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express platform role-facts replace rejects non-object permission payload', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-operate-user-management',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);

    const replaceRoleFacts = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/role-facts/replace',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: TEST_USER.id,
        roles: [
          {
            role_id: 'platform-operate-user-management',
            permission: 'invalid'
          }
        ]
      }
    });

    assert.equal(replaceRoleFacts.status, 400);
    assert.equal(replaceRoleFacts.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express platform role-facts replace rejects top-level permission fields', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-operate-user-management',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);

    const replaceRoleFacts = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/role-facts/replace',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: TEST_USER.id,
        roles: [
          {
            role_id: 'platform-operate-user-management',
            can_view_user_management: true
          }
        ]
      }
    });

    assert.equal(replaceRoleFacts.status, 400);
    assert.equal(replaceRoleFacts.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express platform role-facts replace rejects payload with more than 5 role facts', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-operate-user-management',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);

    const replaceRoleFacts = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/role-facts/replace',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: TEST_USER.id,
        roles: [
          { role_id: 'r-1' },
          { role_id: 'r-2' },
          { role_id: 'r-3' },
          { role_id: 'r-4' },
          { role_id: 'r-5' },
          { role_id: 'r-6' }
        ]
      }
    });

    assert.equal(replaceRoleFacts.status, 400);
    assert.equal(replaceRoleFacts.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express platform role-facts replace rejects duplicate role_id entries', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-operate-user-management',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);

    const replaceRoleFacts = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/role-facts/replace',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: TEST_USER.id,
        roles: [
          { role_id: 'r-duplicate', status: 'active' },
          { role_id: 'r-duplicate', status: 'disabled' }
        ]
      }
    });

    assert.equal(replaceRoleFacts.status, 400);
    assert.equal(replaceRoleFacts.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express platform role-facts replace rejects duplicate role_id entries regardless of case', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedPlatformRoleFacts({
    roleId: 'platform-operate-user-management',
    canViewUserManagement: 1,
    canOperateUserManagement: 1
  });

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);

    const replaceRoleFacts = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/platform/role-facts/replace',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        user_id: TEST_USER.id,
        roles: [
          { role_id: 'Role-Case', status: 'active' },
          { role_id: 'role-case', status: 'disabled' }
        ]
      }
    });

    assert.equal(replaceRoleFacts.status, 400);
    assert.equal(replaceRoleFacts.body.error_code, 'AUTH-400-INVALID-PAYLOAD');
  } finally {
    await harness.close();
  }
});

test('express tenant options/select/switch endpoints work with mysql persistent auth store', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedTenantDomainAccess();
  await seedTenantOptions();
  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'tenant'
      }
    });
    assert.equal(login.status, 200);
    assert.equal(login.body.entry_domain, 'tenant');
    assert.equal(login.body.tenant_selection_required, true);
    assert.equal(Array.isArray(login.body.tenant_options), true);
    assert.equal(login.body.tenant_options.length, 2);
    assert.equal(login.body.active_tenant_id, null);
    assert.deepEqual(login.body.tenant_permission_context, {
      scope_label: '组织未选择（无可操作权限）',
      can_view_user_management: false,
      can_operate_user_management: false,
      can_view_role_management: false,
      can_operate_role_management: false
    });
    assert.equal(typeof login.body.access_token, 'string');

    const accessToken = login.body.access_token;

    const optionsBeforeSelect = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/tenant/options',
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    assert.equal(optionsBeforeSelect.status, 200);
    assert.equal(optionsBeforeSelect.body.tenant_selection_required, true);
    assert.equal(optionsBeforeSelect.body.active_tenant_id, null);
    assert.equal(optionsBeforeSelect.body.tenant_options.length, 2);
    assert.deepEqual(optionsBeforeSelect.body.tenant_permission_context, {
      scope_label: '组织未选择（无可操作权限）',
      can_view_user_management: false,
      can_operate_user_management: false,
      can_view_role_management: false,
      can_operate_role_management: false
    });

    const selected = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/tenant/switch',
      headers: {
        authorization: `Bearer ${accessToken}`
      },
      body: { tenant_id: 'tenant-a' }
    });
    assert.equal(selected.status, 200);
    assert.equal(selected.body.active_tenant_id, 'tenant-a');
    assert.equal(selected.body.tenant_selection_required, false);
    assert.deepEqual(selected.body.tenant_permission_context, {
      scope_label: '组织权限（Tenant A）',
      can_view_user_management: true,
      can_operate_user_management: true,
      can_view_role_management: true,
      can_operate_role_management: false
    });
    const userManagementProbeAllowed = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/tenant/user-management/probe',
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    assert.equal(userManagementProbeAllowed.status, 200);
    assert.equal(userManagementProbeAllowed.body.ok, true);
    assert.equal(typeof userManagementProbeAllowed.body.request_id, 'string');

    const switched = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/tenant/switch',
      headers: {
        authorization: `Bearer ${accessToken}`
      },
      body: { tenant_id: 'tenant-b' }
    });
    assert.equal(switched.status, 200);
    assert.equal(switched.body.active_tenant_id, 'tenant-b');
    assert.equal(switched.body.tenant_selection_required, false);
    assert.deepEqual(switched.body.tenant_permission_context, {
      scope_label: '组织权限（Tenant B）',
      can_view_user_management: false,
      can_operate_user_management: false,
      can_view_role_management: true,
      can_operate_role_management: true
    });
    const userManagementProbeDenied = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/tenant/user-management/probe',
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    assert.equal(userManagementProbeDenied.status, 403);
    assert.equal(userManagementProbeDenied.body.error_code, 'AUTH-403-FORBIDDEN');
    assert.equal(typeof userManagementProbeDenied.body.request_id, 'string');

    const optionsAfterSwitch = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/tenant/options',
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    assert.equal(optionsAfterSwitch.status, 200);
    assert.equal(optionsAfterSwitch.body.active_tenant_id, 'tenant-b');
    assert.equal(optionsAfterSwitch.body.tenant_selection_required, false);
    assert.deepEqual(optionsAfterSwitch.body.tenant_permission_context, {
      scope_label: '组织权限（Tenant B）',
      can_view_user_management: false,
      can_operate_user_management: false,
      can_view_role_management: true,
      can_operate_role_management: true
    });

    const switchDenied = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/tenant/switch',
      headers: {
        authorization: `Bearer ${accessToken}`
      },
      body: { tenant_id: 'tenant-not-granted' }
    });
    assert.equal(switchDenied.status, 403);
    assert.equal(switchDenied.body.error_code, 'AUTH-403-NO-DOMAIN');

    const platformLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(platformLogin.status, 200);
    assert.equal(platformLogin.body.entry_domain, 'platform');
    assert.equal(typeof platformLogin.body.access_token, 'string');

    const userManagementProbeNoDomain = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/tenant/user-management/probe',
      headers: {
        authorization: `Bearer ${platformLogin.body.access_token}`
      }
    });
    assert.equal(userManagementProbeNoDomain.status, 403);
    assert.equal(userManagementProbeNoDomain.body.error_code, 'AUTH-403-NO-DOMAIN');
    assert.equal(typeof userManagementProbeNoDomain.body.request_id, 'string');
  } finally {
    await harness.close();
  }
});

test('express platform login rejects tenant-only identity without platform domain access', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await adminConnection.execute(
    `
      DELETE FROM platform_users
      WHERE user_id = ?
    `,
    [TEST_USER.id]
  );
  await seedTenantOptions();

  const harness = await createExpressHarness();
  try {
    const platformLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });

    assert.equal(platformLogin.status, 403);
    assert.equal(platformLogin.body.error_code, 'AUTH-403-NO-DOMAIN');
    assert.equal(typeof platformLogin.body.request_id, 'string');

    const [platformDomainRows] = await adminConnection.execute(
      `
        SELECT COUNT(*) AS row_count
        FROM platform_users
        WHERE user_id = ?
      `,
      [TEST_USER.id]
    );
    assert.equal(Number(platformDomainRows?.[0]?.row_count || 0), 0);
  } finally {
    await harness.close();
  }
});

test('express platform login rejects users with disabled tenant relationships and does not auto-grant platform domain', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await adminConnection.execute(
    `
      DELETE FROM platform_users
      WHERE user_id = ?
    `,
    [TEST_USER.id]
  );
  await adminConnection.execute(
    `
      INSERT INTO tenant_memberships (
        membership_id,
        user_id,
        tenant_id,
        tenant_name,
        status,
        can_view_user_management,
        can_operate_user_management,
        can_view_role_management,
        can_operate_role_management
      )
      VALUES (?, ?, ?, ?, 'disabled', 1, 0, 0, 0)
      ON DUPLICATE KEY UPDATE
        tenant_name = VALUES(tenant_name),
        status = VALUES(status),
        can_view_user_management = VALUES(can_view_user_management),
        can_operate_user_management = VALUES(can_operate_user_management),
        can_view_role_management = VALUES(can_view_role_management),
        can_operate_role_management = VALUES(can_operate_role_management),
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [
      'membership-tenant-disabled',
      TEST_USER.id,
      'tenant-disabled',
      'Tenant Disabled'
    ]
  );

  const harness = await createExpressHarness();
  try {
    const platformLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });

    assert.equal(platformLogin.status, 403);
    assert.equal(platformLogin.body.error_code, 'AUTH-403-NO-DOMAIN');
    assert.equal(typeof platformLogin.body.request_id, 'string');

    const [platformDomainRows] = await adminConnection.execute(
      `
        SELECT COUNT(*) AS row_count
        FROM platform_users
        WHERE user_id = ?
      `,
      [TEST_USER.id]
    );
    assert.equal(Number(platformDomainRows?.[0]?.row_count || 0), 0);
  } finally {
    await harness.close();
  }
});

test('express platform user-management probe enforces no-domain, forbidden, and allow paths with mysql persistent auth store', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }
  await seedTenantDomainAccess();
  await seedTenantOptions();

  const harness = await createExpressHarness();
  try {
    const tenantLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'tenant'
      }
    });
    assert.equal(tenantLogin.status, 200);

    const platformProbeNoDomain = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/platform/user-management/probe',
      headers: {
        authorization: `Bearer ${tenantLogin.body.access_token}`
      }
    });
    assert.equal(platformProbeNoDomain.status, 403);
    assert.equal(platformProbeNoDomain.body.error_code, 'AUTH-403-NO-DOMAIN');
    assert.equal(typeof platformProbeNoDomain.body.request_id, 'string');

    const platformLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(platformLogin.status, 200);

    const platformProbeForbidden = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/platform/user-management/probe',
      headers: {
        authorization: `Bearer ${platformLogin.body.access_token}`
      }
    });
    assert.equal(platformProbeForbidden.status, 403);
    assert.equal(platformProbeForbidden.body.error_code, 'AUTH-403-FORBIDDEN');
    assert.equal(typeof platformProbeForbidden.body.request_id, 'string');

    await seedPlatformRoleFacts({
      roleId: 'platform-view-user-management',
      canViewUserManagement: 1
    });
    const platformProbeAllowed = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/platform/user-management/probe',
      headers: {
        authorization: `Bearer ${platformLogin.body.access_token}`
      }
    });
    assert.equal(platformProbeAllowed.status, 200);
    assert.equal(platformProbeAllowed.body.ok, true);
    assert.equal(typeof platformProbeAllowed.body.request_id, 'string');
  } finally {
    await harness.close();
  }
});

test('express platform user-management probe revokes access after platform role facts are removed', async () => {
  if (!(await prepareMySqlState())) {
    return;
  }

  const harness = await createExpressHarness();
  try {
    const platformLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(platformLogin.status, 200);

    await seedPlatformRoleFacts({
      roleId: 'platform-view-user-management',
      canViewUserManagement: 1
    });

    const allowed = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/platform/user-management/probe',
      headers: {
        authorization: `Bearer ${platformLogin.body.access_token}`
      }
    });
    assert.equal(allowed.status, 200);

    await clearPlatformRoleFacts();
    const revoked = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/platform/user-management/probe',
      headers: {
        authorization: `Bearer ${platformLogin.body.access_token}`
      }
    });
    assert.equal(revoked.status, 403);
    assert.equal(revoked.body.error_code, 'AUTH-403-FORBIDDEN');
  } finally {
    await harness.close();
  }
});

test('createApiApp boots with auth schema created only from official migrations', async () => {
  if (!requireMySqlOrReady()) {
    return;
  }

  await adminConnection.execute('SET FOREIGN_KEY_CHECKS = 0');
  try {
    await adminConnection.execute('DROP TABLE IF EXISTS platform_integration_freeze_control');
    await adminConnection.execute('DROP TABLE IF EXISTS platform_integration_retry_recovery_queue');
    await adminConnection.execute(
      'DROP TABLE IF EXISTS platform_integration_contract_compatibility_checks'
    );
    await adminConnection.execute('DROP TABLE IF EXISTS platform_integration_contract_versions');
    await adminConnection.execute('DROP TABLE IF EXISTS platform_integration_catalog');
    await adminConnection.execute('DROP TABLE IF EXISTS auth_refresh_tokens');
    await adminConnection.execute('DROP TABLE IF EXISTS auth_sessions');
    await adminConnection.execute('DROP TABLE IF EXISTS platform_user_roles');
    await adminConnection.execute('DROP TABLE IF EXISTS tenant_membership_roles');
    await adminConnection.execute('DROP TABLE IF EXISTS tenant_memberships');
    await adminConnection.execute('DROP TABLE IF EXISTS auth_user_tenant_membership_history');
    await adminConnection.execute('DROP TABLE IF EXISTS platform_users');
    await adminConnection.execute('DROP TABLE IF EXISTS tenant_role_permission_grants');
    await adminConnection.execute('DROP TABLE IF EXISTS platform_role_permission_grants');
    await adminConnection.execute('DROP TABLE IF EXISTS platform_roles');
    await adminConnection.execute('DROP TABLE IF EXISTS audit_events');
    await adminConnection.execute('DROP TABLE IF EXISTS system_sensitive_configs');
    await adminConnection.execute('DROP TABLE IF EXISTS tenants');
    await adminConnection.execute('DROP TABLE IF EXISTS iam_users');
  } finally {
    await adminConnection.execute('SET FOREIGN_KEY_CHECKS = 1');
  }

  await adminConnection.execute(
    `
      CREATE TABLE IF NOT EXISTS iam_users (
        id VARCHAR(64) NOT NULL,
        phone VARCHAR(32) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'active',
        session_version INT UNSIGNED NOT NULL DEFAULT 1,
        created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        PRIMARY KEY (id),
        UNIQUE KEY uk_iam_users_phone (phone)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `
  );
  await runMigrationSql(adminConnection, '0002_auth_sessions_refresh.sql');
  await runMigrationSql(adminConnection, '0003_auth_timestamp_precision.sql');
  await runMigrationSql(adminConnection, '0004_auth_session_domain_tenant_context.sql');
  await runMigrationSql(adminConnection, '0005_auth_domain_tenant_membership.sql');
  await runMigrationSql(adminConnection, '0006_auth_platform_permission_snapshot.sql');
  await runMigrationSql(adminConnection, '0007_auth_platform_role_facts.sql');
  await runMigrationSql(adminConnection, '0008_platform_org_bootstrap.sql');
  await runMigrationSql(adminConnection, '0009_platform_role_catalog.sql');
  await runMigrationSql(adminConnection, '0010_platform_role_permission_grants.sql');
  await runMigrationSql(adminConnection, '0011_auth_user_platform_roles_role_id_index.sql');
  await runMigrationSql(adminConnection, '0012_tenant_member_lifecycle.sql');
  await runMigrationSql(adminConnection, '0013_platform_role_catalog_tenant_isolation.sql');
  await runMigrationSql(adminConnection, '0014_tenant_role_permission_grants.sql');
  await runMigrationSql(adminConnection, '0015_auth_tenant_membership_roles.sql');
  await runMigrationSql(adminConnection, '0016_auth_tenant_member_profile_fields.sql');
  await runMigrationSql(adminConnection, '0017_owner_transfer_takeover_role_cleanup.sql');
  await runMigrationSql(adminConnection, '0018_audit_events.sql');
  await runMigrationSql(adminConnection, '0019_system_sensitive_configs.sql');
  await runMigrationSql(adminConnection, '0020_permission_grants_final_authorization_cleanup.sql');
  await runMigrationSql(adminConnection, '0021_platform_integration_catalog.sql');
  await runMigrationSql(adminConnection, '0022_platform_integration_contract_versions.sql');
  await runMigrationSql(adminConnection, '0023_platform_integration_retry_recovery.sql');
  await runMigrationSql(adminConnection, '0024_platform_integration_freeze_control.sql');
  await runMigrationSql(adminConnection, '0025_platform_user.sql');
  await seedTestUser();

  const harness = await createExpressHarness();
  try {
    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: TEST_USER.phone,
        password: TEST_USER.password,
        entry_domain: 'platform'
      }
    });
    assert.equal(login.status, 200);
    assert.equal(login.body.entry_domain, 'platform');
    assert.equal(login.body.active_tenant_id, null);
    assert.equal(typeof login.body.access_token, 'string');
    assert.equal(typeof login.body.refresh_token, 'string');
  } finally {
    await harness.close();
  }
});

test('mock mode boots without mysql connection when persistent store is not required', async () => {
  let connectCalled = false;
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
  const app = await createApiApp(mockConfig, {
    dependencyProbe,
    connectMySql: async () => {
      connectCalled = true;
      throw new Error('mysql should not be used in mock mode');
    }
  });

  try {
    await app.init();
    assert.equal(connectCalled, false);
  } finally {
    await app.close();
  }
});

test('createApiApp closes db client when auth service init fails after mysql connect', async () => {
  let dbCloseCalls = 0;
  let createAuthServiceCalls = 0;
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        requirePersistentAuthStore: true,
        connectMySql: async () => ({
          query: async (sql, params = []) => {
            const normalizedSql = String(sql);
            if (normalizedSql.includes('FROM information_schema.tables')) {
              return [
                { table_name: 'auth_sessions' },
                { table_name: 'tenant_memberships' },
                { table_name: 'platform_user_roles' },
                { table_name: 'platform_users' },
                { table_name: 'platform_role_permission_grants' }
              ];
            }
            if (normalizedSql.includes('FROM information_schema.columns')) {
              const tableName = String(params[0] || '');
              if (tableName === 'auth_sessions') {
                return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'tenant_memberships') {
                return AUTH_USER_TENANTS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_user_roles') {
                return AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_users') {
                return PLATFORM_USER_PROFILES_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_role_permission_grants') {
                return PLATFORM_ROLE_PERMISSION_GRANTS_REQUIRED_COLUMN_ROWS;
              }
              return [];
            }
            return [];
          },
          inTransaction: async (runner) => runner({ query: async () => [] }),
          close: async () => {
            dbCloseCalls += 1;
          }
        }),
        createAuthService: () => {
          createAuthServiceCalls += 1;
          throw new Error('auth-service-init-failure');
        }
      }),
    /auth-service-init-failure/
  );

  assert.equal(createAuthServiceCalls, 1);
  assert.equal(dbCloseCalls, 1);
});

test('createApiApp preflight accepts uppercase information_schema field names', async () => {
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
  const app = await createApiApp(mockConfig, {
    dependencyProbe,
    requirePersistentAuthStore: true,
    connectMySql: async () => ({
      query: async (sql, params = []) => {
        const normalizedSql = String(sql);
        if (normalizedSql.includes('FROM information_schema.tables')) {
          return [
            { TABLE_NAME: 'auth_sessions' },
            { TABLE_NAME: 'tenant_memberships' },
            { TABLE_NAME: 'platform_user_roles' },
            { TABLE_NAME: 'platform_users' },
            { TABLE_NAME: 'platform_role_permission_grants' }
          ];
        }
        if (normalizedSql.includes('FROM information_schema.columns')) {
          const tableName = String(params[0] || '');
          if (tableName === 'auth_sessions') {
            return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS_UPPER;
          }
          if (tableName === 'tenant_memberships') {
            return AUTH_USER_TENANTS_REQUIRED_COLUMN_ROWS_UPPER;
          }
          if (tableName === 'platform_user_roles') {
            return AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS_UPPER;
          }
          if (tableName === 'platform_users') {
            return PLATFORM_USER_PROFILES_REQUIRED_COLUMN_ROWS_UPPER;
          }
          if (tableName === 'platform_role_permission_grants') {
            return PLATFORM_ROLE_PERMISSION_GRANTS_REQUIRED_COLUMN_ROWS_UPPER;
          }
          return [];
        }
        return [];
      },
      inTransaction: async (runner) => runner({ query: async () => [] }),
      close: async () => {}
    })
  });

  try {
    await app.init();
  } finally {
    await app.close();
  }
});

test('createApiApp fails fast when auth schema table is missing', async () => {
  let dbCloseCalls = 0;
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        requirePersistentAuthStore: true,
        connectMySql: async () => ({
          query: async (sql, params = []) => {
            const normalizedSql = String(sql);
            if (normalizedSql.includes('FROM information_schema.tables')) {
              return [
                { table_name: 'auth_sessions' },
                { table_name: 'tenant_memberships' },
                { table_name: 'platform_user_roles' },
                { table_name: 'platform_role_permission_grants' }
              ];
            }
            if (normalizedSql.includes('FROM information_schema.columns')) {
              const tableName = String(params[0] || '');
              if (tableName === 'auth_sessions') {
                return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'tenant_memberships') {
                return AUTH_USER_TENANTS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_user_roles') {
                return AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_role_permission_grants') {
                return PLATFORM_ROLE_PERMISSION_GRANTS_REQUIRED_COLUMN_ROWS;
              }
              return [];
            }
            return [];
          },
          inTransaction: async (runner) => runner({ query: async () => [] }),
          close: async () => {
            dbCloseCalls += 1;
          }
        })
      }),
    /Auth schema preflight failed: missing tables: platform_users/
  );

  assert.equal(dbCloseCalls, 1);
});

test('createApiApp fails fast when platform_user_roles table is missing', async () => {
  let dbCloseCalls = 0;
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        requirePersistentAuthStore: true,
        connectMySql: async () => ({
          query: async (sql, params = []) => {
            const normalizedSql = String(sql);
            if (normalizedSql.includes('FROM information_schema.tables')) {
              return [
                { table_name: 'auth_sessions' },
                { table_name: 'tenant_memberships' },
                { table_name: 'platform_users' },
                { table_name: 'platform_role_permission_grants' }
              ];
            }
            if (normalizedSql.includes('FROM information_schema.columns')) {
              const tableName = String(params[0] || '');
              if (tableName === 'auth_sessions') {
                return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'tenant_memberships') {
                return AUTH_USER_TENANTS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_users') {
                return PLATFORM_USER_PROFILES_REQUIRED_COLUMN_ROWS;
              }
              return [];
            }
            return [];
          },
          inTransaction: async (runner) => runner({ query: async () => [] }),
          close: async () => {
            dbCloseCalls += 1;
          }
        })
      }),
    /Auth schema preflight failed: missing tables: platform_user_roles/
  );

  assert.equal(dbCloseCalls, 1);
});

test('createApiApp parser and fallback error responses include access-control-allow-origin', async () => {
  const mockConfig = readConfig({
    ALLOW_MOCK_BACKENDS: 'true',
    API_JSON_BODY_LIMIT_BYTES: '64',
    API_CORS_ALLOWED_ORIGINS: 'https://web.example'
  });
  const app = await createApiApp(mockConfig, {
    dependencyProbe
  });

  await app.init();
  await app.listen(0, '127.0.0.1');
  const address = app.getHttpServer().address();
  const port = typeof address === 'object' && address ? address.port : 0;

  try {
    const malformedJson = await fetch(`http://127.0.0.1:${port}/auth/login`, {
      method: 'POST',
      headers: {
        Accept: 'application/problem+json',
        'content-type': 'application/json',
        'x-request-id': 'req-create-apiapp-bad-json',
        origin: 'https://web.example'
      },
      body: '{"phone":"13910000000"'
    });
    const malformedPayload = await parseResponseBody(malformedJson);
    assert.equal(malformedJson.status, 400);
    assert.equal(malformedPayload.error_code, 'AUTH-400-INVALID-PAYLOAD');
    assert.equal(malformedPayload.request_id, 'req-create-apiapp-bad-json');
    assert.match(String(malformedPayload.traceparent || ''), TRACEPARENT_PATTERN);
    assert.equal(
      malformedJson.headers.get('x-request-id'),
      'req-create-apiapp-bad-json'
    );
    assert.equal(
      malformedJson.headers.get('traceparent'),
      malformedPayload.traceparent
    );
    assert.equal(
      malformedJson.headers.get('access-control-allow-origin'),
      'https://web.example'
    );

    const oversized = await fetch(`http://127.0.0.1:${port}/auth/login`, {
      method: 'POST',
      headers: {
        Accept: 'application/problem+json',
        'content-type': 'application/json',
        'x-request-id': 'req-create-apiapp-too-large',
        origin: 'https://web.example'
      },
      body: JSON.stringify({ payload: 'x'.repeat(256) })
    });
    const oversizedPayload = await parseResponseBody(oversized);
    assert.equal(oversized.status, 413);
    assert.equal(oversizedPayload.error_code, 'AUTH-413-PAYLOAD-TOO-LARGE');
    assert.equal(oversizedPayload.detail, 'JSON payload exceeds allowed size');
    assert.equal(oversizedPayload.request_id, 'req-create-apiapp-too-large');
    assert.match(String(oversizedPayload.traceparent || ''), TRACEPARENT_PATTERN);
    assert.equal(
      oversized.headers.get('x-request-id'),
      'req-create-apiapp-too-large'
    );
    assert.equal(oversized.headers.get('traceparent'), oversizedPayload.traceparent);
    assert.equal(oversized.headers.get('access-control-allow-origin'), 'https://web.example');

    const notFound = await fetch(`http://127.0.0.1:${port}/missing-path`, {
      method: 'GET',
      headers: {
        Accept: 'application/problem+json',
        'x-request-id': 'req-create-apiapp-not-found',
        origin: 'https://web.example'
      }
    });
    const notFoundPayload = await parseResponseBody(notFound);
    assert.equal(notFound.status, 404);
    assert.equal(notFoundPayload.status, 404);
    assert.equal(notFoundPayload.error_code, 'AUTH-404-NOT-FOUND');
    assert.equal(notFoundPayload.request_id, 'req-create-apiapp-not-found');
    assert.equal(notFound.headers.get('access-control-allow-origin'), 'https://web.example');

    const methodNotAllowed = await fetch(`http://127.0.0.1:${port}/health`, {
      method: 'POST',
      headers: {
        Accept: 'application/problem+json',
        'content-type': 'application/json',
        'x-request-id': 'req-create-apiapp-method-not-allowed',
        origin: 'https://web.example'
      },
      body: JSON.stringify({ ping: true })
    });
    const methodNotAllowedPayload = await parseResponseBody(methodNotAllowed);
    assert.equal(methodNotAllowed.status, 405);
    assert.equal(
      methodNotAllowedPayload.error_code,
      'AUTH-405-METHOD-NOT-ALLOWED'
    );
    assert.equal(
      methodNotAllowedPayload.request_id,
      'req-create-apiapp-method-not-allowed'
    );
    assert.equal(methodNotAllowed.headers.get('allow'), 'GET,HEAD,OPTIONS');
    assert.equal(
      methodNotAllowed.headers.get('access-control-allow-origin'),
      'https://web.example'
    );

    const notFoundWithAmbiguousRequestId = await fetch(
      `http://127.0.0.1:${port}/missing-path`,
      {
        method: 'GET',
        headers: {
          Accept: 'application/problem+json',
          'x-request-id': 'req-a,req-b',
          origin: 'https://web.example'
        }
      }
    );
    const notFoundWithAmbiguousRequestIdPayload =
      await parseResponseBody(notFoundWithAmbiguousRequestId);
    assert.equal(notFoundWithAmbiguousRequestId.status, 404);
    assert.equal(
      notFoundWithAmbiguousRequestIdPayload.error_code,
      'AUTH-404-NOT-FOUND'
    );
    assert.match(
      notFoundWithAmbiguousRequestIdPayload.request_id,
      UUID_PATTERN
    );
    assert.notEqual(
      notFoundWithAmbiguousRequestIdPayload.request_id,
      'req-a,req-b'
    );
    assert.equal(
      notFoundWithAmbiguousRequestId.headers.get('access-control-allow-origin'),
      'https://web.example'
    );

  } finally {
    await app.close();
  }
});

test('createApiApp degrades /health when dependency probe throws', async () => {
  const mockConfig = readConfig({
    ALLOW_MOCK_BACKENDS: 'true',
    API_CORS_ALLOWED_ORIGINS: 'https://web.example'
  });
  const app = await createApiApp(mockConfig, {
    dependencyProbe: async () => {
      throw new Error('dependency probe exploded');
    }
  });

  await app.init();
  await app.listen(0, '127.0.0.1');
  const address = app.getHttpServer().address();
  const port = typeof address === 'object' && address ? address.port : 0;
  const requestId = 'req-create-apiapp-internal';

  try {
    const response = await fetch(`http://127.0.0.1:${port}/health`, {
      method: 'GET',
      headers: {
        Accept: 'application/problem+json',
        'x-request-id': requestId,
        origin: 'https://web.example'
      }
    });
    const payload = await parseResponseBody(response);

    assert.equal(response.status, 503);
    assert.equal(payload.ok, false);
    assert.equal(payload.request_id, requestId);
    assert.equal(payload.dependencies.db.mode, 'probe-error');
    assert.equal(payload.dependencies.redis.mode, 'probe-error');
    assert.equal(payload.dependencies.db.detail, 'dependency probe failed');
    assert.equal(payload.dependencies.redis.detail, 'dependency probe failed');
    assert.ok(!String(payload.dependencies.db.detail).includes('dependency probe exploded'));
    assert.equal(response.headers.get('access-control-allow-origin'), 'https://web.example');
  } finally {
    await app.close();
  }
});

test('createApiApp global error handler includes AUTH-500-INTERNAL error_code', async () => {
  const mockConfig = readConfig({
    ALLOW_MOCK_BACKENDS: 'true',
    API_CORS_ALLOWED_ORIGINS: 'https://web.example'
  });
  const app = await createApiApp(mockConfig, {
    authService: {
      login: async () => {
        throw new Error('unexpected-login-failure');
      },
      authorizeRoute: async () => ({
        user_id: 'platform-admin',
        session_id: 'platform-session'
      })
    }
  });

  await app.init();
  await app.listen(0, '127.0.0.1');
  const address = app.getHttpServer().address();
  const port = typeof address === 'object' && address ? address.port : 0;
  const requestId = 'req-create-apiapp-unhandled';

  try {
    const response = await fetch(`http://127.0.0.1:${port}/auth/login`, {
      method: 'POST',
      headers: {
        Accept: 'application/problem+json',
        'content-type': 'application/json',
        'x-request-id': requestId,
        traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
        origin: 'https://web.example'
      },
      body: JSON.stringify({
        phone: '13800000000',
        password: 'Passw0rd!'
      })
    });
    const payload = await parseResponseBody(response);

    assert.equal(response.status, 500);
    assert.equal(payload.error_code, 'AUTH-500-INTERNAL');
    assert.equal(payload.request_id, requestId);
    assert.equal(
      payload.traceparent,
      '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
    );
    assert.equal(response.headers.get('x-request-id'), requestId);
    assert.equal(
      response.headers.get('traceparent'),
      '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
    );
    assert.equal(response.headers.get('access-control-allow-origin'), 'https://web.example');
  } finally {
    await app.close();
  }
});

test('createApiApp fails fast when protected route permission declaration is missing', async () => {
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        routeDefinitions: ROUTE_DEFINITIONS_WITH_MISSING_PERMISSION
      }),
    /Route permission preflight failed: missing protected route declarations: GET \/auth\/missing-permission/
  );
});

test('createApiApp fails fast when protected routes exist but authService lacks authorizeRoute capability', async () => {
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        authService: {
          logout: async () => ({ ok: true })
        }
      }),
    /Route authorization preflight failed: missing authorizeRoute handler for protected routes:/
  );
});

test('createApiApp fails fast when route declaration access/scope is invalid', async () => {
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        routeDefinitions: [
          {
            method: 'GET',
            path: '/health',
            access: 'public',
            permission_code: '',
            scope: 'public'
          },
          {
            method: 'POST',
            path: '/auth/login',
            access: 'publik',
            permission_code: '',
            scope: 'publick'
          }
        ]
      }),
    /Route permission preflight failed: invalid route declaration fields: POST \/auth\/login \(invalid access: publik\), POST \/auth\/login \(invalid scope: publick\)/
  );
});

test('createApiApp enforces executable route alignment for custom routeDefinitions by default', async () => {
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        routeDefinitions: [
          {
            method: 'GET',
            path: '/health',
            access: 'public',
            permission_code: '',
            scope: 'public'
          }
        ]
      }),
    /Route permission preflight failed: executable routes missing declarations:/
  );
});

test('createApiApp fails fast when protected route permission code is unknown to evaluator', async () => {
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        routeDefinitions: ROUTE_DEFINITIONS_WITH_UNKNOWN_PERMISSION_CODE
      }),
    /Route permission preflight failed: unknown permission codes: GET \/auth\/tenant\/user-management\/probe \(unknown permission_code: tenant\.user_management\.operat\)/
  );
});

test('createApiApp accepts preflight permission capability overrides from options', async () => {
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  const app = await createApiApp(mockConfig, {
    dependencyProbe,
    routeDefinitions: [
      {
        method: 'GET',
        path: '/health',
        access: 'public',
        permission_code: '',
        scope: 'public'
      },
      {
        method: 'GET',
        path: '/auth/tenant/user-management/probe',
        access: 'protected',
        permission_code: 'tenant.custom.read',
        scope: 'tenant'
      }
    ],
    executableRouteKeys: ['GET /health', 'GET /auth/tenant/user-management/probe'],
    supportedPermissionCodes: ['tenant.custom.read'],
    supportedPermissionScopes: {
      'tenant.custom.read': ['tenant']
    }
  });

  await app.close();
});

test('createApiApp fails fast when duplicate method+path route declarations exist', async () => {
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        routeDefinitions: ROUTE_DEFINITIONS_WITH_DUPLICATE_ROUTE_KEY
      }),
    /Route permission preflight failed: duplicate route declarations: GET \/health/
  );
});

test('createApiApp fails fast when protected route permission scope is incompatible', async () => {
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        routeDefinitions: ROUTE_DEFINITIONS_WITH_INCOMPATIBLE_PERMISSION_SCOPE
      }),
    /Route permission preflight failed: incompatible permission scope declarations: GET \/auth\/tenant\/user-management\/probe \(permission_code tenant\.user_management\.operate incompatible with scope session; allowed scopes: tenant\)/
  );
});

test('createApiApp accepts route method declarations with trailing whitespace', async () => {
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  const app = await createApiApp(mockConfig, {
    dependencyProbe,
    routeDefinitions: [
      {
        method: 'GET ',
        path: '/health',
        access: 'public',
        permission_code: '',
        scope: 'public'
      }
    ],
    executableRouteKeys: ['GET /health']
  });

  await app.close();
});

test('createApiApp uses immutable snapshot for custom routeDefinitions at startup', async () => {
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
  const customRouteDefinitions = ROUTE_DEFINITIONS.map((routeDefinition) => ({
    ...routeDefinition
  }));
  const protectedProbeRoute = customRouteDefinitions.find(
    (routeDefinition) =>
      routeDefinition.method === 'GET'
      && routeDefinition.path === '/auth/tenant/user-management/probe'
  );
  assert.ok(protectedProbeRoute);

  const app = await createApiApp(mockConfig, {
    dependencyProbe,
    routeDefinitions: customRouteDefinitions
  });

  await app.init();
  await app.listen(0, '127.0.0.1');
  const address = app.getHttpServer().address();
  const port = typeof address === 'object' && address ? address.port : 0;

  protectedProbeRoute.access = 'public';
  protectedProbeRoute.permission_code = '';
  protectedProbeRoute.scope = 'public';

  try {
    const response = await fetch(`http://127.0.0.1:${port}/auth/tenant/user-management/probe`, {
      headers: {
        accept: 'application/problem+json'
      }
    });
    const payload = await parseResponseBody(response);

    assert.equal(response.status, 401);
    assert.equal(payload.error_code, 'AUTH-401-INVALID-ACCESS');
  } finally {
    await app.close();
  }
});

test('createApiApp fails fast when tenant_memberships permission columns are missing', async () => {
  let dbCloseCalls = 0;
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        requirePersistentAuthStore: true,
        connectMySql: async () => ({
          query: async (sql, params = []) => {
            const normalizedSql = String(sql);
            if (normalizedSql.includes('FROM information_schema.tables')) {
              return [
                { table_name: 'auth_sessions' },
                { table_name: 'tenant_memberships' },
                { table_name: 'platform_user_roles' },
                { table_name: 'platform_users' },
                { table_name: 'platform_role_permission_grants' }
              ];
            }
            if (normalizedSql.includes('FROM information_schema.columns')) {
              const tableName = String(params[0] || '');
              if (tableName === 'auth_sessions') {
                return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'tenant_memberships') {
                return [
                  { column_name: 'user_id' },
                  { column_name: 'tenant_id' },
                  { column_name: 'tenant_name' },
                  { column_name: 'status' },
                  { column_name: 'can_view_user_management' },
                  { column_name: 'can_operate_user_management' }
                ];
              }
              if (tableName === 'platform_user_roles') {
                return AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_users') {
                return PLATFORM_USER_PROFILES_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_role_permission_grants') {
                return PLATFORM_ROLE_PERMISSION_GRANTS_REQUIRED_COLUMN_ROWS;
              }
              return [];
            }
            return [];
          },
          inTransaction: async (runner) => runner({ query: async () => [] }),
          close: async () => {
            dbCloseCalls += 1;
          }
        })
      }),
    /Auth schema preflight failed: tenant_memberships missing columns/
  );

  assert.equal(dbCloseCalls, 1);
});

test('createApiApp fails fast when tenant_memberships profile columns are missing', async () => {
  let dbCloseCalls = 0;
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        requirePersistentAuthStore: true,
        connectMySql: async () => ({
          query: async (sql, params = []) => {
            const normalizedSql = String(sql);
            if (normalizedSql.includes('FROM information_schema.tables')) {
              return [
                { table_name: 'auth_sessions' },
                { table_name: 'tenant_memberships' },
                { table_name: 'platform_user_roles' },
                { table_name: 'platform_users' },
                { table_name: 'platform_role_permission_grants' }
              ];
            }
            if (normalizedSql.includes('FROM information_schema.columns')) {
              const tableName = String(params[0] || '');
              if (tableName === 'auth_sessions') {
                return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'tenant_memberships') {
                return AUTH_USER_TENANTS_REQUIRED_COLUMN_ROWS.filter(
                  (row) =>
                    row.column_name !== 'display_name'
                    && row.column_name !== 'department_name'
                );
              }
              if (tableName === 'platform_user_roles') {
                return AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_users') {
                return PLATFORM_USER_PROFILES_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_role_permission_grants') {
                return PLATFORM_ROLE_PERMISSION_GRANTS_REQUIRED_COLUMN_ROWS;
              }
              return [];
            }
            return [];
          },
          inTransaction: async (runner) => runner({ query: async () => [] }),
          close: async () => {
            dbCloseCalls += 1;
          }
        })
      }),
    /Auth schema preflight failed: tenant_memberships missing columns: display_name, department_name/
  );

  assert.equal(dbCloseCalls, 1);
});

test('createApiApp fails fast when platform_users required columns are missing', async () => {
  let dbCloseCalls = 0;
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        requirePersistentAuthStore: true,
        connectMySql: async () => ({
          query: async (sql, params = []) => {
            const normalizedSql = String(sql);
            if (normalizedSql.includes('FROM information_schema.tables')) {
              return [
                { table_name: 'auth_sessions' },
                { table_name: 'tenant_memberships' },
                { table_name: 'platform_user_roles' },
                { table_name: 'platform_users' },
                { table_name: 'platform_role_permission_grants' }
              ];
            }
            if (normalizedSql.includes('FROM information_schema.columns')) {
              const tableName = String(params[0] || '');
              if (tableName === 'auth_sessions') {
                return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'tenant_memberships') {
                return AUTH_USER_TENANTS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_user_roles') {
                return AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_users') {
                return PLATFORM_USER_PROFILES_REQUIRED_COLUMN_ROWS.filter(
                  (row) => row.column_name !== 'status'
                );
              }
              if (tableName === 'platform_role_permission_grants') {
                return PLATFORM_ROLE_PERMISSION_GRANTS_REQUIRED_COLUMN_ROWS;
              }
              return [];
            }
            return [];
          },
          inTransaction: async (runner) => runner({ query: async () => [] }),
          close: async () => {
            dbCloseCalls += 1;
          }
        })
      }),
    /Auth schema preflight failed: platform_users missing columns: status/
  );

  assert.equal(dbCloseCalls, 1);
});

test('createApiApp fails fast when auth_sessions context columns are missing', async () => {
  let dbCloseCalls = 0;
  const mockConfig = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

  await assert.rejects(
    () =>
      createApiApp(mockConfig, {
        dependencyProbe,
        requirePersistentAuthStore: true,
        connectMySql: async () => ({
          query: async (sql, params = []) => {
            const normalizedSql = String(sql);
            if (normalizedSql.includes('FROM information_schema.tables')) {
              return [
                { table_name: 'auth_sessions' },
                { table_name: 'tenant_memberships' },
                { table_name: 'platform_user_roles' },
                { table_name: 'platform_users' },
                { table_name: 'platform_role_permission_grants' }
              ];
            }
            if (normalizedSql.includes('FROM information_schema.columns')) {
              const tableName = String(params[0] || '');
              if (tableName === 'auth_sessions') {
                return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS_WITHOUT_ACTIVE_TENANT;
              }
              if (tableName === 'tenant_memberships') {
                return AUTH_USER_TENANTS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_user_roles') {
                return AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_users') {
                return PLATFORM_USER_PROFILES_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'platform_role_permission_grants') {
                return PLATFORM_ROLE_PERMISSION_GRANTS_REQUIRED_COLUMN_ROWS;
              }
              return [];
            }
            return [];
          },
          inTransaction: async (runner) => runner({ query: async () => [] }),
          close: async () => {
            dbCloseCalls += 1;
          }
        })
      }),
    /Auth schema preflight failed: auth_sessions missing columns: active_tenant_id/
  );

  assert.equal(dbCloseCalls, 1);
});

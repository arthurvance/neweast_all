const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createHash, pbkdf2Sync, randomBytes } = require('node:crypto');
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
const AUTH_DOMAIN_ACCESS_REQUIRED_COLUMNS = [
  'user_id',
  'domain',
  'status',
  'can_view_member_admin',
  'can_operate_member_admin',
  'can_view_billing',
  'can_operate_billing',
  'updated_at'
];
const AUTH_DOMAIN_ACCESS_REQUIRED_COLUMN_ROWS = AUTH_DOMAIN_ACCESS_REQUIRED_COLUMNS.map((columnName) => ({
  column_name: columnName
}));
const AUTH_DOMAIN_ACCESS_REQUIRED_COLUMN_ROWS_UPPER = AUTH_DOMAIN_ACCESS_REQUIRED_COLUMNS.map(
  (columnName) => ({
    COLUMN_NAME: columnName
  })
);
const AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMNS = [
  'user_id',
  'role_id',
  'status',
  'can_view_member_admin',
  'can_operate_member_admin',
  'can_view_billing',
  'can_operate_billing',
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
    path: '/auth/tenant/member-admin/probe',
    access: 'protected',
    permission_code: 'tenant.member_admin.operat',
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
    path: '/auth/tenant/member-admin/probe',
    access: 'protected',
    permission_code: 'tenant.member_admin.operate',
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
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(64) NOT NULL,
        phone VARCHAR(32) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'active',
        session_version INT UNSIGNED NOT NULL DEFAULT 1,
        created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        PRIMARY KEY (id),
        UNIQUE KEY uk_users_phone (phone)
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
      CREATE TABLE IF NOT EXISTS refresh_tokens (
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
      CREATE TABLE IF NOT EXISTS auth_user_domain_access (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id VARCHAR(64) NOT NULL,
        domain VARCHAR(16) NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'active',
        can_view_member_admin TINYINT(1) NOT NULL DEFAULT 0,
        can_operate_member_admin TINYINT(1) NOT NULL DEFAULT 0,
        can_view_billing TINYINT(1) NOT NULL DEFAULT 0,
        can_operate_billing TINYINT(1) NOT NULL DEFAULT 0,
        created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        PRIMARY KEY (id),
        UNIQUE KEY uk_auth_user_domain_access_user_domain (user_id, domain),
        KEY idx_auth_user_domain_access_user_status (user_id, status)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `
  );

  const [domainPermissionColumns] = await adminConnection.execute(
    `
      SELECT COLUMN_NAME AS column_name
      FROM information_schema.columns
      WHERE table_schema = DATABASE()
        AND table_name = 'auth_user_domain_access'
        AND column_name IN (
          'can_view_member_admin',
          'can_operate_member_admin',
          'can_view_billing',
          'can_operate_billing'
        )
    `
  );
  const existingDomainColumns = new Set(domainPermissionColumns.map((row) => row.column_name));
  const missingDomainColumnDefinitions = [
    ['can_view_member_admin', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['can_operate_member_admin', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['can_view_billing', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['can_operate_billing', 'TINYINT(1) NOT NULL DEFAULT 0']
  ].filter(([columnName]) => !existingDomainColumns.has(columnName));

  for (const [columnName, columnDefinition] of missingDomainColumnDefinitions) {
    await adminConnection.execute(
      `ALTER TABLE auth_user_domain_access ADD COLUMN ${columnName} ${columnDefinition}`
    );
  }

  await adminConnection.execute(
    `
      CREATE TABLE IF NOT EXISTS auth_user_tenants (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id VARCHAR(64) NOT NULL,
        tenant_id VARCHAR(64) NOT NULL,
        tenant_name VARCHAR(128) NULL,
        can_view_member_admin TINYINT(1) NOT NULL DEFAULT 0,
        can_operate_member_admin TINYINT(1) NOT NULL DEFAULT 0,
        can_view_billing TINYINT(1) NOT NULL DEFAULT 0,
        can_operate_billing TINYINT(1) NOT NULL DEFAULT 0,
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
        AND table_name = 'auth_user_tenants'
        AND column_name IN (
          'can_view_member_admin',
          'can_operate_member_admin',
          'can_view_billing',
          'can_operate_billing'
        )
    `
  );

  const existingColumns = new Set(tenantPermissionColumns.map((row) => row.column_name));
  const missingColumnDefinitions = [
    ['can_view_member_admin', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['can_operate_member_admin', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['can_view_billing', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['can_operate_billing', 'TINYINT(1) NOT NULL DEFAULT 0']
  ].filter(([columnName]) => !existingColumns.has(columnName));

  for (const [columnName, columnDefinition] of missingColumnDefinitions) {
    await adminConnection.execute(
      `ALTER TABLE auth_user_tenants ADD COLUMN ${columnName} ${columnDefinition}`
    );
  }

  await adminConnection.execute(
    `
      CREATE TABLE IF NOT EXISTS auth_user_platform_roles (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id VARCHAR(64) NOT NULL,
        role_id VARCHAR(64) NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'active',
        can_view_member_admin TINYINT(1) NOT NULL DEFAULT 0,
        can_operate_member_admin TINYINT(1) NOT NULL DEFAULT 0,
        can_view_billing TINYINT(1) NOT NULL DEFAULT 0,
        can_operate_billing TINYINT(1) NOT NULL DEFAULT 0,
        created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        PRIMARY KEY (id),
        UNIQUE KEY uk_auth_user_platform_roles_user_role (user_id, role_id),
        KEY idx_auth_user_platform_roles_user_status (user_id, status)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `
  );
};

const resetTestData = async () => {
  await adminConnection.execute('DELETE FROM auth_user_platform_roles WHERE user_id = ?', [
    TEST_USER.id
  ]);
  await adminConnection.execute('DELETE FROM auth_user_tenants WHERE user_id = ?', [TEST_USER.id]);
  await adminConnection.execute('DELETE FROM auth_user_domain_access WHERE user_id = ?', [TEST_USER.id]);
  await adminConnection.execute('DELETE FROM refresh_tokens WHERE user_id = ?', [TEST_USER.id]);
  await adminConnection.execute('DELETE FROM auth_sessions WHERE user_id = ?', [TEST_USER.id]);
  await adminConnection.execute('DELETE FROM users WHERE id = ? OR phone = ?', [
    TEST_USER.id,
    TEST_USER.phone
  ]);
};

const seedTestUser = async () => {
  await adminConnection.execute(
    `
      INSERT INTO users (id, phone, password_hash, status, session_version)
      VALUES (?, ?, ?, ?, 1)
    `,
    [TEST_USER.id, TEST_USER.phone, hashPassword(TEST_USER.password), TEST_USER.status]
  );

  await adminConnection.execute(
    `
      INSERT INTO auth_user_domain_access (user_id, domain, status)
      VALUES (?, 'platform', 'active')
      ON DUPLICATE KEY UPDATE status = VALUES(status), updated_at = CURRENT_TIMESTAMP(3)
    `,
    [TEST_USER.id]
  );
};

const seedTenantDomainAccess = async () => {
  await adminConnection.execute(
    `
      INSERT INTO auth_user_domain_access (user_id, domain, status)
      VALUES (?, 'tenant', 'active')
      ON DUPLICATE KEY UPDATE status = VALUES(status), updated_at = CURRENT_TIMESTAMP(3)
    `,
    [TEST_USER.id]
  );
};

const seedTenantOptions = async () => {
  await adminConnection.execute(
    `
      INSERT INTO auth_user_tenants (
        user_id,
        tenant_id,
        tenant_name,
        status,
        can_view_member_admin,
        can_operate_member_admin,
        can_view_billing,
        can_operate_billing
      )
      VALUES
        (?, 'tenant-a', 'Tenant A', 'active', 1, 1, 1, 0),
        (?, 'tenant-b', 'Tenant B', 'active', 0, 0, 1, 1)
      ON DUPLICATE KEY UPDATE
        tenant_name = VALUES(tenant_name),
        status = VALUES(status),
        can_view_member_admin = VALUES(can_view_member_admin),
        can_operate_member_admin = VALUES(can_operate_member_admin),
        can_view_billing = VALUES(can_view_billing),
        can_operate_billing = VALUES(can_operate_billing),
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [TEST_USER.id, TEST_USER.id]
  );
};

const seedPlatformRoleFacts = async ({
  roleId = 'platform-role-default',
  status = 'active',
  canViewMemberAdmin = 0,
  canOperateMemberAdmin = 0,
  canViewBilling = 0,
  canOperateBilling = 0
} = {}) => {
  await adminConnection.execute(
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
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        status = VALUES(status),
        can_view_member_admin = VALUES(can_view_member_admin),
        can_operate_member_admin = VALUES(can_operate_member_admin),
        can_view_billing = VALUES(can_view_billing),
        can_operate_billing = VALUES(can_operate_billing),
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [
      TEST_USER.id,
      roleId,
      status,
      Number(canViewMemberAdmin),
      Number(canOperateMemberAdmin),
      Number(canViewBilling),
      Number(canOperateBilling)
    ]
  );
};

const clearPlatformRoleFacts = async () => {
  await adminConnection.execute(
    `
      DELETE FROM auth_user_platform_roles
      WHERE user_id = ?
    `,
    [TEST_USER.id]
  );
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

const createExpressHarness = async () => {
  const app = await createApiApp(config, {
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
        FROM refresh_tokens
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
      can_view_member_admin: false,
      can_operate_member_admin: false,
      can_view_billing: false,
      can_operate_billing: false
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
      can_view_member_admin: false,
      can_operate_member_admin: false,
      can_view_billing: false,
      can_operate_billing: false
    });

    const selected = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/tenant/select',
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
      can_view_member_admin: true,
      can_operate_member_admin: true,
      can_view_billing: true,
      can_operate_billing: false
    });
    const memberAdminProbeAllowed = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/tenant/member-admin/probe',
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    assert.equal(memberAdminProbeAllowed.status, 200);
    assert.equal(memberAdminProbeAllowed.body.ok, true);
    assert.equal(typeof memberAdminProbeAllowed.body.request_id, 'string');

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
      can_view_member_admin: false,
      can_operate_member_admin: false,
      can_view_billing: true,
      can_operate_billing: true
    });
    const memberAdminProbeDenied = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/tenant/member-admin/probe',
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    assert.equal(memberAdminProbeDenied.status, 403);
    assert.equal(memberAdminProbeDenied.body.error_code, 'AUTH-403-FORBIDDEN');
    assert.equal(typeof memberAdminProbeDenied.body.request_id, 'string');

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
      can_view_member_admin: false,
      can_operate_member_admin: false,
      can_view_billing: true,
      can_operate_billing: true
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

    const memberAdminProbeNoDomain = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/tenant/member-admin/probe',
      headers: {
        authorization: `Bearer ${platformLogin.body.access_token}`
      }
    });
    assert.equal(memberAdminProbeNoDomain.status, 403);
    assert.equal(memberAdminProbeNoDomain.body.error_code, 'AUTH-403-NO-DOMAIN');
    assert.equal(typeof memberAdminProbeNoDomain.body.request_id, 'string');
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
      DELETE FROM auth_user_domain_access
      WHERE user_id = ? AND domain = 'platform'
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
        FROM auth_user_domain_access
        WHERE user_id = ? AND domain = 'platform'
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
      DELETE FROM auth_user_domain_access
      WHERE user_id = ? AND domain = 'platform'
    `,
    [TEST_USER.id]
  );
  await adminConnection.execute(
    `
      INSERT INTO auth_user_tenants (
        user_id,
        tenant_id,
        tenant_name,
        status,
        can_view_member_admin,
        can_operate_member_admin,
        can_view_billing,
        can_operate_billing
      )
      VALUES (?, ?, ?, 'disabled', 1, 0, 0, 0)
      ON DUPLICATE KEY UPDATE
        tenant_name = VALUES(tenant_name),
        status = VALUES(status),
        can_view_member_admin = VALUES(can_view_member_admin),
        can_operate_member_admin = VALUES(can_operate_member_admin),
        can_view_billing = VALUES(can_view_billing),
        can_operate_billing = VALUES(can_operate_billing),
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [TEST_USER.id, 'tenant-disabled', 'Tenant Disabled']
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
        FROM auth_user_domain_access
        WHERE user_id = ? AND domain = 'platform'
      `,
      [TEST_USER.id]
    );
    assert.equal(Number(platformDomainRows?.[0]?.row_count || 0), 0);
  } finally {
    await harness.close();
  }
});

test('express platform member-admin probe enforces no-domain, forbidden, and allow paths with mysql persistent auth store', async () => {
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
      path: '/auth/platform/member-admin/probe',
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
      path: '/auth/platform/member-admin/probe',
      headers: {
        authorization: `Bearer ${platformLogin.body.access_token}`
      }
    });
    assert.equal(platformProbeForbidden.status, 403);
    assert.equal(platformProbeForbidden.body.error_code, 'AUTH-403-FORBIDDEN');
    assert.equal(typeof platformProbeForbidden.body.request_id, 'string');

    await seedPlatformRoleFacts({
      roleId: 'platform-view-member-admin',
      canViewMemberAdmin: 1
    });
    const platformProbeAllowed = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/platform/member-admin/probe',
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

test('express platform member-admin probe revokes access after platform role facts are removed', async () => {
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
      roleId: 'platform-view-member-admin',
      canViewMemberAdmin: 1
    });

    const allowed = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/platform/member-admin/probe',
      headers: {
        authorization: `Bearer ${platformLogin.body.access_token}`
      }
    });
    assert.equal(allowed.status, 200);

    await clearPlatformRoleFacts();
    const revoked = await invokeRoute(harness, {
      method: 'get',
      path: '/auth/platform/member-admin/probe',
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

  await adminConnection.execute('DROP TABLE IF EXISTS refresh_tokens');
  await adminConnection.execute('DROP TABLE IF EXISTS auth_sessions');
  await adminConnection.execute('DROP TABLE IF EXISTS auth_user_platform_roles');
  await adminConnection.execute('DROP TABLE IF EXISTS auth_user_tenants');
  await adminConnection.execute('DROP TABLE IF EXISTS auth_user_domain_access');
  await adminConnection.execute('DROP TABLE IF EXISTS users');
  await adminConnection.execute(
    `
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(64) NOT NULL,
        phone VARCHAR(32) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'active',
        session_version INT UNSIGNED NOT NULL DEFAULT 1,
        created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        PRIMARY KEY (id),
        UNIQUE KEY uk_users_phone (phone)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `
  );
  await runMigrationSql(adminConnection, '0002_auth_sessions_refresh.sql');
  await runMigrationSql(adminConnection, '0003_auth_timestamp_precision.sql');
  await runMigrationSql(adminConnection, '0004_auth_session_domain_tenant_context.sql');
  await runMigrationSql(adminConnection, '0005_auth_domain_tenant_membership.sql');
  await runMigrationSql(adminConnection, '0006_auth_platform_permission_snapshot.sql');
  await runMigrationSql(adminConnection, '0007_auth_platform_role_facts.sql');
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
                { table_name: 'auth_user_domain_access' },
                { table_name: 'auth_user_tenants' },
                { table_name: 'auth_user_platform_roles' }
              ];
            }
            if (normalizedSql.includes('FROM information_schema.columns')) {
              const tableName = String(params[0] || '');
              if (tableName === 'auth_sessions') {
                return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'auth_user_domain_access') {
                return AUTH_DOMAIN_ACCESS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'auth_user_tenants') {
                return [
                  { column_name: 'user_id' },
                  { column_name: 'tenant_id' },
                  { column_name: 'tenant_name' },
                  { column_name: 'status' },
                  { column_name: 'can_view_member_admin' },
                  { column_name: 'can_operate_member_admin' },
                  { column_name: 'can_view_billing' },
                  { column_name: 'can_operate_billing' }
                ];
              }
              if (tableName === 'auth_user_platform_roles') {
                return AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS;
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
            { TABLE_NAME: 'auth_user_domain_access' },
            { TABLE_NAME: 'auth_user_tenants' },
            { TABLE_NAME: 'auth_user_platform_roles' }
          ];
        }
        if (normalizedSql.includes('FROM information_schema.columns')) {
          const tableName = String(params[0] || '');
          if (tableName === 'auth_sessions') {
            return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS_UPPER;
          }
          if (tableName === 'auth_user_domain_access') {
            return AUTH_DOMAIN_ACCESS_REQUIRED_COLUMN_ROWS_UPPER;
          }
          if (tableName === 'auth_user_tenants') {
            return [
              { COLUMN_NAME: 'user_id' },
              { COLUMN_NAME: 'tenant_id' },
              { COLUMN_NAME: 'tenant_name' },
              { COLUMN_NAME: 'status' },
              { COLUMN_NAME: 'can_view_member_admin' },
              { COLUMN_NAME: 'can_operate_member_admin' },
              { COLUMN_NAME: 'can_view_billing' },
              { COLUMN_NAME: 'can_operate_billing' }
            ];
          }
          if (tableName === 'auth_user_platform_roles') {
            return AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS_UPPER;
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
                { table_name: 'auth_user_tenants' },
                { table_name: 'auth_user_platform_roles' }
              ];
            }
            if (normalizedSql.includes('FROM information_schema.columns')) {
              const tableName = String(params[0] || '');
              if (tableName === 'auth_sessions') {
                return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'auth_user_domain_access') {
                return AUTH_DOMAIN_ACCESS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'auth_user_tenants') {
                return [
                  { column_name: 'user_id' },
                  { column_name: 'tenant_id' },
                  { column_name: 'tenant_name' },
                  { column_name: 'status' },
                  { column_name: 'can_view_member_admin' },
                  { column_name: 'can_operate_member_admin' },
                  { column_name: 'can_view_billing' },
                  { column_name: 'can_operate_billing' }
                ];
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
    /Auth schema preflight failed: missing tables: auth_user_domain_access/
  );

  assert.equal(dbCloseCalls, 1);
});

test('createApiApp fails fast when auth_user_platform_roles table is missing', async () => {
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
                { table_name: 'auth_user_domain_access' },
                { table_name: 'auth_user_tenants' }
              ];
            }
            if (normalizedSql.includes('FROM information_schema.columns')) {
              const tableName = String(params[0] || '');
              if (tableName === 'auth_sessions') {
                return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'auth_user_domain_access') {
                return AUTH_DOMAIN_ACCESS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'auth_user_tenants') {
                return [
                  { column_name: 'user_id' },
                  { column_name: 'tenant_id' },
                  { column_name: 'tenant_name' },
                  { column_name: 'status' },
                  { column_name: 'can_view_member_admin' },
                  { column_name: 'can_operate_member_admin' },
                  { column_name: 'can_view_billing' },
                  { column_name: 'can_operate_billing' }
                ];
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
    /Auth schema preflight failed: missing tables: auth_user_platform_roles/
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
    assert.equal(notFound.headers.get('access-control-allow-origin'), 'https://web.example');
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

    assert.equal(response.status, 500);
    assert.equal(payload.error_code, 'AUTH-500-INTERNAL');
    assert.equal(payload.request_id, requestId);
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
    /Route permission preflight failed: unknown permission codes: GET \/auth\/tenant\/member-admin\/probe \(unknown permission_code: tenant\.member_admin\.operat\)/
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
        path: '/auth/tenant/member-admin/probe',
        access: 'protected',
        permission_code: 'tenant.custom.read',
        scope: 'tenant'
      }
    ],
    executableRouteKeys: ['GET /health', 'GET /auth/tenant/member-admin/probe'],
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
    /Route permission preflight failed: incompatible permission scope declarations: GET \/auth\/tenant\/member-admin\/probe \(permission_code tenant\.member_admin\.operate incompatible with scope session; allowed scopes: tenant\)/
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
      && routeDefinition.path === '/auth/tenant/member-admin/probe'
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
    const response = await fetch(`http://127.0.0.1:${port}/auth/tenant/member-admin/probe`, {
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

test('createApiApp fails fast when auth_user_tenants permission columns are missing', async () => {
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
                { table_name: 'auth_user_domain_access' },
                { table_name: 'auth_user_tenants' },
                { table_name: 'auth_user_platform_roles' }
              ];
            }
            if (normalizedSql.includes('FROM information_schema.columns')) {
              const tableName = String(params[0] || '');
              if (tableName === 'auth_sessions') {
                return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'auth_user_domain_access') {
                return AUTH_DOMAIN_ACCESS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'auth_user_tenants') {
                return [
                  { column_name: 'user_id' },
                  { column_name: 'tenant_id' },
                  { column_name: 'tenant_name' },
                  { column_name: 'status' },
                  { column_name: 'can_view_member_admin' },
                  { column_name: 'can_operate_member_admin' }
                ];
              }
              if (tableName === 'auth_user_platform_roles') {
                return AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS;
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
    /Auth schema preflight failed: auth_user_tenants missing columns/
  );

  assert.equal(dbCloseCalls, 1);
});

test('createApiApp fails fast when auth_user_domain_access required columns are missing', async () => {
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
                { table_name: 'auth_user_domain_access' },
                { table_name: 'auth_user_tenants' },
                { table_name: 'auth_user_platform_roles' }
              ];
            }
            if (normalizedSql.includes('FROM information_schema.columns')) {
              const tableName = String(params[0] || '');
              if (tableName === 'auth_sessions') {
                return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'auth_user_domain_access') {
                return [
                  { column_name: 'user_id' },
                  { column_name: 'domain' },
                  { column_name: 'status' }
                ];
              }
              if (tableName === 'auth_user_tenants') {
                return [
                  { column_name: 'user_id' },
                  { column_name: 'tenant_id' },
                  { column_name: 'tenant_name' },
                  { column_name: 'status' },
                  { column_name: 'can_view_member_admin' },
                  { column_name: 'can_operate_member_admin' },
                  { column_name: 'can_view_billing' },
                  { column_name: 'can_operate_billing' }
                ];
              }
              if (tableName === 'auth_user_platform_roles') {
                return AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS;
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
    /Auth schema preflight failed: auth_user_domain_access missing columns: can_view_member_admin/
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
                { table_name: 'auth_user_domain_access' },
                { table_name: 'auth_user_tenants' },
                { table_name: 'auth_user_platform_roles' }
              ];
            }
            if (normalizedSql.includes('FROM information_schema.columns')) {
              const tableName = String(params[0] || '');
              if (tableName === 'auth_sessions') {
                return AUTH_SESSIONS_REQUIRED_COLUMN_ROWS_WITHOUT_ACTIVE_TENANT;
              }
              if (tableName === 'auth_user_domain_access') {
                return AUTH_DOMAIN_ACCESS_REQUIRED_COLUMN_ROWS;
              }
              if (tableName === 'auth_user_tenants') {
                return [
                  { column_name: 'user_id' },
                  { column_name: 'tenant_id' },
                  { column_name: 'tenant_name' },
                  { column_name: 'status' },
                  { column_name: 'can_view_member_admin' },
                  { column_name: 'can_operate_member_admin' },
                  { column_name: 'can_view_billing' },
                  { column_name: 'can_operate_billing' }
                ];
              }
              if (tableName === 'auth_user_platform_roles') {
                return AUTH_PLATFORM_ROLE_FACTS_REQUIRED_COLUMN_ROWS;
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

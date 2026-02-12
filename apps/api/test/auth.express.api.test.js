const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { pbkdf2Sync, randomBytes } = require('node:crypto');
const mysql = require('mysql2/promise');
const { createApiApp } = require('../src/app');
const { readConfig } = require('../src/config/env');

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

const TEST_USER = {
  id: 'it-user-active',
  phone: '13910000000',
  password: 'Passw0rd!',
  status: 'active'
};

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
};

const resetTestData = async () => {
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
          query: async () => [],
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

#!/usr/bin/env node
const { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } = require('node:fs');
const { dirname, isAbsolute, join, resolve } = require('node:path');
const { spawnSync } = require('node:child_process');
const { createCipheriv, pbkdf2Sync, randomBytes, randomUUID } = require('node:crypto');
const mysql = require('mysql2/promise');

const now = new Date();
const timestamp = now.toISOString().replace(/[:.]/g, '-');
const reportDir = 'artifacts/smoke';
const chromeRegressionDir = 'artifacts/chrome-regression';
const allowSkipWhenDockerUnavailable =
  String(process.env.SMOKE_ALLOW_DOCKER_UNAVAILABLE || 'false').toLowerCase() === 'true';
const composeUpMaxAttempts = Math.max(1, Number(process.env.SMOKE_DOCKER_COMPOSE_UP_ATTEMPTS || 3));
const composeUpRetryDelayMs = Math.max(
  1000,
  Number(process.env.SMOKE_DOCKER_COMPOSE_UP_RETRY_DELAY_MS || 5000)
);
const requireChromeEvidenceNotBeforeMs = Math.max(
  0,
  Number(process.env.SMOKE_REQUIRE_CHROME_EVIDENCE_NOT_BEFORE_MS || 0)
);
const runOnlineDrillEnabled =
  String(process.env.SMOKE_ENABLE_ONLINE_DRILL || 'true').toLowerCase() === 'true';
const forceProvisionConfigForOnlineDrill =
  String(process.env.SMOKE_ONLINE_DRILL_FORCE_PROVISION_CONFIG || 'true').toLowerCase() === 'true';
const onlineDrillOperatorPhone = String(
  process.env.SMOKE_ONLINE_DRILL_OPERATOR_PHONE || '13800009000'
).trim();
const onlineDrillOperatorPassword = String(
  process.env.SMOKE_ONLINE_DRILL_OPERATOR_PASSWORD || 'Passw0rd!'
);
const onlineDrillTargetDefaultPassword = String(
  process.env.SMOKE_ONLINE_DRILL_TARGET_DEFAULT_PASSWORD || 'InitPass!2026'
);
const onlineDrillDbConfig = Object.freeze({
  host: String(process.env.SMOKE_ONLINE_DRILL_DB_HOST || '127.0.0.1').trim() || '127.0.0.1',
  port: Math.max(1, Number(process.env.SMOKE_ONLINE_DRILL_DB_PORT || 3306)),
  user: String(process.env.SMOKE_ONLINE_DRILL_DB_USER || 'neweast').trim() || 'neweast',
  password: String(process.env.SMOKE_ONLINE_DRILL_DB_PASSWORD || 'neweast'),
  database: String(process.env.SMOKE_ONLINE_DRILL_DB_NAME || 'neweast').trim() || 'neweast'
});
const onlineDrillApiBaseUrl = String(
  process.env.SMOKE_ONLINE_DRILL_API_BASE_URL || 'http://127.0.0.1:3000'
).trim().replace(/\/+$/, '') || 'http://127.0.0.1:3000';

const PBKDF2_ITERATIONS = 150000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';
const SENSITIVE_CONFIG_ENVELOPE_VERSION = 'enc:v1';
const SENSITIVE_CONFIG_KEY_DERIVATION_ITERATIONS = 210000;
const SENSITIVE_CONFIG_KEY_DERIVATION_SALT = 'auth.default_password';
mkdirSync(reportDir, { recursive: true });

const getLatestChromeRegressionArtifact = (targetDir = chromeRegressionDir) => {
  if (!existsSync(targetDir)) {
    return null;
  }

  const candidates = readdirSync(targetDir)
    .filter((name) => /^chrome-regression-.*\.json$/.test(name))
    .map((name) => ({
      path: join(targetDir, name),
      mtimeMs: statSync(join(targetDir, name)).mtimeMs
    }))
    .sort((a, b) => b.mtimeMs - a.mtimeMs);

  if (candidates.length === 0) {
    return null;
  }

  const latest = candidates[0];
  let parsed = {};
  try {
    parsed = JSON.parse(readFileSync(latest.path, 'utf8'));
  } catch (_error) {
    parsed = {};
  }

  return {
    report: latest.path,
    mtimeMs: latest.mtimeMs,
    generated_at: parsed.generated_at || null,
    screenshots: Array.isArray(parsed.screenshots) ? parsed.screenshots : []
  };
};

const normalizeExitStatus = (status, signal) => {
  if (typeof status === 'number') {
    return status;
  }
  if (typeof signal === 'string' && signal.length > 0) {
    return 1;
  }
  return 1;
};

const runCommand = (command, args, env = process.env) => {
  const result = spawnSync(command, args, {
    stdio: 'pipe',
    encoding: 'utf8',
    env
  });

  return {
    status: normalizeExitStatus(result.status, result.signal),
    signal: result.signal || null,
    stdout: result.stdout || '',
    stderr: result.stderr || ''
  };
};

const deriveSensitiveConfigKey = (rawKey) => {
  const normalizedRawKey = String(rawKey || '').trim();
  if (!normalizedRawKey) {
    return null;
  }
  if (/^[0-9a-f]{64}$/i.test(normalizedRawKey)) {
    return Buffer.from(normalizedRawKey, 'hex');
  }
  return pbkdf2Sync(
    normalizedRawKey,
    SENSITIVE_CONFIG_KEY_DERIVATION_SALT,
    SENSITIVE_CONFIG_KEY_DERIVATION_ITERATIONS,
    32,
    'sha256'
  );
};

const buildEncryptedSensitiveConfigValue = ({
  plainText,
  decryptionKey
}) => {
  const key = deriveSensitiveConfigKey(decryptionKey);
  if (!key) {
    throw new Error('Unable to derive provisioning config key');
  }
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const cipherText = Buffer.concat([
    cipher.update(String(plainText || ''), 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  return [
    SENSITIVE_CONFIG_ENVELOPE_VERSION,
    iv.toString('base64url'),
    authTag.toString('base64url'),
    cipherText.toString('base64url')
  ].join(':');
};

const resolveSmokeComposeEnvironment = (
  sourceEnv = process.env,
  {
    forceProvisionConfig = forceProvisionConfigForOnlineDrill,
    targetDefaultPassword = onlineDrillTargetDefaultPassword
  } = {}
) => {
  const resolvedEnv = {
    ...sourceEnv
  };
  const existingEncryptedConfig = String(
    resolvedEnv.AUTH_DEFAULT_PASSWORD_ENCRYPTED || ''
  ).trim();
  const existingDecryptionKey = String(
    resolvedEnv.AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY || ''
  ).trim();
  const shouldGenerateProvisionConfig =
    forceProvisionConfig
    || !existingEncryptedConfig
    || !existingDecryptionKey;

  if (!shouldGenerateProvisionConfig) {
    return {
      env: resolvedEnv,
      generatedProvisionConfig: false,
      targetDefaultPassword
    };
  }

  const generatedDecryptionKey = randomBytes(32).toString('hex');
  resolvedEnv.AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY = generatedDecryptionKey;
  resolvedEnv.AUTH_DEFAULT_PASSWORD_ENCRYPTED = buildEncryptedSensitiveConfigValue({
    plainText: targetDefaultPassword,
    decryptionKey: generatedDecryptionKey
  });
  return {
    env: resolvedEnv,
    generatedProvisionConfig: true,
    targetDefaultPassword
  };
};

const hashSeedPassword = (plainTextPassword) => {
  const salt = randomBytes(16).toString('hex');
  const derived = pbkdf2Sync(
    String(plainTextPassword || ''),
    salt,
    PBKDF2_ITERATIONS,
    PBKDF2_KEYLEN,
    PBKDF2_DIGEST
  ).toString('hex');
  return `pbkdf2$${PBKDF2_DIGEST}$${PBKDF2_ITERATIONS}$${salt}$${derived}`;
};

const ensureUsersTable = async (connection) => {
  await connection.query(
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
};

const ensureAuthDomainPermissionColumns = async (connection) => {
  const [rows] = await connection.query(
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
  const existingColumns = new Set(
    (Array.isArray(rows) ? rows : []).map((row) => String(row?.column_name || ''))
  );
  const missingColumnDefinitions = [
    ['can_view_member_admin', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['can_operate_member_admin', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['can_view_billing', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['can_operate_billing', 'TINYINT(1) NOT NULL DEFAULT 0']
  ].filter(([columnName]) => !existingColumns.has(columnName));

  for (const [columnName, definition] of missingColumnDefinitions) {
    await connection.query(
      `ALTER TABLE auth_user_domain_access ADD COLUMN ${columnName} ${definition}`
    );
  }
};

const bootstrapOnlineDrillOperator = async ({
  connection,
  operatorPhone,
  operatorPassword
}) => {
  const operatorUserId = 'smoke-platform-operator';
  const operatorPasswordHash = hashSeedPassword(operatorPassword);

  await ensureUsersTable(connection);
  await ensureAuthDomainPermissionColumns(connection);

  await connection.query(
    `
      INSERT INTO users (id, phone, password_hash, status, session_version)
      VALUES (?, ?, ?, 'active', 1)
      ON DUPLICATE KEY UPDATE
        phone = VALUES(phone),
        password_hash = VALUES(password_hash),
        status = 'active',
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [operatorUserId, operatorPhone, operatorPasswordHash]
  );

  await connection.query(
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
      VALUES (?, 'platform', 'active', 1, 1, 0, 0)
      ON DUPLICATE KEY UPDATE
        status = 'active',
        can_view_member_admin = 1,
        can_operate_member_admin = 1,
        can_view_billing = 0,
        can_operate_billing = 0,
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [operatorUserId]
  );

  await connection.query(
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
      VALUES (?, '__smoke_platform_member_admin__', 'active', 1, 1, 0, 0)
      ON DUPLICATE KEY UPDATE
        status = 'active',
        can_view_member_admin = 1,
        can_operate_member_admin = 1,
        can_view_billing = 0,
        can_operate_billing = 0,
        updated_at = CURRENT_TIMESTAMP(3)
    `,
    [operatorUserId]
  );

  await connection.query(
    `
      UPDATE auth_sessions
      SET status = 'revoked',
          revoked_reason = 'online-drill-bootstrap',
          updated_at = CURRENT_TIMESTAMP(3)
      WHERE user_id = ? AND status = 'active'
    `,
    [operatorUserId]
  );
  await connection.query(
    `
      UPDATE refresh_tokens
      SET status = 'revoked',
          updated_at = CURRENT_TIMESTAMP(3)
      WHERE user_id = ? AND status = 'active'
    `,
    [operatorUserId]
  );

  return {
    operatorUserId,
    operatorPhone
  };
};

const toApiUrl = (path) => `${onlineDrillApiBaseUrl}${String(path || '')}`;

const callApi = async ({
  method = 'GET',
  path = '/',
  headers = {},
  body = null
}) => {
  const requestHeaders = {
    ...headers
  };
  if (body !== null && body !== undefined) {
    requestHeaders['content-type'] = 'application/json';
  }
  const response = await fetch(toApiUrl(path), {
    method,
    headers: requestHeaders,
    body:
      body === null || body === undefined
        ? undefined
        : JSON.stringify(body)
  });
  const rawText = await response.text();
  let payload = null;
  try {
    payload = rawText ? JSON.parse(rawText) : null;
  } catch (_error) {
    payload = {
      raw: rawText
    };
  }
  return {
    status: Number(response.status),
    payload
  };
};

const assertApiResponse = (condition, message, apiResponse) => {
  if (condition) {
    return;
  }
  throw new Error(
    `${message} (status=${apiResponse?.status}, payload=${JSON.stringify(apiResponse?.payload || null)})`
  );
};

const createTargetPhone = () => {
  const suffix = String(randomBytes(4).readUInt32BE(0) % 100000000).padStart(8, '0');
  return `139${suffix}`;
};

const runOnlineEnvironmentDrill = async ({
  artifacts,
  targetDefaultPassword
}) => {
  const connection = await mysql.createConnection({
    host: onlineDrillDbConfig.host,
    port: onlineDrillDbConfig.port,
    user: onlineDrillDbConfig.user,
    password: onlineDrillDbConfig.password,
    database: onlineDrillDbConfig.database
  });
  let operatorSeed;
  try {
    operatorSeed = await bootstrapOnlineDrillOperator({
      connection,
      operatorPhone: onlineDrillOperatorPhone,
      operatorPassword: onlineDrillOperatorPassword
    });
  } finally {
    await connection.end();
  }

  const loginOperator = await callApi({
    method: 'POST',
    path: '/auth/login',
    body: {
      phone: operatorSeed.operatorPhone,
      password: onlineDrillOperatorPassword,
      entry_domain: 'platform'
    }
  });
  artifacts.steps.push({
    step: 'online drill: login platform operator',
    status: loginOperator.status
  });
  assertApiResponse(
    loginOperator.status === 200 && typeof loginOperator.payload?.access_token === 'string',
    'online drill operator login failed',
    loginOperator
  );

  const operatorAccessToken = loginOperator.payload.access_token;
  const probe = await callApi({
    method: 'GET',
    path: '/auth/platform/member-admin/probe',
    headers: {
      authorization: `Bearer ${operatorAccessToken}`
    }
  });
  artifacts.steps.push({
    step: 'online drill: probe platform member-admin capability',
    status: probe.status
  });
  assertApiResponse(probe.status === 200 && probe.payload?.ok === true, 'online drill probe failed', probe);

  const targetPhone = createTargetPhone();
  const createIdempotencyKey = randomUUID();
  const createTargetUser = await callApi({
    method: 'POST',
    path: '/platform/users',
    headers: {
      authorization: `Bearer ${operatorAccessToken}`,
      'idempotency-key': createIdempotencyKey
    },
    body: {
      phone: targetPhone
    }
  });
  artifacts.steps.push({
    step: 'online drill: create platform user',
    status: createTargetUser.status
  });
  assertApiResponse(
    createTargetUser.status === 200 && typeof createTargetUser.payload?.user_id === 'string',
    'online drill platform user creation failed',
    createTargetUser
  );
  const targetUserId = String(createTargetUser.payload.user_id);

  const replayCreateTargetUser = await callApi({
    method: 'POST',
    path: '/platform/users',
    headers: {
      authorization: `Bearer ${operatorAccessToken}`,
      'idempotency-key': createIdempotencyKey
    },
    body: {
      phone: targetPhone
    }
  });
  artifacts.steps.push({
    step: 'online drill: replay create platform user',
    status: replayCreateTargetUser.status
  });
  assertApiResponse(
    replayCreateTargetUser.status === 200
      && replayCreateTargetUser.payload?.user_id === targetUserId,
    'online drill create replay consistency failed',
    replayCreateTargetUser
  );

  const conflictCreateTargetUser = await callApi({
    method: 'POST',
    path: '/platform/users',
    headers: {
      authorization: `Bearer ${operatorAccessToken}`,
      'idempotency-key': createIdempotencyKey
    },
    body: {
      phone: createTargetPhone()
    }
  });
  artifacts.steps.push({
    step: 'online drill: conflict create with same idempotency key',
    status: conflictCreateTargetUser.status
  });
  assertApiResponse(
    conflictCreateTargetUser.status === 409
      && conflictCreateTargetUser.payload?.error_code === 'AUTH-409-IDEMPOTENCY-CONFLICT',
    'online drill idempotency conflict validation failed',
    conflictCreateTargetUser
  );

  const disableStatusIdempotencyKey = randomUUID();
  const disableTargetUser = await callApi({
    method: 'POST',
    path: '/platform/users/status',
    headers: {
      authorization: `Bearer ${operatorAccessToken}`,
      'idempotency-key': disableStatusIdempotencyKey
    },
    body: {
      user_id: targetUserId,
      status: 'disabled',
      reason: 'online-drill-disable'
    }
  });
  artifacts.steps.push({
    step: 'online drill: disable target platform user',
    status: disableTargetUser.status
  });
  assertApiResponse(
    disableTargetUser.status === 200
      && disableTargetUser.payload?.current_status === 'disabled',
    'online drill disable user failed',
    disableTargetUser
  );

  const loginDisabledTarget = await callApi({
    method: 'POST',
    path: '/auth/login',
    body: {
      phone: targetPhone,
      password: targetDefaultPassword,
      entry_domain: 'platform'
    }
  });
  artifacts.steps.push({
    step: 'online drill: target user login blocked after disable',
    status: loginDisabledTarget.status
  });
  assertApiResponse(
    loginDisabledTarget.status === 403
      && loginDisabledTarget.payload?.error_code === 'AUTH-403-NO-DOMAIN',
    'online drill disable effect validation failed',
    loginDisabledTarget
  );

  const enableTargetUser = await callApi({
    method: 'POST',
    path: '/platform/users/status',
    headers: {
      authorization: `Bearer ${operatorAccessToken}`,
      'idempotency-key': randomUUID()
    },
    body: {
      user_id: targetUserId,
      status: 'active',
      reason: 'online-drill-enable'
    }
  });
  artifacts.steps.push({
    step: 'online drill: enable target platform user',
    status: enableTargetUser.status
  });
  assertApiResponse(
    enableTargetUser.status === 200
      && enableTargetUser.payload?.current_status === 'active',
    'online drill enable user failed',
    enableTargetUser
  );

  const loginEnabledTarget = await callApi({
    method: 'POST',
    path: '/auth/login',
    body: {
      phone: targetPhone,
      password: targetDefaultPassword,
      entry_domain: 'platform'
    }
  });
  artifacts.steps.push({
    step: 'online drill: target user login restored after enable',
    status: loginEnabledTarget.status
  });
  assertApiResponse(
    loginEnabledTarget.status === 200 && typeof loginEnabledTarget.payload?.access_token === 'string',
    'online drill enable effect validation failed',
    loginEnabledTarget
  );

  return {
    enabled: true,
    passed: true,
    operator_user_id: operatorSeed.operatorUserId,
    target_user_id: targetUserId,
    target_phone: targetPhone,
    create_request_id: createTargetUser.payload?.request_id || null,
    disable_request_id: disableTargetUser.payload?.request_id || null,
    enable_request_id: enableTargetUser.payload?.request_id || null
  };
};

const resolveChromeEvidence = (
  notBeforeMs = 0,
  evidenceProvider = getLatestChromeRegressionArtifact
) => {
  const chromeEvidence = evidenceProvider();
  if (!chromeEvidence) {
    throw new Error(
      'Missing Chrome regression evidence in artifacts/chrome-regression. Run `pnpm --dir apps/web run smoke` first.'
    );
  }

  if (Number(notBeforeMs) > 0 && chromeEvidence.mtimeMs < Number(notBeforeMs)) {
    throw new Error(
      `Stale Chrome regression evidence detected (${chromeEvidence.report}). Run web smoke in this session before workspace smoke.`
    );
  }

  const screenshots = Array.isArray(chromeEvidence.screenshots)
    ? chromeEvidence.screenshots
    : [];
  if (screenshots.length === 0) {
    throw new Error(
      `Chrome regression evidence must include at least one screenshot: ${chromeEvidence.report}`
    );
  }

  for (const screenshot of screenshots) {
    const screenshotPath = isAbsolute(screenshot)
      ? screenshot
      : resolve(dirname(chromeEvidence.report), screenshot);
    if (!existsSync(screenshotPath)) {
      throw new Error(`Chrome regression screenshot is missing: ${screenshotPath}`);
    }

    const screenshotStats = statSync(screenshotPath);
    if (screenshotStats.size <= 0) {
      throw new Error(`Chrome regression screenshot is empty: ${screenshotPath}`);
    }
  }

  return chromeEvidence;
};

const waitForUrl = async (url, timeoutMs) => {
  const started = Date.now();
  let lastError = 'unknown';

  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return response;
      }
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error.message;
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 1000));
  }

  throw new Error(`Timeout waiting for ${url}: ${lastError}`);
};

const sleep = (ms) => new Promise((resolveDelay) => setTimeout(resolveDelay, ms));

const isTransientComposeUpFailure = (output) => {
  const normalized = output.toLowerCase();
  return (
    normalized.includes('tls handshake timeout') ||
    normalized.includes('i/o timeout') ||
    normalized.includes('connection reset by peer') ||
    normalized.includes('temporary failure') ||
    normalized.includes('service unavailable') ||
    normalized.includes('toomanyrequests')
  );
};

const runDockerSmoke = async (artifacts) => {
  const composeEnvironmentResolution = runOnlineDrillEnabled
    ? resolveSmokeComposeEnvironment(process.env)
    : {
      env: {
        ...process.env
      },
      generatedProvisionConfig: false,
      targetDefaultPassword: onlineDrillTargetDefaultPassword
    };
  const composeEnv = composeEnvironmentResolution.env;
  artifacts.online_drill = {
    enabled: runOnlineDrillEnabled,
    generated_provision_config: composeEnvironmentResolution.generatedProvisionConfig
  };

  let composeUp = null;
  let composeStarted = false;
  for (let attempt = 1; attempt <= composeUpMaxAttempts; attempt += 1) {
    composeUp = runCommand('docker', ['compose', 'up', '-d', '--build'], composeEnv);
    artifacts.steps.push({
      step: `docker compose up -d --build (attempt ${attempt}/${composeUpMaxAttempts})`,
      ...composeUp
    });

    if (composeUp.status === 0) {
      composeStarted = true;
      break;
    }

    const output = `${composeUp.stderr}\n${composeUp.stdout}`;
    const unavailable =
      output.includes('Cannot connect to the Docker daemon') ||
      output.includes('docker daemon') ||
      output.includes('Is the docker daemon running');

    if (unavailable) {
      return { skipped: true, reason: output.trim() };
    }

    const transientFailure = isTransientComposeUpFailure(output);
    if (!transientFailure || attempt === composeUpMaxAttempts) {
      throw new Error(`docker compose up failed: ${output}`);
    }

    const composeDown = runCommand('docker', ['compose', 'down', '--remove-orphans'], composeEnv);
    artifacts.steps.push({
      step: `docker compose down --remove-orphans (after failed attempt ${attempt})`,
      ...composeDown
    });
    await sleep(composeUpRetryDelayMs * attempt);
  }

  try {
    const migrationRun = runCommand(
      'docker',
      [
        'compose',
        'exec',
        '-T',
        'api',
        'node',
        'apps/api/scripts/migrate-baseline.js'
      ],
      composeEnv
    );
    artifacts.steps.push({ step: 'docker compose exec -T api migrate-baseline', ...migrationRun });
    if (migrationRun.status !== 0) {
      throw new Error(`migration failed: ${migrationRun.stderr || migrationRun.stdout}`);
    }

    const apiHealthResponse = await waitForUrl('http://127.0.0.1:3000/health', 120000);
    const apiHealth = await apiHealthResponse.json();

    const webSmokeResponse = await waitForUrl('http://127.0.0.1:4173/smoke', 120000);
    const webSmoke = await webSmokeResponse.json();

    artifacts.execution_mode = 'docker-compose';
    artifacts.api_status = apiHealthResponse.status;
    artifacts.api_payload = apiHealth;
    artifacts.web_status = webSmokeResponse.status;
    artifacts.web_payload = webSmoke;

    if (!runOnlineDrillEnabled) {
      artifacts.online_drill = {
        ...artifacts.online_drill,
        enabled: false,
        skipped: true,
        reason: 'SMOKE_ENABLE_ONLINE_DRILL=false'
      };
    } else {
      const onlineDrillResult = await runOnlineEnvironmentDrill({
        artifacts,
        targetDefaultPassword: composeEnvironmentResolution.targetDefaultPassword
      });
      artifacts.online_drill = {
        ...artifacts.online_drill,
        ...onlineDrillResult
      };
    }

    const passed =
      apiHealthResponse.status === 200 &&
      apiHealth.ok === true &&
      apiHealth.dependencies?.db?.ok === true &&
      apiHealth.dependencies?.redis?.ok === true &&
      webSmokeResponse.status === 200 &&
      webSmoke.ok === true &&
      artifacts.online_drill?.passed !== false;

    return { skipped: false, passed };
  } finally {
    if (composeStarted) {
      const composeDown = runCommand('docker', ['compose', 'down'], composeEnv);
      artifacts.steps.push({ step: 'docker compose down', ...composeDown });
    }
  }
};

const run = async () => {
  const chromeEvidence = resolveChromeEvidence(requireChromeEvidenceNotBeforeMs);

  const artifacts = {
    generated_at: now.toISOString(),
    chain: 'web -> api -> db/redis',
    chrome_regression: chromeEvidence,
    steps: []
  };

  const dockerResult = await runDockerSmoke(artifacts);
  
  if (dockerResult.skipped) {
    artifacts.execution_mode = 'docker-compose';
    artifacts.skipped = true;
    artifacts.passed = false;
    artifacts.skip_reason = dockerResult.reason;

    writeFileSync(join(reportDir, `smoke-${timestamp}.json`), JSON.stringify(artifacts, null, 2));

    if (allowSkipWhenDockerUnavailable) {
      console.warn('Smoke skipped: Docker environment unavailable.');
      console.warn(`Reason: ${dockerResult.reason}`);
      console.warn(`Report: ${join(reportDir, `smoke-${timestamp}.json`)}`);
      return;
    }

    throw new Error(`Smoke failed: Docker environment unavailable. Reason: ${dockerResult.reason}`);
  }

  const passed = dockerResult.passed;
  artifacts.passed = passed;

  writeFileSync(join(reportDir, `smoke-${timestamp}.json`), JSON.stringify(artifacts, null, 2));
  writeFileSync(
    join(reportDir, `smoke-${timestamp}.log`),
    [
      `mode=${artifacts.execution_mode || 'unknown'}`,
      `api_status=${artifacts.api_status}`,
      `web_status=${artifacts.web_status}`,
      `online_drill=${artifacts.online_drill?.enabled === false ? 'disabled' : artifacts.online_drill?.passed === true ? 'passed' : 'failed'}`,
      `request_id=${artifacts.web_payload?.request_id || artifacts.api_payload?.request_id || 'n/a'}`,
      `passed=${passed}`
    ].join('\n') + '\n'
  );

  if (!passed) {
    throw new Error('Smoke validation failed');
  }

  console.log(`Smoke passed. Report: ${join(reportDir, `smoke-${timestamp}.json`)}`);
};

if (require.main === module) {
  run().catch((error) => {
    const failure = {
      generated_at: now.toISOString(),
      passed: false,
      error: error.message
    };
    writeFileSync(join(reportDir, `smoke-${timestamp}.json`), JSON.stringify(failure, null, 2));
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  });
}

module.exports = {
  buildEncryptedSensitiveConfigValue,
  deriveSensitiveConfigKey,
  getLatestChromeRegressionArtifact,
  normalizeExitStatus,
  resolveSmokeComposeEnvironment,
  resolveChromeEvidence
};

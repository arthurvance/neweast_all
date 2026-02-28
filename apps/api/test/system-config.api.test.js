const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createCipheriv,
  pbkdf2Sync,
  randomBytes
} = require('node:crypto');
const { createRouteHandlers } = require('../src/http-routes');
const { createAuthService } = require('../src/shared-kernel/auth/create-auth-service');
const { dispatchApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
const dependencyProbe = async () => ({
  db: { ok: true },
  redis: { ok: true }
});

const deriveSensitiveConfigKey = (decryptionKey) =>
  pbkdf2Sync(String(decryptionKey || ''), 'auth.default_password', 210000, 32, 'sha256');

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

const OPERATOR_PHONE = '13837770001';
const VIEWER_PHONE = '13837770002';
const USER_MANAGEMENT_ONLY_PHONE = '13837770003';
const RUNTIME_AUTH_NUMERIC_CONFIG = Object.freeze({
  accessTtlSeconds: 900,
  refreshTtlSeconds: 604800,
  otpTtlSeconds: 900,
  rateLimitWindowSeconds: 60,
  rateLimitMaxAttempts: 10
});

const createHarness = () => {
  const authService = createAuthService({
    ...RUNTIME_AUTH_NUMERIC_CONFIG,
    seedUsers: [
      {
        id: 'system-config-operator',
        phone: OPERATOR_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'system-config-operate',
            status: 'active',
            permission: {
              canViewUserManagement: true,
              canOperateUserManagement: true,
              canViewTenantManagement: false,
              canOperateTenantManagement: false,
              canViewRoleManagement: true,
              canOperateRoleManagement: true
            }
          }
        ]
      },
      {
        id: 'system-config-viewer',
        phone: VIEWER_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'system-config-view-only',
            status: 'active',
            permission: {
              canViewUserManagement: true,
              canOperateUserManagement: false,
              canViewTenantManagement: false,
              canOperateTenantManagement: false,
              canViewRoleManagement: true,
              canOperateRoleManagement: false
            }
          }
        ]
      },
      {
        id: 'system-config-user-management-only',
        phone: USER_MANAGEMENT_ONLY_PHONE,
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'user-management-only',
            status: 'active',
            permission: {
              canViewUserManagement: true,
              canOperateUserManagement: true,
              canViewTenantManagement: false,
              canOperateTenantManagement: false,
              canViewRoleManagement: false,
              canOperateRoleManagement: false
            }
          }
        ]
      }
    ]
  });
  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService
  });
  return {
    authService,
    handlers
  };
};

const loginByPhone = async ({
  authService,
  phone,
  requestId
}) =>
  authService.login({
    requestId,
    phone,
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

test('PUT/GET /platform/system-configs/:key supports authorized write/read and audit trace linkage', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-system-config-login-operator'
  });
  const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

  const encryptedValue = buildEncryptedSensitiveConfigValue({
    plainText: 'Secure#Pass123',
    decryptionKey: 'system-config-test-key'
  });
  const updateRoute = await dispatchApiRoute({
    pathname: '/platform/system-configs/auth.default_password',
    method: 'PUT',
    requestId: 'req-system-config-update-success',
    headers: {
      authorization: `Bearer ${login.access_token}`,
      traceparent
    },
    body: {
      value: encryptedValue,
      expected_version: 0
    },
    handlers: harness.handlers
  });
  assert.equal(updateRoute.status, 200);
  const updatePayload = JSON.parse(updateRoute.body);
  assert.equal(updatePayload.data.key, 'auth.default_password');
  assert.equal(updatePayload.data.previous_version, 0);
  assert.equal(updatePayload.data.version, 1);
  assert.equal(updatePayload.data.status, 'active');
  assert.equal(
    Object.prototype.hasOwnProperty.call(updatePayload.data, 'value'),
    false
  );

  const getRoute = await dispatchApiRoute({
    pathname: '/platform/system-configs/auth.default_password',
    method: 'GET',
    requestId: 'req-system-config-get-success',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(getRoute.status, 200);
  const getPayload = JSON.parse(getRoute.body);
  assert.equal(getPayload.data.key, 'auth.default_password');
  assert.equal(getPayload.data.version, 1);
  assert.equal(
    Object.prototype.hasOwnProperty.call(getPayload.data, 'value'),
    false
  );

  const auditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-system-config-update-success&event_type=auth.system_config.updated',
    method: 'GET',
    requestId: 'req-system-config-audit-query',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(auditRoute.status, 200);
  const auditPayload = JSON.parse(auditRoute.body);
  assert.equal(auditPayload.total, 1);
  assert.equal(auditPayload.events[0].event_type, 'auth.system_config.updated');
  assert.equal(auditPayload.events[0].request_id, 'req-system-config-update-success');
  assert.equal(auditPayload.events[0].traceparent, traceparent);
});

test('PUT /platform/system-configs/:key rejects version conflict with 409 problem details', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-system-config-login-conflict'
  });
  const encryptedValue = buildEncryptedSensitiveConfigValue({
    plainText: 'Secure#Pass123',
    decryptionKey: 'system-config-conflict-key'
  });

  const first = await dispatchApiRoute({
    pathname: '/platform/system-configs/auth.default_password',
    method: 'PUT',
    requestId: 'req-system-config-conflict-first',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      value: encryptedValue,
      expected_version: 0
    },
    handlers: harness.handlers
  });
  assert.equal(first.status, 200);

  const second = await dispatchApiRoute({
    pathname: '/platform/system-configs/auth.default_password',
    method: 'PUT',
    requestId: 'req-system-config-conflict-second',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      value: encryptedValue,
      expected_version: 0
    },
    handlers: harness.handlers
  });
  assert.equal(second.status, 409);
  assert.equal(second.headers['content-type'], 'application/problem+json');
  const payload = JSON.parse(second.body);
  assert.equal(payload.error_code, 'SYSCFG-409-VERSION-CONFLICT');
  assert.equal(payload.expected_version, 0);
  assert.equal(payload.current_version, 1);

  const auditRoute = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-system-config-conflict-second&event_type=auth.system_config.update.rejected',
    method: 'GET',
    requestId: 'req-system-config-conflict-audit',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(auditRoute.status, 200);
  const auditPayload = JSON.parse(auditRoute.body);
  assert.equal(auditPayload.total, 1);
  assert.equal(auditPayload.events[0].event_type, 'auth.system_config.update.rejected');
  assert.equal(auditPayload.events[0].request_id, 'req-system-config-conflict-second');
});

test('PUT /platform/system-configs/:key rejects unauthorized operator', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: VIEWER_PHONE,
    requestId: 'req-system-config-login-viewer'
  });
  const encryptedValue = buildEncryptedSensitiveConfigValue({
    plainText: 'Secure#Pass123',
    decryptionKey: 'system-config-forbidden-key'
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/system-configs/auth.default_password',
    method: 'PUT',
    requestId: 'req-system-config-forbidden',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      value: encryptedValue,
      expected_version: 0
    },
    handlers: harness.handlers
  });
  assert.equal(route.status, 403);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
});

test('GET /platform/system-configs/:key rejects user-management without system-config grant', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: USER_MANAGEMENT_ONLY_PHONE,
    requestId: 'req-system-config-login-user-management-only'
  });

  const route = await dispatchApiRoute({
    pathname: '/platform/system-configs/auth.default_password',
    method: 'GET',
    requestId: 'req-system-config-user-management-only-forbidden',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(route.status, 403);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-403-FORBIDDEN');
});

test('PUT /platform/system-configs/:key rejects unknown key and invalid payload', async () => {
  const harness = createHarness();
  const login = await loginByPhone({
    authService: harness.authService,
    phone: OPERATOR_PHONE,
    requestId: 'req-system-config-login-invalid'
  });

  const unknownKey = await dispatchApiRoute({
    pathname: '/platform/system-configs/auth.unknown_key',
    method: 'PUT',
    requestId: 'req-system-config-invalid-key',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      value: 'enc:v1:iv:tag:cipher',
      expected_version: 0
    },
    handlers: harness.handlers
  });
  assert.equal(unknownKey.status, 400);
  assert.equal(JSON.parse(unknownKey.body).error_code, 'SYSCFG-400-INVALID-PAYLOAD');
  const unknownKeyAudit = await dispatchApiRoute({
    pathname: '/platform/audit/events?request_id=req-system-config-invalid-key&event_type=auth.system_config.update.rejected',
    method: 'GET',
    requestId: 'req-system-config-invalid-key-audit',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    handlers: harness.handlers
  });
  assert.equal(unknownKeyAudit.status, 200);
  const unknownKeyAuditPayload = JSON.parse(unknownKeyAudit.body);
  assert.equal(unknownKeyAuditPayload.total, 1);
  assert.equal(unknownKeyAuditPayload.events[0].event_type, 'auth.system_config.update.rejected');
  assert.equal(unknownKeyAuditPayload.events[0].request_id, 'req-system-config-invalid-key');
  assert.equal(unknownKeyAuditPayload.events[0].target_id, 'auth.unknown_key');

  const invalidPayload = await dispatchApiRoute({
    pathname: '/platform/system-configs/auth.default_password',
    method: 'PUT',
    requestId: 'req-system-config-invalid-payload',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      value: '',
      expected_version: 'not-integer'
    },
    handlers: harness.handlers
  });
  assert.equal(invalidPayload.status, 400);
  assert.equal(
    JSON.parse(invalidPayload.body).error_code,
    'SYSCFG-400-INVALID-PAYLOAD'
  );

  const malformedEnvelope = await dispatchApiRoute({
    pathname: '/platform/system-configs/auth.default_password',
    method: 'PUT',
    requestId: 'req-system-config-invalid-envelope',
    headers: {
      authorization: `Bearer ${login.access_token}`
    },
    body: {
      value: 'enc:v1:invalid:tag:cipher',
      expected_version: 0
    },
    handlers: harness.handlers
  });
  assert.equal(malformedEnvelope.status, 400);
  assert.equal(
    JSON.parse(malformedEnvelope.body).error_code,
    'SYSCFG-400-INVALID-PAYLOAD'
  );
});

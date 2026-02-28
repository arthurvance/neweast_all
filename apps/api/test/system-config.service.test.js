const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createCipheriv,
  pbkdf2Sync,
  randomBytes
} = require('node:crypto');
const { AuthProblemError } = require('../src/shared-kernel/auth/create-auth-service');
const {
  createPlatformSystemConfigService
} = require('../src/domains/platform/config/system-config/service');

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

const VALID_ENCRYPTED_VALUE = buildEncryptedSensitiveConfigValue({
  plainText: 'Secure#Pass123',
  decryptionKey: 'system-config-service-test-key'
});

const createService = ({
  authorizeRoute = async () => ({
    user_id: 'platform-operator',
    session_id: 'platform-session',
    entry_domain: 'platform',
    active_tenant_id: null
  }),
  getSystemSensitiveConfig = async () => ({
    key: 'auth.default_password',
    value: VALID_ENCRYPTED_VALUE,
    version: 3,
    updated_by_user_id: 'platform-operator',
    updated_at: '2026-02-21T09:00:00.000Z',
    status: 'active'
  }),
  upsertSystemSensitiveConfig = async () => ({
    key: 'auth.default_password',
    version: 4,
    previous_version: 3,
    updated_by_user_id: 'platform-operator',
    updated_at: '2026-02-21T09:05:00.000Z',
    status: 'active'
  }),
  recordSystemSensitiveConfigAuditEvent = async () => {}
} = {}) =>
  createPlatformSystemConfigService({
    authService: {
      authorizeRoute,
      getSystemSensitiveConfig,
      upsertSystemSensitiveConfig,
      recordSystemSensitiveConfigAuditEvent
    }
  });

test('getSystemConfig rejects non-whitelisted key', async () => {
  const service = createService();
  await assert.rejects(
    () =>
      service.getSystemConfig({
        requestId: 'req-system-config-service-invalid-key',
        accessToken: 'Bearer fake-access-token',
        configKey: 'auth.not_supported'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'SYSCFG-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('getSystemConfig returns redacted metadata without value', async () => {
  const service = createService();
  const result = await service.getSystemConfig({
    requestId: 'req-system-config-service-get',
    accessToken: 'Bearer fake-access-token',
    configKey: 'auth.default_password'
  });
  assert.equal(result.data.key, 'auth.default_password');
  assert.equal(result.data.version, 3);
  assert.equal(result.data.status, 'active');
  assert.equal(result.data.updated_by_user_id, 'platform-operator');
  assert.equal(result.data.updated_at, '2026-02-21T09:00:00.000Z');
  assert.equal(Object.prototype.hasOwnProperty.call(result.data, 'value'), false);
});

test('updateSystemConfig maps optimistic concurrency conflict to 409 Problem Details', async () => {
  const service = createService({
    upsertSystemSensitiveConfig: async () => {
      const error = new Error('system sensitive config version conflict');
      error.code = 'ERR_SYSTEM_SENSITIVE_CONFIG_VERSION_CONFLICT';
      error.currentVersion = 4;
      throw error;
    }
  });
  await assert.rejects(
    () =>
      service.updateSystemConfig({
        requestId: 'req-system-config-service-conflict',
        accessToken: 'Bearer fake-access-token',
        configKey: 'auth.default_password',
        payload: {
          value: VALID_ENCRYPTED_VALUE,
          expected_version: 3
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 409);
      assert.equal(error.errorCode, 'SYSCFG-409-VERSION-CONFLICT');
      assert.equal(error.extensions?.key, 'auth.default_password');
      assert.equal(error.extensions?.expected_version, 3);
      assert.equal(error.extensions?.current_version, 4);
      return true;
    }
  );
});

test('updateSystemConfig maps duplicate-entry conflict to 409 Problem Details', async () => {
  const service = createService({
    upsertSystemSensitiveConfig: async () => {
      const error = new Error('Duplicate entry');
      error.code = 'ER_DUP_ENTRY';
      error.errno = 1062;
      throw error;
    }
  });
  await assert.rejects(
    () =>
      service.updateSystemConfig({
        requestId: 'req-system-config-service-dup-entry',
        accessToken: 'Bearer fake-access-token',
        configKey: 'auth.default_password',
        payload: {
          value: VALID_ENCRYPTED_VALUE,
          expected_version: 3
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 409);
      assert.equal(error.errorCode, 'SYSCFG-409-VERSION-CONFLICT');
      assert.equal(error.extensions?.key, 'auth.default_password');
      assert.equal(error.extensions?.expected_version, 3);
      return true;
    }
  );
});

test('getSystemConfig persists rejected audit event when read capability is unavailable', async () => {
  const auditEvents = [];
  const service = createService({
    getSystemSensitiveConfig: null,
    recordSystemSensitiveConfigAuditEvent: async (payload) => {
      auditEvents.push(payload);
      return payload;
    }
  });
  await assert.rejects(
    () =>
      service.getSystemConfig({
        requestId: 'req-system-config-service-read-capability-missing',
        accessToken: 'Bearer fake-access-token',
        configKey: 'auth.default_password'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'SYSCFG-503-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
  assert.equal(auditEvents.length, 1);
  assert.equal(auditEvents[0].eventType, 'auth.system_config.read.rejected');
  assert.equal(auditEvents[0].targetId, 'auth.default_password');
  assert.equal(auditEvents[0].result, 'rejected');
});

test('updateSystemConfig writes rejected audit event for authorization failure', async () => {
  const auditEvents = [];
  const service = createService({
    authorizeRoute: async () => {
      throw new AuthProblemError({
        status: 403,
        title: 'Forbidden',
        detail: '当前操作无权限',
        errorCode: 'AUTH-403-FORBIDDEN'
      });
    },
    recordSystemSensitiveConfigAuditEvent: async (payload) => {
      auditEvents.push(payload);
      return payload;
    }
  });
  await assert.rejects(
    () =>
      service.updateSystemConfig({
        requestId: 'req-system-config-service-forbidden',
        accessToken: 'Bearer fake-access-token',
        configKey: 'auth.default_password',
        payload: {
          value: VALID_ENCRYPTED_VALUE,
          expected_version: 0
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-FORBIDDEN');
      return true;
    }
  );
  assert.equal(auditEvents.length, 1);
  assert.equal(auditEvents[0].eventType, 'auth.system_config.update.rejected');
  assert.equal(auditEvents[0].result, 'rejected');
  assert.equal(auditEvents[0].targetId, 'auth.default_password');
});

test('updateSystemConfig persists rejected audit event when update capability is unavailable', async () => {
  const auditEvents = [];
  const service = createService({
    upsertSystemSensitiveConfig: null,
    recordSystemSensitiveConfigAuditEvent: async (payload) => {
      auditEvents.push(payload);
      return payload;
    }
  });
  await assert.rejects(
    () =>
      service.updateSystemConfig({
        requestId: 'req-system-config-service-update-capability-missing',
        accessToken: 'Bearer fake-access-token',
        configKey: 'auth.default_password',
        payload: {
          value: VALID_ENCRYPTED_VALUE,
          expected_version: 0
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'SYSCFG-503-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
  assert.equal(auditEvents.length, 1);
  assert.equal(auditEvents[0].eventType, 'auth.system_config.update.rejected');
  assert.equal(auditEvents[0].targetId, 'auth.default_password');
  assert.equal(auditEvents[0].result, 'rejected');
});

test('updateSystemConfig rejects malformed encrypted envelope payload', async () => {
  const service = createService();
  await assert.rejects(
    () =>
      service.updateSystemConfig({
        requestId: 'req-system-config-service-invalid-envelope',
        accessToken: 'Bearer fake-access-token',
        configKey: 'auth.default_password',
        payload: {
          value: 'enc:v1:invalid:tag:cipher',
          expected_version: 0
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'SYSCFG-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

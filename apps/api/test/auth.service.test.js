const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createCipheriv,
  createHash,
  generateKeyPairSync,
  pbkdf2Sync,
  randomBytes
} = require('node:crypto');
const {
  createAuthService,
  AuthProblemError,
  REFRESH_TTL_SECONDS
} = require('../src/modules/auth/auth.service');
const { createInMemoryAuthStore } = require('../src/modules/auth/auth.store.memory');

const seedUsers = [
  {
    id: 'user-active',
    phone: '13800000000',
    password: 'Passw0rd!',
    status: 'active'
  },
  {
    id: 'user-disabled',
    phone: '13800000001',
    password: 'Passw0rd!',
    status: 'disabled'
  }
];

const tenantPermissionA = {
  scopeLabel: '组织权限快照 A',
  canViewMemberAdmin: true,
  canOperateMemberAdmin: true,
  canViewBilling: true,
  canOperateBilling: false
};

const tenantPermissionB = {
  scopeLabel: '组织权限快照 B',
  canViewMemberAdmin: false,
  canOperateMemberAdmin: false,
  canViewBilling: true,
  canOperateBilling: true
};

const createService = () => createAuthService({ seedUsers });
const toOwnerTransferTakeoverRoleIdForOrg = (orgId) =>
  `tenant_owner__${createHash('sha256')
    .update(String(orgId || '').trim())
    .digest('hex')
    .slice(0, 24)}`;
const TENANT_GRANT_SYNC_FAILURE_TENANT_ID = 'tenant-grant-sync-failure';
const TENANT_GRANT_SYNC_FAILURE_ROLE_ID = 'tenant_grant_sync_failure_role';
const TENANT_GRANT_SYNC_FAILURE_OPERATOR_USER_ID = 'tenant-grant-sync-operator';
const TENANT_GRANT_SYNC_FAILURE_MEMBERSHIP_A = 'membership-sync-target-a';
const TENANT_GRANT_SYNC_FAILURE_MEMBERSHIP_B = 'membership-sync-target-b';
const TENANT_GRANT_SYNC_FAILURE_USER_A = 'tenant-sync-target-a';
const TENANT_GRANT_SYNC_FAILURE_USER_B = 'tenant-sync-target-b';
const createTenantGrantSyncFailureService = () => {
  const authStore = createInMemoryAuthStore({
    seedUsers: [
      ...seedUsers,
      {
        id: TENANT_GRANT_SYNC_FAILURE_OPERATOR_USER_ID,
        phone: '13817770101',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: 'membership-sync-operator',
            tenantId: TENANT_GRANT_SYNC_FAILURE_TENANT_ID,
            tenantName: 'Tenant Grant Sync Failure',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: TENANT_GRANT_SYNC_FAILURE_USER_A,
        phone: '13817770102',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: TENANT_GRANT_SYNC_FAILURE_MEMBERSHIP_A,
            tenantId: TENANT_GRANT_SYNC_FAILURE_TENANT_ID,
            tenantName: 'Tenant Grant Sync Failure',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: TENANT_GRANT_SYNC_FAILURE_USER_B,
        phone: '13817770103',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: TENANT_GRANT_SYNC_FAILURE_MEMBERSHIP_B,
            tenantId: TENANT_GRANT_SYNC_FAILURE_TENANT_ID,
            tenantName: 'Tenant Grant Sync Failure',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ],
    hashPassword: (password) =>
      createHash('sha256').update(String(password || '')).digest('hex'),
    faultInjector: {
      beforeTenantRolePermissionSnapshotSync: ({ membershipId }) => {
        if (membershipId === TENANT_GRANT_SYNC_FAILURE_MEMBERSHIP_B) {
          const error = new Error('injected-tenant-role-permission-sync-failure');
          error.code = 'ERR_TENANT_ROLE_PERMISSION_SYNC_FAILED';
          error.syncReason = 'injected-mid-sync';
          throw error;
        }
      }
    }
  });
  const service = createAuthService({
    authStore,
    otpStore: noOpOtpStore,
    rateLimitStore: passRateLimitStore
  });
  return {
    service,
    authStore
  };
};
const setupTenantGrantSyncFailureScenario = async () => {
  const { service, authStore } = createTenantGrantSyncFailureService();
  await service.createPlatformRoleCatalogEntry({
    roleId: TENANT_GRANT_SYNC_FAILURE_ROLE_ID,
    code: 'TENANT_GRANT_SYNC_FAILURE_ROLE',
    name: 'Tenant Grant Sync Failure Role',
    status: 'active',
    scope: 'tenant',
    tenantId: TENANT_GRANT_SYNC_FAILURE_TENANT_ID,
    isSystem: false,
    operatorUserId: TENANT_GRANT_SYNC_FAILURE_OPERATOR_USER_ID,
    operatorSessionId: 'tenant-grant-sync-operator-session'
  });
  await service.replaceTenantRolePermissionGrants({
    requestId: 'req-tenant-grant-sync-prime-grants',
    tenantId: TENANT_GRANT_SYNC_FAILURE_TENANT_ID,
    roleId: TENANT_GRANT_SYNC_FAILURE_ROLE_ID,
    permissionCodes: ['tenant.member_admin.view'],
    operatorUserId: TENANT_GRANT_SYNC_FAILURE_OPERATOR_USER_ID,
    operatorSessionId: 'tenant-grant-sync-operator-session'
  });
  await service.replaceTenantMemberRoleBindings({
    requestId: 'req-tenant-grant-sync-prime-bindings-a',
    tenantId: TENANT_GRANT_SYNC_FAILURE_TENANT_ID,
    membershipId: TENANT_GRANT_SYNC_FAILURE_MEMBERSHIP_A,
    roleIds: [TENANT_GRANT_SYNC_FAILURE_ROLE_ID],
    operatorUserId: TENANT_GRANT_SYNC_FAILURE_OPERATOR_USER_ID,
    operatorSessionId: 'tenant-grant-sync-operator-session'
  });
  await service.replaceTenantMemberRoleBindings({
    requestId: 'req-tenant-grant-sync-prime-bindings-b',
    tenantId: TENANT_GRANT_SYNC_FAILURE_TENANT_ID,
    membershipId: TENANT_GRANT_SYNC_FAILURE_MEMBERSHIP_B,
    roleIds: [TENANT_GRANT_SYNC_FAILURE_ROLE_ID],
    operatorUserId: TENANT_GRANT_SYNC_FAILURE_OPERATOR_USER_ID,
    operatorSessionId: 'tenant-grant-sync-operator-session'
  });
  return {
    service,
    authStore
  };
};
const noOpOtpStore = {
  upsertOtp: async () => ({ sent_at_ms: Date.now() }),
  getSentAt: async () => null,
  verifyAndConsumeOtp: async () => ({ ok: false, reason: 'missing' })
};
const passRateLimitStore = {
  consume: async () => ({ allowed: true, count: 1, remainingSeconds: 60 })
};
const PLATFORM_ROLE_FACTS_OPERATOR_PHONE = '13819990000';

const buildPlatformRoleFactsOperatorSeed = () => ({
  id: 'platform-role-facts-operator',
  phone: PLATFORM_ROLE_FACTS_OPERATOR_PHONE,
  password: 'Passw0rd!',
  status: 'active',
  domains: ['platform'],
  platformRoles: [
    {
      roleId: 'platform-role-facts-operate',
      status: 'active',
      permission: {
        canViewMemberAdmin: true,
        canOperateMemberAdmin: true,
        canViewBilling: false,
        canOperateBilling: false
      }
    }
  ]
});

const loginPlatformRoleFactsOperator = (service, requestId) =>
  service.login({
    requestId,
    phone: PLATFORM_ROLE_FACTS_OPERATOR_PHONE,
    password: 'Passw0rd!',
    entryDomain: 'platform'
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
const buildEncryptedSensitiveConfigValueLegacy = ({
  plainText,
  decryptionKey
}) => {
  const key = createHash('sha256').update(String(decryptionKey || '')).digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const cipherText = Buffer.concat([
    cipher.update(String(plainText || ''), 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  return `enc:v1:${iv.toString('base64url')}:${authTag.toString('base64url')}:${cipherText.toString('base64url')}`;
};
const createSensitiveConfigProvider = ({ encryptedDefaultPassword = '' } = {}) => ({
  getEncryptedConfig: async (configKey) =>
    String(configKey || '').trim() === 'auth.default_password'
      ? String(encryptedDefaultPassword || '')
      : ''
});

test('default service does not allow legacy seeded credentials', async () => {
  const service = createAuthService();

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-login-default',
        phone: '13800000000',
        password: 'Passw0rd!'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      return true;
    }
  );
});

test('service uses injected authStore lookup path', async () => {
  const service = createAuthService({
    allowInMemoryOtpStores: true,
    authStore: {
      findUserByPhone: async () => {
        throw new Error('store-called');
      }
    }
  });

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-login-store',
        phone: '13800000000',
        password: 'Passw0rd!'
      }),
    /store-called/
  );
});

test('service rejects implicit otp/rate-limit fallback for external authStore', () => {
  assert.throws(
    () =>
      createAuthService({
        authStore: {
          findUserByPhone: async () => null
        }
      }),
    /OTP and rate-limit stores must be configured explicitly/
  );
});

test('service requires otpStore.getSentAt in otp store contract', () => {
  assert.throws(
    () =>
      createAuthService({
        seedUsers,
        otpStore: {
          upsertOtp: async () => ({ sent_at_ms: Date.now() }),
          verifyAndConsumeOtp: async () => ({ ok: false, reason: 'missing' })
        }
      }),
    /otpStore\.getSentAt is required/
  );
});

test('service requires external jwt keys when multi-instance mode is enabled', () => {
  assert.throws(
    () => createAuthService({ enforceExternalJwtKeys: true, seedUsers }),
    /External JWT key pair is required/
  );
});

test('service disables access session cache in multi-instance mode', () => {
  const keyPair = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  const service = createAuthService({
    seedUsers,
    jwtKeyPair: keyPair,
    multiInstance: true,
    accessSessionCacheTtlMs: 800
  });

  assert.equal(service._internals.accessSessionCacheTtlMs, 0);
});

test('login success returns token pair and session metadata', async () => {
  const service = createService();
  const result = await service.login({
    requestId: 'req-login-1',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  assert.equal(result.request_id, 'req-login-1');
  assert.equal(result.token_type, 'Bearer');
  assert.ok(result.access_token);
  assert.ok(result.refresh_token);
  assert.ok(result.session_id);
  assert.deepEqual(result.tenant_permission_context, {
    scope_label: '平台入口（无组织侧权限上下文）',
    can_view_member_admin: false,
    can_operate_member_admin: false,
    can_view_billing: false,
    can_operate_billing: false
  });
});

test('tenant entry provisions tenant-domain access from active memberships when explicit tenant-domain row is missing', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'domain-tenant-provision-user',
        phone: '13810000000',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        tenants: [{ tenantId: 'tenant-a', tenantName: 'A', permission: tenantPermissionA }]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-login-tenant-provision',
    phone: '13810000000',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });
  assert.equal(login.entry_domain, 'tenant');
  assert.equal(login.active_tenant_id, 'tenant-a');
  assert.equal(login.tenant_selection_required, false);

  const access = await service._internals.authStore.findDomainAccessByUserId(
    'domain-tenant-provision-user'
  );
  assert.deepEqual(access, { platform: true, tenant: true });

  const tenantGranted = service._internals.auditTrail.find(
    (event) => event.type === 'auth.domain.tenant_granted'
  );
  assert.ok(tenantGranted);
});

test('tenant entry failure does not grant default platform-domain access on password login', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'domain-no-membership-user',
        phone: '13810000012',
        password: 'Passw0rd!',
        status: 'active',
        domains: [],
        tenants: []
      }
    ]
  });

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-login-no-membership',
        phone: '13810000012',
        password: 'Passw0rd!',
        entryDomain: 'tenant'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );

  const access = await service._internals.authStore.findDomainAccessByUserId(
    'domain-no-membership-user'
  );
  assert.deepEqual(access, { platform: false, tenant: false });

  const defaultGranted = service._internals.auditTrail.find(
    (event) => event.type === 'auth.domain.default_granted'
  );
  assert.equal(defaultGranted, undefined);

  const rejected = service._internals.auditTrail.find(
    (event) => event.type === 'auth.domain.rejected'
  );
  assert.ok(rejected);
  assert.equal(rejected.permission_code, null);
});

test('tenant entry failure does not grant default platform-domain access on otp login', async () => {
  const otpStore = {
    upsertOtp: async () => ({ sent_at_ms: Date.now() }),
    getSentAt: async () => null,
    verifyAndConsumeOtp: async () => ({ ok: true, reason: 'ok' })
  };
  const service = createAuthService({
    seedUsers: [
      {
        id: 'otp-domain-no-membership-user',
        phone: '13810000013',
        password: 'Passw0rd!',
        status: 'active',
        domains: [],
        tenants: []
      }
    ],
    otpStore,
    rateLimitStore: passRateLimitStore
  });

  await assert.rejects(
    () =>
      service.loginWithOtp({
        requestId: 'req-otp-login-no-membership',
        phone: '13810000013',
        otpCode: '123456',
        entryDomain: 'tenant'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );

  const access = await service._internals.authStore.findDomainAccessByUserId(
    'otp-domain-no-membership-user'
  );
  assert.deepEqual(access, { platform: false, tenant: false });

  const defaultGranted = service._internals.auditTrail.find(
    (event) => event.type === 'auth.domain.default_granted'
  );
  assert.equal(defaultGranted, undefined);
});

test('login is fail-closed when authStore.findDomainAccessByUserId is unavailable', async () => {
  const bootstrapService = createAuthService({
    seedUsers: [
      {
        id: 'domain-missing-method-user',
        phone: '13810000010',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform']
      }
    ]
  });
  const baseStore = bootstrapService._internals.authStore;
  const authStore = {
    ...baseStore,
    findDomainAccessByUserId: undefined
  };

  const service = createAuthService({
    authStore,
    otpStore: noOpOtpStore,
    rateLimitStore: passRateLimitStore
  });

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-login-fail-closed',
        phone: '13810000010',
        password: 'Passw0rd!',
        entryDomain: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );
});

test('login provisions default platform domain access when user has no domain rows', async () => {
  const bootstrapService = createAuthService({
    seedUsers: [
      {
        id: 'domain-default-user',
        phone: '13810000011',
        password: 'Passw0rd!',
        status: 'active',
        domains: []
      }
    ]
  });
  const authStore = bootstrapService._internals.authStore;
  const service = createAuthService({
    authStore,
    otpStore: noOpOtpStore,
    rateLimitStore: passRateLimitStore
  });

  const login = await service.login({
    requestId: 'req-login-default-domain-provision',
    phone: '13810000011',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });
  assert.equal(login.entry_domain, 'platform');

  const access = await authStore.findDomainAccessByUserId('domain-default-user');
  assert.deepEqual(access, { platform: true, tenant: false });

  const defaultGranted = service._internals.auditTrail.find(
    (event) => event.type === 'auth.domain.default_granted'
  );
  assert.ok(defaultGranted);
});

test('platform entry rejects tenant-only identity and does not auto-grant platform domain', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'platform-denied-tenant-only-user',
        phone: '13810000023',
        password: 'Passw0rd!',
        status: 'active',
        domains: [],
        tenants: [
          { tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA }
        ]
      }
    ]
  });

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-login-platform-denied-tenant-only',
        phone: '13810000023',
        password: 'Passw0rd!',
        entryDomain: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );

  const access = await service._internals.authStore.findDomainAccessByUserId(
    'platform-denied-tenant-only-user'
  );
  assert.equal(access.platform, false);

  const defaultGranted = service._internals.auditTrail.find(
    (event) => event.type === 'auth.domain.default_granted'
  );
  assert.equal(defaultGranted, undefined);
});

test('platform entry rejects users with only disabled tenant relationships and does not auto-grant platform domain', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'platform-denied-disabled-tenant-user',
        phone: '13810000024',
        password: 'Passw0rd!',
        status: 'active',
        domains: [],
        tenants: [
          {
            tenantId: 'tenant-disabled',
            tenantName: 'Tenant Disabled',
            status: 'disabled',
            permission: tenantPermissionA
          }
        ]
      }
    ]
  });

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-login-platform-denied-disabled-tenant',
        phone: '13810000024',
        password: 'Passw0rd!',
        entryDomain: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );

  const access = await service._internals.authStore.findDomainAccessByUserId(
    'platform-denied-disabled-tenant-user'
  );
  assert.equal(access.platform, false);

  const defaultGranted = service._internals.auditTrail.find(
    (event) => event.type === 'auth.domain.default_granted'
  );
  assert.equal(defaultGranted, undefined);
});

test('tenant entry with multiple options requires selection and persists active tenant in session', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-multi-user',
        phone: '13810000001',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [
          { tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA },
          { tenantId: 'tenant-b', tenantName: 'Tenant B', permission: tenantPermissionB }
        ]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-login-tenant-multi',
    phone: '13810000001',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  assert.equal(login.entry_domain, 'tenant');
  assert.equal(login.tenant_selection_required, true);
  assert.equal(login.active_tenant_id, null);
  assert.equal(login.tenant_options.length, 2);
  assert.deepEqual(login.tenant_permission_context, {
    scope_label: '组织未选择（无可操作权限）',
    can_view_member_admin: false,
    can_operate_member_admin: false,
    can_view_billing: false,
    can_operate_billing: false
  });

  const beforeSelect = await service.tenantOptions({
    requestId: 'req-tenant-options-before',
    accessToken: login.access_token
  });
  assert.equal(beforeSelect.tenant_selection_required, true);
  assert.equal(beforeSelect.active_tenant_id, null);
  assert.deepEqual(beforeSelect.tenant_permission_context, {
    scope_label: '组织未选择（无可操作权限）',
    can_view_member_admin: false,
    can_operate_member_admin: false,
    can_view_billing: false,
    can_operate_billing: false
  });

  const selected = await service.selectTenant({
    requestId: 'req-tenant-select',
    accessToken: login.access_token,
    tenantId: 'tenant-b'
  });
  assert.equal(selected.entry_domain, 'tenant');
  assert.equal(selected.active_tenant_id, 'tenant-b');
  assert.equal(selected.tenant_selection_required, false);
  assert.deepEqual(selected.tenant_permission_context, {
    scope_label: '组织权限快照 B',
    can_view_member_admin: false,
    can_operate_member_admin: false,
    can_view_billing: true,
    can_operate_billing: true
  });

  const afterSelect = await service.tenantOptions({
    requestId: 'req-tenant-options-after',
    accessToken: login.access_token
  });
  assert.equal(afterSelect.active_tenant_id, 'tenant-b');
  assert.equal(afterSelect.tenant_selection_required, false);
  assert.deepEqual(afterSelect.tenant_permission_context, {
    scope_label: '组织权限快照 B',
    can_view_member_admin: false,
    can_operate_member_admin: false,
    can_view_billing: true,
    can_operate_billing: true
  });
});

test('tenant entry with single option binds active tenant directly', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-single-user',
        phone: '13810000002',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [{
          tenantId: 'tenant-single',
          tenantName: 'Single Tenant',
          permission: {
            scopeLabel: '组织权限快照 Single',
            canViewMemberAdmin: true,
            canOperateMemberAdmin: false,
            canViewBilling: false,
            canOperateBilling: false
          }
        }]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-login-tenant-single',
    phone: '13810000002',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  assert.equal(login.entry_domain, 'tenant');
  assert.equal(login.tenant_selection_required, false);
  assert.equal(login.active_tenant_id, 'tenant-single');
});

test('tenant entry accepts enabled tenant membership in in-memory auth store', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-enabled-user',
        phone: '13810000022',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        tenants: [{
          tenantId: 'tenant-enabled',
          tenantName: 'Enabled Tenant',
          status: 'enabled',
          permission: {
            scopeLabel: '组织权限快照 Enabled',
            canViewMemberAdmin: true,
            canOperateMemberAdmin: false,
            canViewBilling: false,
            canOperateBilling: false
          }
        }]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-login-tenant-enabled',
    phone: '13810000022',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  assert.equal(login.entry_domain, 'tenant');
  assert.equal(login.tenant_selection_required, false);
  assert.equal(login.active_tenant_id, 'tenant-enabled');
  assert.equal(login.tenant_options.length, 1);
  assert.deepEqual(login.tenant_permission_context, {
    scope_label: '组织权限快照 Enabled',
    can_view_member_admin: true,
    can_operate_member_admin: false,
    can_view_billing: false,
    can_operate_billing: false
  });
});

test('tenant entry is rejected when tenant permission context is missing', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-missing-permission-user',
        phone: '13810000020',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [{ tenantId: 'tenant-missing', tenantName: 'Tenant Missing Permission' }]
      }
    ]
  });

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-login-tenant-missing-permission',
        phone: '13810000020',
        password: 'Passw0rd!',
        entryDomain: 'tenant'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );
});

test('tenant options reconciles stale active_tenant_id against latest tenant options', async () => {
  const bootstrapService = createAuthService({
    seedUsers: [
      {
        id: 'tenant-reconcile-user',
        phone: '13810000021',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [
          { tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA },
          { tenantId: 'tenant-b', tenantName: 'Tenant B', permission: tenantPermissionB }
        ]
      }
    ]
  });
  const baseStore = bootstrapService._internals.authStore;

  let tenantOptions = [
    { tenantId: 'tenant-a', tenantName: 'Tenant A' },
    { tenantId: 'tenant-b', tenantName: 'Tenant B' }
  ];
  const authStore = {
    ...baseStore,
    listTenantOptionsByUserId: async () => tenantOptions.map((item) => ({ ...item }))
  };
  const service = createAuthService({
    authStore,
    otpStore: noOpOtpStore,
    rateLimitStore: passRateLimitStore
  });

  const login = await service.login({
    requestId: 'req-login-tenant-reconcile',
    phone: '13810000021',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });
  assert.equal(login.tenant_selection_required, true);

  const selected = await service.selectTenant({
    requestId: 'req-tenant-reconcile-select-a',
    accessToken: login.access_token,
    tenantId: 'tenant-a'
  });
  assert.equal(selected.active_tenant_id, 'tenant-a');

  tenantOptions = [{ tenantId: 'tenant-b', tenantName: 'Tenant B' }];
  const reconciled = await service.tenantOptions({
    requestId: 'req-tenant-reconcile-options',
    accessToken: login.access_token
  });

  assert.equal(reconciled.active_tenant_id, 'tenant-b');
  assert.equal(reconciled.tenant_selection_required, false);
  assert.deepEqual(reconciled.tenant_permission_context, {
    scope_label: '组织权限快照 B',
    can_view_member_admin: false,
    can_operate_member_admin: false,
    can_view_billing: true,
    can_operate_billing: true
  });

  const session = await authStore.findSessionById(login.session_id);
  assert.equal(session.activeTenantId, 'tenant-b');
});

test('tenant switch rejects tenant outside session allowed options', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-switch-user',
        phone: '13810000003',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [
          { tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA },
          { tenantId: 'tenant-b', tenantName: 'Tenant B', permission: tenantPermissionB }
        ]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-login-tenant-switch',
    phone: '13810000003',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });
  assert.equal(login.tenant_selection_required, true);

  await assert.rejects(
    () =>
      service.switchTenant({
        requestId: 'req-tenant-switch-denied',
        accessToken: login.access_token,
        tenantId: 'tenant-outside'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );
});

test('tenant options in platform entry session is blocked with AUTH-403-NO-DOMAIN', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'platform-options-user',
        phone: '13810000030',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [
          { tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA },
          { tenantId: 'tenant-b', tenantName: 'Tenant B', permission: tenantPermissionB }
        ]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-login-platform-options',
    phone: '13810000030',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });
  assert.equal(login.entry_domain, 'platform');

  await assert.rejects(
    () =>
      service.tenantOptions({
        requestId: 'req-tenant-options-platform',
        accessToken: login.access_token
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );
});

test('selectTenant rejects stale authorizationContext after session domain changes', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-stale-context-user',
        phone: '13810000031',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [
          { tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA },
          { tenantId: 'tenant-b', tenantName: 'Tenant B', permission: tenantPermissionB }
        ]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-login-tenant-stale-context',
    phone: '13810000031',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  const authorizationContext = await service.authorizeRoute({
    requestId: 'req-authorize-tenant-stale-context',
    accessToken: login.access_token,
    permissionCode: 'tenant.context.switch',
    scope: 'tenant'
  });

  await service._internals.authStore.updateSessionContext({
    sessionId: login.session_id,
    entryDomain: 'platform',
    activeTenantId: null
  });
  service._internals.accessSessionCache.clear();

  await assert.rejects(
    () =>
      service.selectTenant({
        requestId: 'req-select-tenant-stale-context',
        accessToken: login.access_token,
        tenantId: 'tenant-a',
        authorizationContext
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );
});

test('login failure keeps unified semantics and does not leak account state', async () => {
  const service = createService();

  await assert.rejects(
    () => service.login({ requestId: 'req-login-2', phone: '13800000000', password: 'wrong' }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      assert.equal(error.detail, '手机号或密码错误');
      return true;
    }
  );

  await assert.rejects(
    () => service.login({ requestId: 'req-login-3', phone: '13800000001', password: 'Passw0rd!' }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      assert.equal(error.detail, '手机号或密码错误');
      return true;
    }
  );

  await assert.rejects(
    () => service.login({ requestId: 'req-login-4', phone: '13999999999', password: 'Passw0rd!' }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      assert.equal(error.detail, '手机号或密码错误');
      return true;
    }
  );

  const lastAudit = service._internals.auditTrail[service._internals.auditTrail.length - 1];
  assert.equal(lastAudit.type, 'auth.login.failed');
  assert.equal(lastAudit.phone_masked, '139****9999');
});

test('refresh rotation invalidates previous refresh token immediately', async () => {
  const service = createService();
  const login = await service.login({
    requestId: 'req-login-5',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  const refreshed = await service.refresh({
    requestId: 'req-refresh-1',
    refreshToken: login.refresh_token
  });

  assert.ok(refreshed.access_token);
  assert.ok(refreshed.refresh_token);
  assert.notEqual(refreshed.refresh_token, login.refresh_token);

  await assert.rejects(
    () => service.refresh({ requestId: 'req-refresh-2', refreshToken: login.refresh_token }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-REFRESH');
      return true;
    }
  );

  await assert.rejects(
    () => service.refresh({ requestId: 'req-refresh-3', refreshToken: refreshed.refresh_token }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-REFRESH');
      return true;
    }
  );
});

test('refresh rotation writes traceable rotated_from/rotated_to chain and keeps response tracing fields', async () => {
  const service = createService();
  const login = await service.login({
    requestId: 'req-rotation-chain-login',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  const refreshed = await service.refresh({
    requestId: 'req-rotation-chain-refresh',
    refreshToken: login.refresh_token
  });

  assert.equal(refreshed.session_id, login.session_id);
  assert.equal(refreshed.request_id, 'req-rotation-chain-refresh');

  const previousHash = refreshTokenHash(login.refresh_token);
  const nextHash = refreshTokenHash(refreshed.refresh_token);
  const previousRecord = await service._internals.authStore.findRefreshTokenByHash(previousHash);
  const nextRecord = await service._internals.authStore.findRefreshTokenByHash(nextHash);

  assert.equal(previousRecord.status, 'rotated');
  assert.equal(previousRecord.rotatedTo, nextHash);
  assert.equal(nextRecord.status, 'active');
  assert.equal(nextRecord.rotatedFrom, previousHash);
});

test('refresh rejects rotated/revoked/missing/expired/malformed with unified AUTH-401-INVALID-REFRESH', async () => {
  const assertInvalidRefresh = async (executor) =>
    assert.rejects(executor, (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-REFRESH');
      return true;
    });

  const rotatedService = createService();
  const rotatedLogin = await rotatedService.login({
    requestId: 'req-rotated-login',
    phone: '13800000000',
    password: 'Passw0rd!'
  });
  await rotatedService.refresh({
    requestId: 'req-rotated-refresh-ok',
    refreshToken: rotatedLogin.refresh_token
  });
  await assertInvalidRefresh(() =>
    rotatedService.refresh({
      requestId: 'req-rotated-refresh-replay',
      refreshToken: rotatedLogin.refresh_token
    })
  );

  const revokedService = createService();
  const revokedLogin = await revokedService.login({
    requestId: 'req-revoked-login',
    phone: '13800000000',
    password: 'Passw0rd!'
  });
  await revokedService._internals.authStore.markRefreshTokenStatus({
    tokenHash: refreshTokenHash(revokedLogin.refresh_token),
    status: 'revoked'
  });
  await assertInvalidRefresh(() =>
    revokedService.refresh({
      requestId: 'req-revoked-refresh',
      refreshToken: revokedLogin.refresh_token
    })
  );

  const missingService = createService();
  const missingLogin = await missingService.login({
    requestId: 'req-missing-login',
    phone: '13800000000',
    password: 'Passw0rd!'
  });
  const originalFindRefreshTokenByHash = missingService._internals.authStore.findRefreshTokenByHash;
  missingService._internals.authStore.findRefreshTokenByHash = async () => null;
  await assertInvalidRefresh(() =>
    missingService.refresh({
      requestId: 'req-missing-refresh',
      refreshToken: missingLogin.refresh_token
    })
  );
  missingService._internals.authStore.findRefreshTokenByHash = originalFindRefreshTokenByHash;

  let nowMs = Date.now();
  const expiredService = createAuthService({
    seedUsers,
    now: () => nowMs
  });
  const expiredLogin = await expiredService.login({
    requestId: 'req-expired-login',
    phone: '13800000000',
    password: 'Passw0rd!'
  });
  nowMs += REFRESH_TTL_SECONDS * 1000 + 1;
  await assertInvalidRefresh(() =>
    expiredService.refresh({
      requestId: 'req-expired-refresh',
      refreshToken: expiredLogin.refresh_token
    })
  );
  const expiredAudit = expiredService._internals.auditTrail
    .slice()
    .reverse()
    .find((event) => event.request_id === 'req-expired-refresh');
  assert.ok(expiredAudit);
  assert.equal(expiredAudit.user_id, 'user-active');
  assert.equal(expiredAudit.session_id, expiredLogin.session_id);
  assert.equal(expiredAudit.disposition_reason, 'refresh-token-expired');

  const malformedService = createService();
  await assertInvalidRefresh(() =>
    malformedService.refresh({
      requestId: 'req-malformed-refresh',
      refreshToken: 'malformed.refresh.token'
    })
  );
});

test('refresh rejects ownership mismatch and avoids revoking unrelated session chain', async () => {
  const service = createService();
  const sessionA = await service.login({
    requestId: 'req-binding-mismatch-login-a',
    phone: '13800000000',
    password: 'Passw0rd!'
  });
  const sessionB = await service.login({
    requestId: 'req-binding-mismatch-login-b',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  const originalFindRefreshTokenByHash = service._internals.authStore.findRefreshTokenByHash;
  service._internals.authStore.findRefreshTokenByHash = async (tokenHash) => {
    const record = await originalFindRefreshTokenByHash(tokenHash);
    if (!record) {
      return null;
    }
    return {
      ...record,
      sessionId: sessionB.session_id
    };
  };

  await assert.rejects(
    () =>
      service.refresh({
        requestId: 'req-binding-mismatch-refresh-a',
        refreshToken: sessionA.refresh_token
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-REFRESH');
      return true;
    }
  );

  const originalRecordA = await originalFindRefreshTokenByHash(refreshTokenHash(sessionA.refresh_token));
  assert.ok(originalRecordA);
  assert.equal(originalRecordA.status, 'active');

  const mismatchAudit = service._internals.auditTrail
    .slice()
    .reverse()
    .find((event) => event.request_id === 'req-binding-mismatch-refresh-a');
  assert.ok(mismatchAudit);
  assert.equal(mismatchAudit.disposition_reason, 'refresh-token-binding-mismatch');
  assert.equal(mismatchAudit.disposition_action, 'reject-only');

  service._internals.authStore.findRefreshTokenByHash = originalFindRefreshTokenByHash;

  const sessionBRefreshed = await service.refresh({
    requestId: 'req-binding-mismatch-refresh-b',
    refreshToken: sessionB.refresh_token
  });
  assert.ok(sessionBRefreshed.refresh_token);
});

test('refresh audit marks expired jwt as refresh-token-expired instead of malformed', async () => {
  const service = createService();
  const login = await service.login({
    requestId: 'req-jwt-expired-login',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  const realDateNow = Date.now;
  Date.now = () => realDateNow() + REFRESH_TTL_SECONDS * 1000 + 2000;
  try {
    await assert.rejects(
      () =>
        service.refresh({
          requestId: 'req-jwt-expired-refresh',
          refreshToken: login.refresh_token
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.errorCode, 'AUTH-401-INVALID-REFRESH');
        return true;
      }
    );
  } finally {
    Date.now = realDateNow;
  }

  const expiredJwtAudit = service._internals.auditTrail
    .slice()
    .reverse()
    .find((event) => event.request_id === 'req-jwt-expired-refresh');
  assert.ok(expiredJwtAudit);
  assert.equal(expiredJwtAudit.user_id, 'user-active');
  assert.equal(expiredJwtAudit.session_id, login.session_id);
  assert.equal(expiredJwtAudit.detail, 'refresh token expired');
  assert.equal(expiredJwtAudit.disposition_reason, 'refresh-token-expired');
  assert.equal(expiredJwtAudit.disposition_action, 'reject-only');
});

test('refresh replay revokes only current session chain and keeps concurrent sessions valid', async () => {
  const service = createService();
  const sessionA = await service.login({
    requestId: 'req-replay-isolation-login-a',
    phone: '13800000000',
    password: 'Passw0rd!'
  });
  const sessionB = await service.login({
    requestId: 'req-replay-isolation-login-b',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  const sessionARefreshed = await service.refresh({
    requestId: 'req-replay-isolation-refresh-a-ok',
    refreshToken: sessionA.refresh_token
  });

  await assert.rejects(
    () =>
      service.refresh({
        requestId: 'req-replay-isolation-refresh-a-replay',
        refreshToken: sessionA.refresh_token
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-REFRESH');
      return true;
    }
  );

  const sessionBRefreshed = await service.refresh({
    requestId: 'req-replay-isolation-refresh-b-ok',
    refreshToken: sessionB.refresh_token
  });
  assert.ok(sessionBRefreshed.access_token);

  await assert.rejects(
    () =>
      service.refresh({
        requestId: 'req-replay-isolation-refresh-a-chain-revoked',
        refreshToken: sessionARefreshed.refresh_token
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-REFRESH');
      return true;
    }
  );
});

test('refresh replay audit event contains user/session/request identifiers and disposal reason', async () => {
  const service = createService();
  const login = await service.login({
    requestId: 'req-replay-audit-login',
    phone: '13800000000',
    password: 'Passw0rd!'
  });
  await service.refresh({
    requestId: 'req-replay-audit-refresh-ok',
    refreshToken: login.refresh_token
  });

  await assert.rejects(
    () =>
      service.refresh({
        requestId: 'req-replay-audit-refresh-replay',
        refreshToken: login.refresh_token
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-REFRESH');
      return true;
    }
  );

  const replayAuditEvent = service._internals.auditTrail
    .slice()
    .reverse()
    .find((event) => event.type === 'auth.refresh.replay_or_invalid');

  assert.ok(replayAuditEvent);
  assert.equal(replayAuditEvent.request_id, 'req-replay-audit-refresh-replay');
  assert.equal(replayAuditEvent.user_id, 'user-active');
  assert.equal(replayAuditEvent.session_id, login.session_id);
  assert.equal(replayAuditEvent.detail, 'refresh token rejected');
  assert.equal(replayAuditEvent.disposition_reason, 'refresh-replay-detected');
});

test('refresh failure writes session metadata into audit trail', async () => {
  const service = createService();

  await assert.rejects(
    () => service.refresh({ requestId: 'req-refresh-invalid-payload', refreshToken: '' }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );

  const lastAudit = service._internals.auditTrail[service._internals.auditTrail.length - 1];
  assert.equal(lastAudit.type, 'auth.refresh.replay_or_invalid');
  assert.equal(lastAudit.session_id_hint, 'unknown');
});

test('logout only revokes current session, keeping concurrent sessions valid', async () => {
  const service = createService();

  const sessionA = await service.login({ requestId: 'req-login-a', phone: '13800000000', password: 'Passw0rd!' });
  const sessionB = await service.login({ requestId: 'req-login-b', phone: '13800000000', password: 'Passw0rd!' });

  const logoutResult = await service.logout({
    requestId: 'req-logout-a',
    accessToken: sessionA.access_token
  });

  assert.equal(logoutResult.ok, true);
  assert.equal(logoutResult.session_id, sessionA.session_id);

  const refreshB = await service.refresh({
    requestId: 'req-refresh-b',
    refreshToken: sessionB.refresh_token
  });

  assert.ok(refreshB.access_token);
  assert.ok(refreshB.refresh_token);

  await assert.rejects(
    () => service.refresh({ requestId: 'req-refresh-a', refreshToken: sessionA.refresh_token }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      return true;
    }
  );
});

test('logout rejects invalid access token even when authorizationContext is provided', async () => {
  const service = createService();
  const session = await service.login({
    requestId: 'req-login-context-invalid-token',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  await assert.rejects(
    () =>
      service.logout({
        requestId: 'req-logout-context-invalid-token',
        accessToken: 'definitely-invalid-token',
        authorizationContext: {
          session: { sessionId: session.session_id },
          user: { id: 'user-active' }
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
      return true;
    }
  );
});

test('logout rejects authorizationContext that does not match validated access session', async () => {
  const service = createService();
  const session = await service.login({
    requestId: 'req-login-context-mismatch',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  await assert.rejects(
    () =>
      service.logout({
        requestId: 'req-logout-context-mismatch',
        accessToken: session.access_token,
        authorizationContext: {
          session: { sessionId: `${session.session_id}-tampered` },
          user: { id: 'user-active' }
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
      return true;
    }
  );
});

test('change password revokes current auth session and only new password is accepted', async () => {
  const service = createService();

  const session = await service.login({
    requestId: 'req-login-6',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  const changed = await service.changePassword({
    requestId: 'req-change-1',
    accessToken: session.access_token,
    currentPassword: 'Passw0rd!',
    newPassword: 'Passw0rd!2026'
  });

  assert.equal(changed.password_changed, true);
  assert.equal(changed.relogin_required, true);

  await assert.rejects(
    () => service.login({ requestId: 'req-login-7', phone: '13800000000', password: 'Passw0rd!' }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      return true;
    }
  );

  const relogin = await service.login({
    requestId: 'req-login-8',
    phone: '13800000000',
    password: 'Passw0rd!2026'
  });

  assert.ok(relogin.access_token);
  assert.ok(relogin.refresh_token);
});

test('platform role facts critical change bumps session version, rejects old access/refresh, and writes mismatch audit', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-converge-user',
        phone: '13810000401',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-role-converge-login',
    phone: '13810000401',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-converge-operator-login'
  );
  const originalAccessPayload = decodeJwtPayload(login.access_token);

  // Warm access-session cache to verify critical-state change actively invalidates cache entries.
  await service.authorizeRoute({
    requestId: 'req-role-converge-cache-warm',
    accessToken: login.access_token,
    permissionCode: 'auth.session.logout',
    scope: 'session'
  });

  await service.replacePlatformRolesAndSyncSnapshot({
    requestId: 'req-role-converge-change',
    accessToken: operatorLogin.access_token,
    userId: 'platform-role-converge-user',
    roles: [
      {
        roleId: 'platform-view-member-admin',
        status: 'active',
        permission: {
          canViewMemberAdmin: true,
          canOperateMemberAdmin: false,
          canViewBilling: false,
          canOperateBilling: false
        }
      }
    ]
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-role-converge-old-access',
        accessToken: login.access_token,
        permissionCode: 'auth.session.logout',
        scope: 'session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
      return true;
    }
  );

  await assert.rejects(
    () =>
      service.refresh({
        requestId: 'req-role-converge-old-refresh',
        refreshToken: login.refresh_token
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-REFRESH');
      return true;
    }
  );

  const relogin = await service.login({
    requestId: 'req-role-converge-relogin',
    phone: '13810000401',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });
  const reloginAccessPayload = decodeJwtPayload(relogin.access_token);
  assert.ok(
    Number(reloginAccessPayload.sv) > Number(originalAccessPayload.sv),
    'relogin access token should carry incremented session version'
  );

  const accessMismatchAudit = service._internals.auditTrail.find(
    (event) => event.request_id === 'req-role-converge-old-access'
  );
  assert.ok(accessMismatchAudit);
  assert.equal(accessMismatchAudit.type, 'auth.access.invalid');
  assert.equal(accessMismatchAudit.user_id, 'platform-role-converge-user');
  assert.equal(accessMismatchAudit.session_id, login.session_id);
  assert.equal(accessMismatchAudit.disposition_reason, 'session-version-mismatch');

  const refreshMismatchAudit = service._internals.auditTrail.find(
    (event) => event.request_id === 'req-role-converge-old-refresh'
  );
  assert.ok(refreshMismatchAudit);
  assert.equal(refreshMismatchAudit.type, 'auth.refresh.replay_or_invalid');
  assert.equal(refreshMismatchAudit.user_id, 'platform-role-converge-user');
  assert.equal(refreshMismatchAudit.session_id, login.session_id);
  assert.equal(refreshMismatchAudit.disposition_reason, 'session-version-mismatch');
});

test('platform role facts unchanged does not bump session version or invalidate existing token', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-noop-user',
        phone: '13810000402',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-view-member-admin',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-role-noop-login',
    phone: '13810000402',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-noop-operator-login'
  );

  const beforeUser = await service._internals.authStore.findUserById('platform-role-noop-user');
  await service.replacePlatformRolesAndSyncSnapshot({
    requestId: 'req-role-noop-change',
    accessToken: operatorLogin.access_token,
    userId: 'platform-role-noop-user',
    roles: [
      {
        roleId: 'platform-view-member-admin',
        status: 'active',
        permission: {
          canViewMemberAdmin: true,
          canOperateMemberAdmin: false,
          canViewBilling: false,
          canOperateBilling: false
        }
      }
    ]
  });
  const afterUser = await service._internals.authStore.findUserById('platform-role-noop-user');

  assert.equal(Number(afterUser.sessionVersion), Number(beforeUser.sessionVersion));

  const authorized = await service.authorizeRoute({
    requestId: 'req-role-noop-old-access',
    accessToken: login.access_token,
    permissionCode: 'auth.session.logout',
    scope: 'session'
  });
  assert.equal(authorized.user_id, 'platform-role-noop-user');
});

test('platform role facts replace rejects unknown user id with invalid payload', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-existing-user',
        phone: '13810000403',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-missing-user-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-missing-user',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-missing-user',
        roles: []
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace rejects missing roles payload with invalid payload', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-missing-roles-user',
        phone: '13810000405',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-missing-roles-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-missing-roles',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-missing-roles-user'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace rejects role item without role_id', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-invalid-item-user',
        phone: '13810000406',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-invalid-item-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-invalid-item',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-invalid-item-user',
        roles: [{ status: 'active' }]
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace rejects non-string user_id', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: '123',
        phone: '13810000427',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-non-string-user-id-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-non-string-user-id',
        accessToken: operatorLogin.access_token,
        userId: 123,
        roles: []
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace rejects non-string role_id', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-non-string-role-id-user',
        phone: '13810000428',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-non-string-role-id-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-non-string-role-id',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-non-string-role-id-user',
        roles: [
          {
            role_id: 123,
            status: 'active'
          }
        ]
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace rejects unsupported role status', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-invalid-status-user',
        phone: '13810000408',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-invalid-status-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-invalid-status',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-invalid-status-user',
        roles: [
          {
            role_id: 'platform-member-admin',
            status: 'pending-approval'
          }
        ]
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace rejects blank role status', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-blank-status-user',
        phone: '13810000411',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-blank-status-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-blank-status',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-blank-status-user',
        roles: [
          {
            role_id: 'platform-member-admin',
            status: '   '
          }
        ]
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace rejects payload with more than 5 role facts', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-too-many-user',
        phone: '13810000412',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-too-many-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-too-many',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-too-many-user',
        roles: [
          { role_id: 'r-1' },
          { role_id: 'r-2' },
          { role_id: 'r-3' },
          { role_id: 'r-4' },
          { role_id: 'r-5' },
          { role_id: 'r-6' }
        ]
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace rejects role_id longer than 64 chars', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-too-long-user',
        phone: '13810000417',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-too-long-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-too-long',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-too-long-user',
        roles: [
          {
            role_id: 'r'.repeat(65),
            status: 'active'
          }
        ]
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace rejects non-boolean permission flags', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-invalid-permission-user',
        phone: '13810000423',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-invalid-permission-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-invalid-permission',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-invalid-permission-user',
        roles: [
          {
            role_id: 'platform-member-admin',
            status: 'active',
            permission: {
              can_operate_member_admin: 'true'
            }
          }
        ]
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace rejects non-object permission payload', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-invalid-permission-shape-user',
        phone: '13810000429',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-invalid-permission-shape-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-invalid-permission-shape',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-invalid-permission-shape-user',
        roles: [
          {
            role_id: 'platform-member-admin',
            status: 'active',
            permission: 'invalid'
          }
        ]
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace rejects top-level permission fields outside permission object', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-top-level-permission-user',
        phone: '13810000430',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-top-level-permission-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-top-level-permission',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-top-level-permission-user',
        roles: [
          {
            role_id: 'platform-member-admin',
            can_view_member_admin: true
          }
        ]
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace rejects duplicate role_id entries', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-duplicate-accepted-user',
        phone: '13810000413',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-duplicate-accepted-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-duplicate-accepted',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-duplicate-accepted-user',
        roles: [
          { role_id: 'r-1', status: 'active' },
          { role_id: 'r-2', status: 'active' },
          { role_id: 'r-3', status: 'active' },
          { role_id: 'r-4', status: 'active' },
          { role_id: 'r-5', status: 'active' },
          { role_id: 'r-5', status: 'disabled' }
        ]
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace rejects duplicate role_id entries regardless of case', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-duplicate-case-user',
        phone: '13810000415',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-duplicate-case-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-duplicate-case',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-duplicate-case-user',
        roles: [
          { role_id: 'Role-Case', status: 'active' },
          { role_id: 'role-case', status: 'disabled' }
        ]
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace resolves authorized session only once', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-single-auth-check-user',
        phone: '13810000431',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-single-auth-check-operator-login'
  );
  const authStore = service._internals.authStore;
  const originalFindSessionById = authStore.findSessionById;
  let findSessionByIdCallCount = 0;
  authStore.findSessionById = async (...args) => {
    findSessionByIdCallCount += 1;
    return originalFindSessionById(...args);
  };

  try {
    await service.replacePlatformRolesAndSyncSnapshot({
      requestId: 'req-role-single-auth-check',
      accessToken: operatorLogin.access_token,
      userId: 'platform-role-single-auth-check-user',
      roles: []
    });
    assert.equal(findSessionByIdCallCount, 1);
  } finally {
    authStore.findSessionById = originalFindSessionById;
  }
});

test('platform role facts replace audit includes actor and target identifiers', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'platform-role-audit-actor-user',
        phone: '13810000419',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-operate-member-admin',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'platform-role-audit-target-user',
        phone: '13810000420',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-view-member-admin',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-role-audit-login',
    phone: '13810000419',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  await service.replacePlatformRolesAndSyncSnapshot({
    requestId: 'req-role-audit-update',
    accessToken: login.access_token,
    userId: 'platform-role-audit-target-user',
    roles: []
  });

  const roleFactsAudit = service._internals.auditTrail.find(
    (event) => event.request_id === 'req-role-audit-update'
  );
  assert.ok(roleFactsAudit);
  assert.equal(roleFactsAudit.type, 'auth.platform_role_facts.updated');
  assert.equal(roleFactsAudit.user_id, 'platform-role-audit-target-user');
  assert.equal(roleFactsAudit.session_id, login.session_id);
  assert.equal(roleFactsAudit.actor_user_id, 'platform-role-audit-actor-user');
  assert.equal(roleFactsAudit.actor_session_id, login.session_id);
  assert.equal(roleFactsAudit.target_user_id, 'platform-role-audit-target-user');
});

test('platform role facts replace rejects caller without platform.member_admin.operate', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'platform-role-no-operate-actor',
        phone: '13810000421',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      },
      {
        id: 'platform-role-no-operate-target',
        phone: '13810000422',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-role-no-operate-login',
    phone: '13810000421',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-no-operate-replace',
        accessToken: login.access_token,
        userId: 'platform-role-no-operate-target',
        roles: []
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-FORBIDDEN');
      return true;
    }
  );

  const forbiddenAudit = service._internals.auditTrail.find(
    (event) => event.request_id === 'req-role-no-operate-replace'
  );
  assert.ok(forbiddenAudit);
  assert.equal(forbiddenAudit.type, 'auth.route.forbidden');
  assert.equal(forbiddenAudit.permission_code, 'platform.member_admin.operate');
});

test('platform role facts replace rejects authorizationContext mismatch when accessToken is provided', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'platform-role-context-mismatch-user',
        phone: '13810000414',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-role-context-mismatch-login',
    phone: '13810000414',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-context-mismatch',
        accessToken: login.access_token,
        userId: 'platform-role-context-mismatch-user',
        roles: [],
        authorizationContext: {
          session: { sessionId: `${login.session_id}-tampered` },
          user: { id: 'platform-role-context-mismatch-user' }
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
      return true;
    }
  );

  const contextMismatchAudit = service._internals.auditTrail.find(
    (event) => event.request_id === 'req-role-context-mismatch'
  );
  assert.ok(contextMismatchAudit);
  assert.equal(contextMismatchAudit.type, 'auth.access.invalid');
  assert.equal(contextMismatchAudit.user_id, 'platform-role-context-mismatch-user');
  assert.equal(contextMismatchAudit.session_id, `${login.session_id}-tampered`);
  assert.equal(
    contextMismatchAudit.disposition_reason,
    'access-authorization-context-mismatch'
  );
});

test('platform role facts replace fails closed when platform role catalog table is unavailable', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-catalog-missing-user',
        phone: '13810000428',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });

  service._internals.authStore.findPlatformRoleCatalogEntriesByRoleIds = async () => {
    const missingTableError = new Error(
      "Table 'neweast.platform_role_catalog' doesn't exist"
    );
    missingTableError.code = 'ER_NO_SUCH_TABLE';
    missingTableError.errno = 1146;
    throw missingTableError;
  };
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-catalog-missing-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-catalog-missing',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-catalog-missing-user',
        roles: [{ role_id: 'sys_admin', status: 'active' }],
        enforceRoleCatalogValidation: true
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(
        error.extensions.degradation_reason,
        'platform-role-catalog-unavailable'
      );
      return true;
    }
  );
});

test('platform role facts replace fails closed when platform role catalog table is unavailable', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-catalog-missing-empty-roles-user',
        phone: '13810000431',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });

  service._internals.authStore.findPlatformRoleCatalogEntriesByRoleIds = async () => {
    const missingTableError = new Error(
      "Table 'neweast.platform_role_catalog' doesn't exist"
    );
    missingTableError.code = 'ER_NO_SUCH_TABLE';
    missingTableError.errno = 1146;
    throw missingTableError;
  };
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-catalog-missing-empty-roles-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-catalog-missing-empty-roles',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-catalog-missing-empty-roles-user',
        roles: [{ role_id: 'sys_admin', status: 'active' }],
        enforceRoleCatalogValidation: true
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(
        error.extensions.degradation_reason,
        'platform-role-catalog-unavailable'
      );
      return true;
    }
  );
});

test('platform role facts replace fails closed when role catalog lookup capability is unavailable', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-catalog-unsupported-user',
        phone: '13810000429',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });

  delete service._internals.authStore.findPlatformRoleCatalogEntriesByRoleIds;
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-catalog-unsupported-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-catalog-unsupported',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-catalog-unsupported-user',
        roles: [{ role_id: 'sys_admin', status: 'active' }],
        enforceRoleCatalogValidation: true
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(
        error.extensions.degradation_reason,
        'platform-role-catalog-lookup-unsupported'
      );
      return true;
    }
  );
});

test('platform role facts replace fails closed when role catalog lookup capability is unavailable', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-catalog-unsupported-empty-roles-user',
        phone: '13810000432',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });

  service._internals.authStore.countPlatformRoleCatalogEntries = async () => 1;
  delete service._internals.authStore.findPlatformRoleCatalogEntriesByRoleIds;
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-catalog-unsupported-empty-roles-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-catalog-unsupported-empty-roles',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-catalog-unsupported-empty-roles-user',
        roles: [{ role_id: 'sys_admin', status: 'active' }],
        enforceRoleCatalogValidation: true
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(
        error.extensions.degradation_reason,
        'platform-role-catalog-lookup-unsupported'
      );
      return true;
    }
  );
});

test('platform role facts replace maps role catalog lookup query failures to AUTH-503-PLATFORM-SNAPSHOT-DEGRADED', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-catalog-query-failed-user',
        phone: '13810000430',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });

  service._internals.authStore.findPlatformRoleCatalogEntriesByRoleIds = async () => {
    throw new Error('platform role catalog query timeout');
  };
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-catalog-query-failed-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-catalog-query-failed',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-catalog-query-failed-user',
        roles: [{ role_id: 'sys_admin', status: 'active' }],
        enforceRoleCatalogValidation: true
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(
        error.extensions.degradation_reason,
        'platform-role-catalog-query-failed'
      );
      return true;
    }
  );
});

test('platform role facts replace maps db-deadlock reason to AUTH-503-PLATFORM-SNAPSHOT-DEGRADED', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-deadlock-user',
        phone: '13810000404',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });

  service._internals.authStore.replacePlatformRolesAndSyncSnapshot = async () => ({
    synced: false,
    reason: 'db-deadlock',
    permission: null
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-deadlock-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-deadlock',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-deadlock-user',
        roles: []
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(error.extensions.degradation_reason, 'db-deadlock');
      return true;
    }
  );
});

test('platform role facts replace maps mysql duplicate key error to AUTH-400-INVALID-PAYLOAD', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-duplicate-key-user',
        phone: '13810000416',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });

  service._internals.authStore.replacePlatformRolesAndSyncSnapshot = async () => {
    const duplicateKeyError = new Error(
      "Duplicate entry 'platform-role-duplicate-key-user-admin' for key 'uk_auth_user_platform_roles_user_role'"
    );
    duplicateKeyError.code = 'ER_DUP_ENTRY';
    duplicateKeyError.errno = 1062;
    throw duplicateKeyError;
  };
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-duplicate-key-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-duplicate-key',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-duplicate-key-user',
        roles: [{ role_id: 'admin', status: 'active' }]
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace maps mysql data-too-long error to AUTH-400-INVALID-PAYLOAD', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-data-too-long-user',
        phone: '13810000424',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });

  service._internals.authStore.replacePlatformRolesAndSyncSnapshot = async () => {
    const dataTooLongError = new Error("Data too long for column 'role_id' at row 1");
    dataTooLongError.code = 'ER_DATA_TOO_LONG';
    dataTooLongError.errno = 1406;
    throw dataTooLongError;
  };
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-data-too-long-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-data-too-long',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-data-too-long-user',
        roles: [{ role_id: 'admin', status: 'active' }]
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('platform role facts replace maps unknown sync reason to AUTH-503-PLATFORM-SNAPSHOT-DEGRADED', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-unknown-reason-user',
        phone: '13810000407',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });

  service._internals.authStore.replacePlatformRolesAndSyncSnapshot = async () => ({
    synced: false,
    reason: 'snapshot-write-missed',
    permission: null
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-unknown-reason-operator-login'
  );

  await assert.rejects(
    () =>
      service.replacePlatformRolesAndSyncSnapshot({
        requestId: 'req-role-unknown-reason',
        accessToken: operatorLogin.access_token,
        userId: 'platform-role-unknown-reason-user',
        roles: []
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(error.extensions.degradation_reason, 'snapshot-write-missed');
      return true;
    }
  );
});

test('replacePlatformRolePermissionGrants re-loads user role facts after write to avoid stale overwrite', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'platform-role-grants-stale-target',
        phone: '13810000433',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'role_alpha',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          },
          {
            roleId: 'role_beta',
            status: 'active',
            permission: {
              canViewMemberAdmin: false,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'role_alpha',
    code: 'ROLE_ALPHA',
    name: 'Role Alpha'
  });
  await service.createPlatformRoleCatalogEntry({
    roleId: 'role_beta',
    code: 'ROLE_BETA',
    name: 'Role Beta'
  });
  await service.replacePlatformRolePermissionGrants({
    requestId: 'req-role-permission-grants-stale-prime-role-beta',
    roleId: 'role_beta',
    permissionCodes: ['platform.billing.view'],
    operatorUserId: 'platform-role-grants-operator',
    operatorSessionId: 'platform-role-grants-operator-session'
  });

  const authStore = service._internals.authStore;
  const originalListUserIdsByPlatformRoleId = authStore.listUserIdsByPlatformRoleId;
  const originalListPlatformRoleFactsByUserId = authStore.listPlatformRoleFactsByUserId;
  const originalReplacePlatformRolesAndSyncSnapshot = authStore.replacePlatformRolesAndSyncSnapshot;

  let listRoleFactsCallCount = 0;
  let capturedSyncedRoles = null;
  authStore.listUserIdsByPlatformRoleId = async ({ roleId }) =>
    String(roleId || '').trim().toLowerCase() === 'role_alpha'
      ? ['platform-role-grants-stale-target']
      : [];
  authStore.listPlatformRoleFactsByUserId = async () => {
    listRoleFactsCallCount += 1;
    if (listRoleFactsCallCount === 1) {
      return [
        {
          roleId: 'role_alpha',
          status: 'active',
          permission: {
            canViewMemberAdmin: true,
            canOperateMemberAdmin: false,
            canViewBilling: false,
            canOperateBilling: false
          }
        },
        {
          roleId: 'role_beta',
          status: 'active',
          permission: {
            canViewMemberAdmin: false,
            canOperateMemberAdmin: false,
            canViewBilling: false,
            canOperateBilling: false
          }
        }
      ];
    }
    return [
      {
        roleId: 'role_alpha',
        status: 'active',
        permission: {
          canViewMemberAdmin: true,
          canOperateMemberAdmin: false,
          canViewBilling: false,
          canOperateBilling: false
        }
      },
      {
        roleId: 'role_beta',
        status: 'active',
        permission: {
          canViewMemberAdmin: false,
          canOperateMemberAdmin: false,
          canViewBilling: true,
          canOperateBilling: false
        }
      }
    ];
  };
  authStore.replacePlatformRolesAndSyncSnapshot = async ({ roles }) => {
    capturedSyncedRoles = roles;
    return {
      synced: true,
      reason: 'ok'
    };
  };

  try {
    const result = await service.replacePlatformRolePermissionGrants({
      requestId: 'req-role-permission-grants-stale-refresh',
      roleId: 'role_alpha',
      permissionCodes: ['platform.member_admin.view'],
      operatorUserId: 'platform-role-grants-operator',
      operatorSessionId: 'platform-role-grants-operator-session'
    });

    assert.equal(result.role_id, 'role_alpha');
    assert.equal(result.affected_user_count, 1);
    assert.equal(listRoleFactsCallCount, 2);
    assert.ok(Array.isArray(capturedSyncedRoles));
    const roleBeta = capturedSyncedRoles.find((role) => role.roleId === 'role_beta');
    assert.ok(roleBeta);
    assert.equal(roleBeta.permission.canViewBilling, true);
  } finally {
    authStore.listUserIdsByPlatformRoleId = originalListUserIdsByPlatformRoleId;
    authStore.listPlatformRoleFactsByUserId = originalListPlatformRoleFactsByUserId;
    authStore.replacePlatformRolesAndSyncSnapshot = originalReplacePlatformRolesAndSyncSnapshot;
  }
});

test('replacePlatformRolePermissionGrants re-computes non-target role permissions from grants source', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'platform-role-grants-source-target',
        phone: '13810000435',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'role_alpha',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          },
          {
            roleId: 'role_beta',
            status: 'active',
            permission: {
              canViewMemberAdmin: false,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'role_alpha',
    code: 'ROLE_ALPHA_GRANTS_SOURCE',
    name: 'Role Alpha Grants Source'
  });
  await service.createPlatformRoleCatalogEntry({
    roleId: 'role_beta',
    code: 'ROLE_BETA_GRANTS_SOURCE',
    name: 'Role Beta Grants Source'
  });

  await service.replacePlatformRolePermissionGrants({
    requestId: 'req-role-permission-grants-source-beta',
    roleId: 'role_beta',
    permissionCodes: ['platform.billing.view'],
    operatorUserId: 'platform-role-grants-operator',
    operatorSessionId: 'platform-role-grants-operator-session'
  });

  const authStore = service._internals.authStore;
  const originalListUserIdsByPlatformRoleId = authStore.listUserIdsByPlatformRoleId;
  const originalListPlatformRoleFactsByUserId = authStore.listPlatformRoleFactsByUserId;
  const originalReplacePlatformRolesAndSyncSnapshot = authStore.replacePlatformRolesAndSyncSnapshot;

  let capturedSyncedRoles = null;
  authStore.listUserIdsByPlatformRoleId = async ({ roleId }) =>
    String(roleId || '').trim().toLowerCase() === 'role_alpha'
      ? ['platform-role-grants-source-target']
      : [];
  authStore.listPlatformRoleFactsByUserId = async () => [
    {
      roleId: 'role_alpha',
      status: 'active',
      permission: {
        canViewMemberAdmin: true,
        canOperateMemberAdmin: false,
        canViewBilling: false,
        canOperateBilling: false
      }
    },
    {
      roleId: 'role_beta',
      status: 'active',
      permission: {
        canViewMemberAdmin: false,
        canOperateMemberAdmin: false,
        canViewBilling: false,
        canOperateBilling: false
      }
    }
  ];
  authStore.replacePlatformRolesAndSyncSnapshot = async ({ roles }) => {
    capturedSyncedRoles = roles;
    return {
      synced: true,
      reason: 'ok'
    };
  };

  try {
    const result = await service.replacePlatformRolePermissionGrants({
      requestId: 'req-role-permission-grants-source-alpha',
      roleId: 'role_alpha',
      permissionCodes: ['platform.member_admin.view'],
      operatorUserId: 'platform-role-grants-operator',
      operatorSessionId: 'platform-role-grants-operator-session'
    });

    assert.equal(result.role_id, 'role_alpha');
    assert.equal(result.affected_user_count, 1);
    assert.ok(Array.isArray(capturedSyncedRoles));
    const roleBeta = capturedSyncedRoles.find((role) => role.roleId === 'role_beta');
    assert.ok(roleBeta);
    assert.equal(roleBeta.permission.canViewBilling, true);
  } finally {
    authStore.listUserIdsByPlatformRoleId = originalListUserIdsByPlatformRoleId;
    authStore.listPlatformRoleFactsByUserId = originalListPlatformRoleFactsByUserId;
    authStore.replacePlatformRolesAndSyncSnapshot = originalReplacePlatformRolesAndSyncSnapshot;
  }
});

test('replacePlatformRolePermissionGrants maps invalid stored role facts to snapshot degraded error', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'platform-role-grants-invalid-role-fact-target',
        phone: '13810000436',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'role_alpha',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'role_alpha',
    code: 'ROLE_ALPHA_INVALID_FACT',
    name: 'Role Alpha Invalid Fact'
  });

  const authStore = service._internals.authStore;
  const originalListUserIdsByPlatformRoleId = authStore.listUserIdsByPlatformRoleId;
  const originalListPlatformRoleFactsByUserId = authStore.listPlatformRoleFactsByUserId;
  authStore.listUserIdsByPlatformRoleId = async ({ roleId }) =>
    String(roleId || '').trim().toLowerCase() === 'role_alpha'
      ? ['platform-role-grants-invalid-role-fact-target']
      : [];
  authStore.listPlatformRoleFactsByUserId = async () => [
    {
      roleId: '',
      status: 'active',
      permission: {
        canViewMemberAdmin: false,
        canOperateMemberAdmin: false,
        canViewBilling: false,
        canOperateBilling: false
      }
    }
  ];

  try {
    await assert.rejects(
      () =>
        service.replacePlatformRolePermissionGrants({
          requestId: 'req-role-permission-grants-invalid-role-facts',
          roleId: 'role_alpha',
          permissionCodes: ['platform.member_admin.view'],
          operatorUserId: 'platform-role-grants-operator',
          operatorSessionId: 'platform-role-grants-operator-session'
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.status, 503);
        assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
        assert.equal(
          error.extensions.degradation_reason,
          'platform-role-permission-role-facts-invalid'
        );
        return true;
      }
    );
  } finally {
    authStore.listUserIdsByPlatformRoleId = originalListUserIdsByPlatformRoleId;
    authStore.listPlatformRoleFactsByUserId = originalListPlatformRoleFactsByUserId;
  }
});

test('replacePlatformRolePermissionGrants accepts snake_case stored role_id when camelCase shadow key is undefined', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'platform-role-grants-shadow-role-id-target',
        phone: '13810000437',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'role_alpha',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'role_alpha',
    code: 'ROLE_ALPHA_SHADOW_ROLE_ID',
    name: 'Role Alpha Shadow Role Id'
  });

  const authStore = service._internals.authStore;
  const originalListUserIdsByPlatformRoleId = authStore.listUserIdsByPlatformRoleId;
  const originalListPlatformRoleFactsByUserId = authStore.listPlatformRoleFactsByUserId;
  const originalReplacePlatformRolesAndSyncSnapshot =
    authStore.replacePlatformRolesAndSyncSnapshot;

  authStore.listUserIdsByPlatformRoleId = async ({ roleId }) =>
    String(roleId || '').trim().toLowerCase() === 'role_alpha'
      ? ['platform-role-grants-shadow-role-id-target']
      : [];
  authStore.listPlatformRoleFactsByUserId = async () => [
    {
      roleId: undefined,
      role_id: 'role_alpha',
      status: 'active',
      permission: {
        canViewMemberAdmin: true,
        canOperateMemberAdmin: false,
        canViewBilling: false,
        canOperateBilling: false
      }
    }
  ];
  authStore.replacePlatformRolesAndSyncSnapshot = async () => ({
    synced: true,
    reason: 'ok'
  });

  try {
    const result = await service.replacePlatformRolePermissionGrants({
      requestId: 'req-role-permission-grants-shadow-role-id',
      roleId: 'role_alpha',
      permissionCodes: ['platform.member_admin.view'],
      operatorUserId: 'platform-role-grants-operator',
      operatorSessionId: 'platform-role-grants-operator-session'
    });

    assert.equal(result.role_id, 'role_alpha');
    assert.equal(result.affected_user_count, 1);
  } finally {
    authStore.listUserIdsByPlatformRoleId = originalListUserIdsByPlatformRoleId;
    authStore.listPlatformRoleFactsByUserId = originalListPlatformRoleFactsByUserId;
    authStore.replacePlatformRolesAndSyncSnapshot =
      originalReplacePlatformRolesAndSyncSnapshot;
  }
});

test('listPlatformRolePermissionGrants fails closed when grants dependency returns malformed shape', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  const authStore = service._internals.authStore;
  const originalListPlatformRolePermissionGrantsByRoleIds =
    authStore.listPlatformRolePermissionGrantsByRoleIds;
  authStore.listPlatformRolePermissionGrantsByRoleIds = async () => [
    {
      permissionCodes: ['platform.member_admin.view']
    }
  ];

  try {
    await assert.rejects(
      () =>
        service.listPlatformRolePermissionGrants({
          roleId: 'sys_admin'
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.status, 503);
        assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
        assert.equal(
          error.extensions.degradation_reason,
          'platform-role-permission-grants-invalid'
        );
        return true;
      }
    );
  } finally {
    authStore.listPlatformRolePermissionGrantsByRoleIds =
      originalListPlatformRolePermissionGrantsByRoleIds;
  }
});

test('listPlatformRolePermissionGrants fails closed when grants dependency contains empty permission code', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  const authStore = service._internals.authStore;
  const originalListPlatformRolePermissionGrantsByRoleIds =
    authStore.listPlatformRolePermissionGrantsByRoleIds;
  authStore.listPlatformRolePermissionGrantsByRoleIds = async () => [
    {
      roleId: 'sys_admin',
      permissionCodes: ['']
    }
  ];

  try {
    await assert.rejects(
      () =>
        service.listPlatformRolePermissionGrants({
          roleId: 'sys_admin'
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.status, 503);
        assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
        assert.equal(
          error.extensions.degradation_reason,
          'platform-role-permission-grants-invalid'
        );
        return true;
      }
    );
  } finally {
    authStore.listPlatformRolePermissionGrantsByRoleIds =
      originalListPlatformRolePermissionGrantsByRoleIds;
  }
});

test('replacePlatformRolePermissionGrants re-loads affected users after write and resyncs newly matched users', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'role_gamma',
    code: 'ROLE_GAMMA',
    name: 'Role Gamma'
  });

  const authStore = service._internals.authStore;
  const originalListUserIdsByPlatformRoleId = authStore.listUserIdsByPlatformRoleId;
  const originalListPlatformRoleFactsByUserId = authStore.listPlatformRoleFactsByUserId;
  const originalReplacePlatformRolesAndSyncSnapshot = authStore.replacePlatformRolesAndSyncSnapshot;

  let listUserIdsCallCount = 0;
  const syncedUserIds = [];
  authStore.listUserIdsByPlatformRoleId = async () => {
    listUserIdsCallCount += 1;
    return listUserIdsCallCount === 1
      ? ['platform-role-grants-user-a']
      : ['platform-role-grants-user-a', 'platform-role-grants-user-b'];
  };
  authStore.listPlatformRoleFactsByUserId = async () => [
    {
      roleId: 'role_gamma',
      status: 'active',
      permission: {
        canViewMemberAdmin: false,
        canOperateMemberAdmin: false,
        canViewBilling: false,
        canOperateBilling: false
      }
    }
  ];
  authStore.replacePlatformRolesAndSyncSnapshot = async ({ userId }) => {
    syncedUserIds.push(String(userId || '').trim());
    return {
      synced: true,
      reason: 'ok'
    };
  };

  try {
    const result = await service.replacePlatformRolePermissionGrants({
      requestId: 'req-role-permission-grants-reload-affected-users',
      roleId: 'role_gamma',
      permissionCodes: ['platform.member_admin.view'],
      operatorUserId: 'platform-role-grants-operator',
      operatorSessionId: 'platform-role-grants-operator-session'
    });

    assert.equal(listUserIdsCallCount, 2);
    assert.equal(result.affected_user_count, 2);
    assert.deepEqual(
      [...new Set(syncedUserIds)].sort((left, right) => left.localeCompare(right)),
      ['platform-role-grants-user-a', 'platform-role-grants-user-b']
    );
  } finally {
    authStore.listUserIdsByPlatformRoleId = originalListUserIdsByPlatformRoleId;
    authStore.listPlatformRoleFactsByUserId = originalListPlatformRoleFactsByUserId;
    authStore.replacePlatformRolesAndSyncSnapshot = originalReplacePlatformRolesAndSyncSnapshot;
  }
});

test('replacePlatformRolePermissionGrants rolls back grants and synced users when resync fails mid-flight', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'platform-role-grants-rollback-user-a',
        phone: '13810000456',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'role_delta',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'platform-role-grants-rollback-user-b',
        phone: '13810000457',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'role_delta',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'role_delta',
    code: 'ROLE_DELTA_ROLLBACK',
    name: 'Role Delta Rollback'
  });
  await service.replacePlatformRolePermissionGrants({
    requestId: 'req-role-permission-grants-rollback-prime',
    roleId: 'role_delta',
    permissionCodes: ['platform.member_admin.view'],
    operatorUserId: 'platform-role-grants-operator',
    operatorSessionId: 'platform-role-grants-operator-session'
  });

  const authStore = service._internals.authStore;
  const originalListUserIdsByPlatformRoleId = authStore.listUserIdsByPlatformRoleId;
  const originalListPlatformRoleFactsByUserId = authStore.listPlatformRoleFactsByUserId;
  const originalReplacePlatformRolesAndSyncSnapshot = authStore.replacePlatformRolesAndSyncSnapshot;

  const syncCallUserIds = [];
  let injectedFailure = false;
  authStore.listUserIdsByPlatformRoleId = async ({ roleId }) =>
    String(roleId || '').trim().toLowerCase() === 'role_delta'
      ? [
        'platform-role-grants-rollback-user-a',
        'platform-role-grants-rollback-user-b'
      ]
      : [];
  authStore.listPlatformRoleFactsByUserId = async ({ userId }) => [
    {
      roleId: 'role_delta',
      status: 'active',
      permission: {
        canViewMemberAdmin: true,
        canOperateMemberAdmin: false,
        canViewBilling: false,
        canOperateBilling: false
      }
    }
  ];
  authStore.replacePlatformRolesAndSyncSnapshot = async ({ userId }) => {
    const normalizedUserId = String(userId || '').trim();
    syncCallUserIds.push(normalizedUserId);
    if (
      normalizedUserId === 'platform-role-grants-rollback-user-b'
      && injectedFailure === false
    ) {
      injectedFailure = true;
      return {
        synced: false,
        reason: 'db-deadlock'
      };
    }
    return {
      synced: true,
      reason: 'ok'
    };
  };

  try {
    await assert.rejects(
      () =>
        service.replacePlatformRolePermissionGrants({
          requestId: 'req-role-permission-grants-rollback-failed',
          roleId: 'role_delta',
          permissionCodes: ['platform.billing.view'],
          operatorUserId: 'platform-role-grants-operator',
          operatorSessionId: 'platform-role-grants-operator-session'
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.status, 503);
        assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
        assert.equal(error.extensions.degradation_reason, 'db-deadlock');
        return true;
      }
    );

    const grantsAfterRollback = await service.listPlatformRolePermissionGrants({
      roleId: 'role_delta'
    });
    assert.deepEqual(
      grantsAfterRollback.permission_codes,
      ['platform.member_admin.view']
    );
    assert.deepEqual(
      syncCallUserIds,
      [
        'platform-role-grants-rollback-user-a',
        'platform-role-grants-rollback-user-b',
        'platform-role-grants-rollback-user-a'
      ]
    );
  } finally {
    authStore.listUserIdsByPlatformRoleId = originalListUserIdsByPlatformRoleId;
    authStore.listPlatformRoleFactsByUserId = originalListPlatformRoleFactsByUserId;
    authStore.replacePlatformRolesAndSyncSnapshot = originalReplacePlatformRolesAndSyncSnapshot;
  }
});

test('replacePlatformRolePermissionGrants loads grants in batch for affected users', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'platform-role-grants-batch-user-a',
        phone: '13810000458',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'role_epsilon',
            status: 'active',
            permission: {
              canViewMemberAdmin: false,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          },
          {
            roleId: 'role_zeta',
            status: 'active',
            permission: {
              canViewMemberAdmin: false,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'platform-role-grants-batch-user-b',
        phone: '13810000459',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'role_epsilon',
            status: 'active',
            permission: {
              canViewMemberAdmin: false,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          },
          {
            roleId: 'role_zeta',
            status: 'active',
            permission: {
              canViewMemberAdmin: false,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'role_epsilon',
    code: 'ROLE_EPSILON_BATCH',
    name: 'Role Epsilon Batch'
  });
  await service.createPlatformRoleCatalogEntry({
    roleId: 'role_zeta',
    code: 'ROLE_ZETA_BATCH',
    name: 'Role Zeta Batch'
  });
  await service.replacePlatformRolePermissionGrants({
    requestId: 'req-role-permission-grants-batch-prime-zeta',
    roleId: 'role_zeta',
    permissionCodes: ['platform.billing.view'],
    operatorUserId: 'platform-role-grants-operator',
    operatorSessionId: 'platform-role-grants-operator-session'
  });

  const authStore = service._internals.authStore;
  const originalListPlatformRolePermissionGrantsByRoleIds =
    authStore.listPlatformRolePermissionGrantsByRoleIds;
  const originalListUserIdsByPlatformRoleId = authStore.listUserIdsByPlatformRoleId;
  const originalListPlatformRoleFactsByUserId = authStore.listPlatformRoleFactsByUserId;
  const originalReplacePlatformRolesAndSyncSnapshot = authStore.replacePlatformRolesAndSyncSnapshot;

  let grantsLookupCallCount = 0;
  authStore.listPlatformRolePermissionGrantsByRoleIds = async (payload) => {
    grantsLookupCallCount += 1;
    return originalListPlatformRolePermissionGrantsByRoleIds(payload);
  };
  authStore.listUserIdsByPlatformRoleId = async ({ roleId }) =>
    String(roleId || '').trim().toLowerCase() === 'role_epsilon'
      ? [
        'platform-role-grants-batch-user-a',
        'platform-role-grants-batch-user-b'
      ]
      : [];
  authStore.listPlatformRoleFactsByUserId = async () => [
    {
      roleId: 'role_epsilon',
      status: 'active',
      permission: {
        canViewMemberAdmin: false,
        canOperateMemberAdmin: false,
        canViewBilling: false,
        canOperateBilling: false
      }
    },
    {
      roleId: 'role_zeta',
      status: 'active',
      permission: {
        canViewMemberAdmin: false,
        canOperateMemberAdmin: false,
        canViewBilling: false,
        canOperateBilling: false
      }
    }
  ];
  authStore.replacePlatformRolesAndSyncSnapshot = async () => ({
    synced: true,
    reason: 'ok'
  });

  try {
    const result = await service.replacePlatformRolePermissionGrants({
      requestId: 'req-role-permission-grants-batch-epsilon',
      roleId: 'role_epsilon',
      permissionCodes: ['platform.member_admin.view'],
      operatorUserId: 'platform-role-grants-operator',
      operatorSessionId: 'platform-role-grants-operator-session'
    });
    assert.equal(result.affected_user_count, 2);
    assert.equal(grantsLookupCallCount, 2);
  } finally {
    authStore.listPlatformRolePermissionGrantsByRoleIds =
      originalListPlatformRolePermissionGrantsByRoleIds;
    authStore.listUserIdsByPlatformRoleId = originalListUserIdsByPlatformRoleId;
    authStore.listPlatformRoleFactsByUserId = originalListPlatformRoleFactsByUserId;
    authStore.replacePlatformRolesAndSyncSnapshot = originalReplacePlatformRolesAndSyncSnapshot;
  }
});

test('replacePlatformRolePermissionGrants fails closed when atomic write result role_id mismatches request', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'platform_atomic_role_mismatch_target',
    code: 'PLATFORM_ATOMIC_ROLE_MISMATCH_TARGET',
    name: 'Platform Atomic Role Mismatch Target'
  });

  service._internals.authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'platform_atomic_role_mismatch_other',
    permissionCodes: ['platform.member_admin.view'],
    affectedUserIds: [],
    affectedUserCount: 0
  });

  await assert.rejects(
    () =>
      service.replacePlatformRolePermissionGrants({
        requestId: 'req-platform-role-permission-atomic-role-mismatch',
        roleId: 'platform_atomic_role_mismatch_target',
        permissionCodes: ['platform.member_admin.view'],
        operatorUserId: 'platform-role-grants-operator',
        operatorSessionId: 'platform-role-grants-operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(
        error.extensions.degradation_reason,
        'platform-role-permission-grants-update-role-mismatch'
      );
      return true;
    }
  );
});

test('replacePlatformRolePermissionGrants accepts snake_case atomic write fields when camelCase shadow keys are undefined', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'platform_atomic_shadow_fields_target',
    code: 'PLATFORM_ATOMIC_SHADOW_FIELDS_TARGET',
    name: 'Platform Atomic Shadow Fields Target'
  });

  const authStore = service._internals.authStore;
  const originalReplaceAtomic =
    authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots;
  authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: undefined,
    role_id: 'platform_atomic_shadow_fields_target',
    permissionCodes: undefined,
    permission_codes: ['platform.member_admin.view'],
    affectedUserIds: undefined,
    affected_user_ids: [],
    affectedUserCount: undefined,
    affected_user_count: 0
  });

  try {
    const result = await service.replacePlatformRolePermissionGrants({
      requestId: 'req-platform-role-permission-atomic-shadow-fields',
      roleId: 'platform_atomic_shadow_fields_target',
      permissionCodes: ['platform.member_admin.view'],
      operatorUserId: 'platform-role-grants-operator',
      operatorSessionId: 'platform-role-grants-operator-session'
    });

    assert.equal(result.role_id, 'platform_atomic_shadow_fields_target');
    assert.deepEqual(result.permission_codes, ['platform.member_admin.view']);
    assert.equal(result.affected_user_count, 0);
  } finally {
    authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots =
      originalReplaceAtomic;
  }
});

test('replacePlatformRolePermissionGrants fails closed when atomic write result permission codes contain surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'platform_atomic_permission_whitespace_target',
    code: 'PLATFORM_ATOMIC_PERMISSION_WHITESPACE_TARGET',
    name: 'Platform Atomic Permission Whitespace Target'
  });

  service._internals.authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'platform_atomic_permission_whitespace_target',
    permissionCodes: [' platform.member_admin.view'],
    affectedUserIds: [],
    affectedUserCount: 0
  });

  await assert.rejects(
    () =>
      service.replacePlatformRolePermissionGrants({
        requestId: 'req-platform-role-permission-atomic-permission-whitespace',
        roleId: 'platform_atomic_permission_whitespace_target',
        permissionCodes: ['platform.member_admin.view'],
        operatorUserId: 'platform-role-grants-operator',
        operatorSessionId: 'platform-role-grants-operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(
        error.extensions.degradation_reason,
        'platform-role-permission-grants-update-invalid'
      );
      return true;
    }
  );
});

test('replacePlatformRolePermissionGrants fails closed when atomic write result omits affected user metadata', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'platform_atomic_missing_affected_metadata_target',
    code: 'PLATFORM_ATOMIC_MISSING_AFFECTED_METADATA_TARGET',
    name: 'Platform Atomic Missing Affected Metadata Target'
  });

  service._internals.authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'platform_atomic_missing_affected_metadata_target',
    permissionCodes: ['platform.member_admin.view']
  });

  await assert.rejects(
    () =>
      service.replacePlatformRolePermissionGrants({
        requestId: 'req-platform-role-permission-atomic-affected-metadata-missing',
        roleId: 'platform_atomic_missing_affected_metadata_target',
        permissionCodes: ['platform.member_admin.view'],
        operatorUserId: 'platform-role-grants-operator',
        operatorSessionId: 'platform-role-grants-operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(
        error.extensions.degradation_reason,
        'platform-role-permission-grants-update-affected-user-metadata-missing'
      );
      return true;
    }
  );
});

test('replacePlatformRolePermissionGrants fails closed when atomic write result affected user count mismatches affected user ids', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'platform_atomic_affected_count_mismatch_target',
    code: 'PLATFORM_ATOMIC_AFFECTED_COUNT_MISMATCH_TARGET',
    name: 'Platform Atomic Affected Count Mismatch Target'
  });

  service._internals.authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'platform_atomic_affected_count_mismatch_target',
    permissionCodes: ['platform.member_admin.view'],
    affectedUserIds: ['platform-role-grants-user-a'],
    affectedUserCount: 2
  });

  await assert.rejects(
    () =>
      service.replacePlatformRolePermissionGrants({
        requestId: 'req-platform-role-permission-atomic-affected-count-mismatch',
        roleId: 'platform_atomic_affected_count_mismatch_target',
        permissionCodes: ['platform.member_admin.view'],
        operatorUserId: 'platform-role-grants-operator',
        operatorSessionId: 'platform-role-grants-operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(
        error.extensions.degradation_reason,
        'platform-role-permission-grants-update-affected-user-count-invalid'
      );
      return true;
    }
  );
});

test('replacePlatformRolePermissionGrants skips out-of-transaction audit fallback when atomic store reports audit_recorded', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'platform_atomic_audit_recorded_target',
    code: 'PLATFORM_ATOMIC_AUDIT_RECORDED_TARGET',
    name: 'Platform Atomic Audit Recorded Target'
  });

  const authStore = service._internals.authStore;
  const originalReplaceAtomic =
    authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots;
  const originalRecordAuditEvent = authStore.recordAuditEvent;
  authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots = async ({
    roleId,
    permissionCodes,
    auditContext
  }) => {
    assert.equal(roleId, 'platform_atomic_audit_recorded_target');
    assert.deepEqual(permissionCodes, ['platform.member_admin.view']);
    assert.equal(typeof auditContext, 'object');
    assert.equal(
      String(auditContext?.requestId || ''),
      'req-platform-role-permission-atomic-audit-recorded'
    );
    assert.equal(String(auditContext?.actorUserId || ''), 'platform-role-facts-operator');
    assert.equal(String(auditContext?.actorSessionId || ''), 'platform-role-facts-session');
    return {
      roleId: 'platform_atomic_audit_recorded_target',
      permissionCodes: ['platform.member_admin.view'],
      affectedUserIds: [],
      affectedUserCount: 0,
      audit_recorded: true
    };
  };
  authStore.recordAuditEvent = async () => {
    throw new Error('recordAuditEvent-should-not-be-called');
  };

  try {
    const result = await service.replacePlatformRolePermissionGrants({
      requestId: 'req-platform-role-permission-atomic-audit-recorded',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
      roleId: 'platform_atomic_audit_recorded_target',
      permissionCodes: ['platform.member_admin.view'],
      operatorUserId: 'platform-role-facts-operator',
      operatorSessionId: 'platform-role-facts-session'
    });

    assert.deepEqual(result, {
      role_id: 'platform_atomic_audit_recorded_target',
      permission_codes: ['platform.member_admin.view'],
      affected_user_count: 0
    });
  } finally {
    authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots =
      originalReplaceAtomic;
    authStore.recordAuditEvent = originalRecordAuditEvent;
  }
});

test('replacePlatformRolePermissionGrants maps ERR_AUDIT_WRITE_FAILED from atomic store to platform snapshot degraded', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'platform_atomic_audit_failed_target',
    code: 'PLATFORM_ATOMIC_AUDIT_FAILED_TARGET',
    name: 'Platform Atomic Audit Failed Target'
  });

  service._internals.authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots = async () => {
    const error = new Error('platform-atomic-audit-write-failed');
    error.code = 'ERR_AUDIT_WRITE_FAILED';
    throw error;
  };

  await assert.rejects(
    () =>
      service.replacePlatformRolePermissionGrants({
        requestId: 'req-platform-role-permission-atomic-audit-failed',
        roleId: 'platform_atomic_audit_failed_target',
        permissionCodes: ['platform.member_admin.view'],
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(error.extensions?.degradation_reason, 'audit-write-failed');
      return true;
    }
  );
});

test('platform role facts replace canonicalizes role_id to lowercase under role catalog validation', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-role-canonical-target',
        phone: '13810000434',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: []
      }
    ]
  });

  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-role-facts-canonical-operator-login'
  );

  const replaceResult = await service.replacePlatformRolesAndSyncSnapshot({
    requestId: 'req-role-facts-canonical-replace',
    accessToken: operatorLogin.access_token,
    userId: 'platform-role-canonical-target',
    roles: [{ role_id: 'SYS_ADMIN', status: 'active' }],
    enforceRoleCatalogValidation: true
  });
  assert.equal(replaceResult.reason, 'ok');

  const persistedRoleFacts = await service._internals.authStore.listPlatformRoleFactsByUserId({
    userId: 'platform-role-canonical-target'
  });
  assert.equal(persistedRoleFacts.length, 1);
  assert.equal(persistedRoleFacts[0].roleId, 'sys_admin');
  assert.equal(persistedRoleFacts[0].role_id, 'sys_admin');
});

test('change password mismatch audit includes masked phone metadata', async () => {
  const service = createService();

  const session = await service.login({
    requestId: 'req-login-9',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  await assert.rejects(
    () =>
      service.changePassword({
        requestId: 'req-change-2',
        accessToken: session.access_token,
        currentPassword: 'wrong-password',
        newPassword: 'Passw0rd!2027'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      return true;
    }
  );

  const lastAudit = service._internals.auditTrail[service._internals.auditTrail.length - 1];
  assert.equal(lastAudit.type, 'auth.password_change.rejected');
  assert.equal(lastAudit.phone_masked, '138****0000');
});

test('sendOtp fails closed and logs cooldown_check_failed audit when getSentAt throws', async () => {
  let upsertCalled = false;
  const failingOtpStore = {
    upsertOtp: async () => {
      upsertCalled = true;
      return { sent_at_ms: Date.now() };
    },
    getSentAt: async () => {
      throw new Error('Redis connection failed');
    },
    verifyAndConsumeOtp: async () => ({ ok: false, reason: 'missing' })
  };

  const service = createAuthService({
    seedUsers,
    otpStore: failingOtpStore
  });

  await assert.rejects(
    () =>
      service.sendOtp({
        requestId: 'req-otp-fail',
        phone: '13800000000'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 429);
      assert.equal(error.errorCode, 'AUTH-429-RATE-LIMITED');
      assert.equal(error.extensions.rate_limit_action, 'otp_send');
      assert.equal(error.extensions.retry_after_seconds, 60);
      assert.equal(error.extensions.rate_limit_limit, 1);
      assert.equal(error.extensions.rate_limit_window_seconds, 60);
      return true;
    }
  );

  assert.equal(upsertCalled, false);

  const auditEvents = service._internals.auditTrail;
  const cooldownFailedEvent = auditEvents.find(
    (e) => e.type === 'auth.otp.send.cooldown_check_failed'
  );
  assert.ok(cooldownFailedEvent, 'should have cooldown_check_failed audit event');
  assert.equal(cooldownFailedEvent.detail, 'getSentAt failed: Redis connection failed');
});

test('sendOtp normalizes string getSentAt value and keeps cooldown seconds bounded', async () => {
  const nowMs = Date.UTC(2026, 0, 1, 0, 0, 0);
  let upsertCalled = false;

  const otpStore = {
    upsertOtp: async () => {
      upsertCalled = true;
      return { sent_at_ms: nowMs };
    },
    getSentAt: async () => String(nowMs - 30 * 1000),
    verifyAndConsumeOtp: async () => ({ ok: false, reason: 'missing' })
  };

  const service = createAuthService({
    seedUsers,
    now: () => nowMs,
    otpStore
  });

  await assert.rejects(
    () =>
      service.sendOtp({
        requestId: 'req-otp-string-sent-at',
        phone: '13800000000'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 429);
      assert.equal(error.errorCode, 'AUTH-429-RATE-LIMITED');
      assert.equal(error.extensions.rate_limit_action, 'otp_send');
      assert.equal(error.extensions.retry_after_seconds, 30);
      assert.ok(error.extensions.retry_after_seconds <= 60);
      return true;
    }
  );

  assert.equal(upsertCalled, false);
});

test('authorizeRoute returns AUTH-403-FORBIDDEN when tenant permission snapshot denies action', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'route-authz-user',
        phone: '13830000000',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [
          { tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA },
          { tenantId: 'tenant-b', tenantName: 'Tenant B', permission: tenantPermissionB }
        ]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-route-authz-login',
    phone: '13830000000',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });
  await service.selectTenant({
    requestId: 'req-route-authz-select',
    accessToken: login.access_token,
    tenantId: 'tenant-b'
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-route-authz-forbidden',
        accessToken: login.access_token,
        permissionCode: 'tenant.member_admin.operate',
        scope: 'tenant'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-FORBIDDEN');
      return true;
    }
  );
});

test('authorizeRoute returns AUTH-403-FORBIDDEN when operate=true but view=false (operate implies view)', async () => {
  const operateWithoutViewPermission = {
    scopeLabel: '组织权限 operate-no-view',
    canViewMemberAdmin: false,
    canOperateMemberAdmin: true,
    canViewBilling: false,
    canOperateBilling: true
  };

  const service = createAuthService({
    seedUsers: [
      {
        id: 'route-authz-ov-user',
        phone: '13830000099',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [
          { tenantId: 'tenant-ov', tenantName: 'Tenant OV', permission: operateWithoutViewPermission }
        ]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-ov-login',
    phone: '13830000099',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-ov-member-admin',
        accessToken: login.access_token,
        permissionCode: 'tenant.member_admin.operate',
        scope: 'tenant'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-FORBIDDEN');
      return true;
    }
  );

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-ov-billing',
        accessToken: login.access_token,
        permissionCode: 'tenant.billing.operate',
        scope: 'tenant'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-FORBIDDEN');
      return true;
    }
  );
});

test('authorizeRoute returns AUTH-403-NO-DOMAIN for tenant scoped route in platform entry', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'route-authz-platform-user',
        phone: '13830000001',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [{ tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA }]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-route-authz-platform-login',
    phone: '13830000001',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-route-authz-no-domain',
        accessToken: login.access_token,
        permissionCode: 'tenant.context.switch',
        scope: 'tenant'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );
});

test('authorizeRoute returns AUTH-403-NO-DOMAIN for tenant scoped route when active_tenant_id is missing', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'route-authz-tenant-unselected-user',
        phone: '13830000003',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [
          { tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA },
          { tenantId: 'tenant-b', tenantName: 'Tenant B', permission: tenantPermissionB }
        ]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-route-authz-tenant-unselected-login',
    phone: '13830000003',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });
  assert.equal(login.active_tenant_id, null);
  assert.equal(login.tenant_selection_required, true);

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-route-authz-tenant-unselected-no-domain',
        accessToken: login.access_token,
        permissionCode: 'tenant.member_admin.view',
        scope: 'tenant'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );
});

test('authorizeRoute session-scope succeeds without loading tenant permission context', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'session-scope-user',
        phone: '13830000077',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [
          { tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA }
        ]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-ss-login',
    phone: '13830000077',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  // Session-scope authorizeRoute should succeed without loading tenant permission context
  const result = await service.authorizeRoute({
    requestId: 'req-ss-logout',
    accessToken: login.access_token,
    permissionCode: 'auth.session.logout',
    scope: 'session'
  });

  assert.equal(result.session_id, login.session_id);
  assert.equal(result.user_id, 'session-scope-user');
  assert.equal(result.tenant_permission_context, null);
});

test('authorizeRoute returns AUTH-403-NO-DOMAIN for platform scoped route in tenant entry', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'route-authz-tenant-entry-user',
        phone: '13830000055',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [
          { tenantId: 'tenant-a', tenantName: 'Tenant A', permission: tenantPermissionA }
        ],
        platformPermission: {
          scopeLabel: '平台权限快照',
          canViewMemberAdmin: true,
          canOperateMemberAdmin: true,
          canViewBilling: true,
          canOperateBilling: true
        }
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-route-authz-tenant-entry-login',
    phone: '13830000055',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-route-authz-platform-no-domain',
        accessToken: login.access_token,
        permissionCode: 'platform.member_admin.view',
        scope: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );
});

test('authorizeRoute is fail-closed for platform scope when platform role facts are absent', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'route-authz-platform-missing-snapshot-user',
        phone: '13830000057',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform']
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-route-authz-platform-missing-snapshot-login',
    phone: '13830000057',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-route-authz-platform-missing-snapshot',
        accessToken: login.access_token,
        permissionCode: 'platform.member_admin.view',
        scope: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-FORBIDDEN');
      return true;
    }
  );

  const forbidden = service._internals.auditTrail.find(
    (event) =>
      event.type === 'auth.route.forbidden'
      && event.detail === 'permission denied: platform.member_admin.view'
  );
  assert.ok(forbidden);
  assert.equal(forbidden.permission_code, 'platform.member_admin.view');
});

test('authorizeRoute clears stale platform snapshot when role facts are empty', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'route-authz-platform-stale-snapshot-user',
        phone: '13830000058',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformPermission: {
          scopeLabel: '平台权限快照（历史）',
          canViewMemberAdmin: true,
          canOperateMemberAdmin: true,
          canViewBilling: false,
          canOperateBilling: false
        }
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-route-authz-platform-stale-snapshot-login',
    phone: '13830000058',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-route-authz-platform-stale-snapshot',
        accessToken: login.access_token,
        permissionCode: 'platform.member_admin.view',
        scope: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-FORBIDDEN');
      return true;
    }
  );

  const forbidden = service._internals.auditTrail.find(
    (event) =>
      event.type === 'auth.route.forbidden'
      && event.permission_code === 'platform.member_admin.view'
      && event.detail === 'permission denied: platform.member_admin.view'
  );
  assert.ok(forbidden);
});

test('authorizeRoute fails closed with 503 when platform snapshot sync reports db-deadlock exhaustion', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'route-authz-platform-deadlock-user',
        phone: '13830000060',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformPermission: {
          scopeLabel: '平台权限快照',
          canViewMemberAdmin: true,
          canOperateMemberAdmin: true,
          canViewBilling: true,
          canOperateBilling: true
        }
      }
    ]
  });

  service._internals.authStore.syncPlatformPermissionSnapshotByUserId = async () => ({
    synced: false,
    reason: 'db-deadlock',
    permission: null
  });

  const login = await service.login({
    requestId: 'req-route-authz-platform-deadlock-login',
    phone: '13830000060',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-route-authz-platform-deadlock',
        accessToken: login.access_token,
        permissionCode: 'platform.member_admin.view',
        scope: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(error.extensions?.degradation_reason, 'db-deadlock');
      return true;
    }
  );

  const degraded = service._internals.auditTrail.find(
    (event) =>
      event.type === 'auth.platform.snapshot.degraded'
      && event.permission_code === 'platform.member_admin.view'
      && event.degradation_reason === 'db-deadlock'
  );
  assert.ok(degraded);
});

test('authorizeRoute fails closed with 503 when platform snapshot sync remains concurrent after retry', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'route-authz-platform-concurrent-user',
        phone: '13830000061',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformPermission: {
          scopeLabel: '平台权限快照',
          canViewMemberAdmin: true,
          canOperateMemberAdmin: true,
          canViewBilling: false,
          canOperateBilling: false
        }
      }
    ]
  });

  let syncCallCount = 0;
  service._internals.authStore.syncPlatformPermissionSnapshotByUserId = async () => {
    syncCallCount += 1;
    return {
      synced: false,
      reason: 'concurrent-role-facts-update',
      permission: null
    };
  };

  const login = await service.login({
    requestId: 'req-route-authz-platform-concurrent-login',
    phone: '13830000061',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-route-authz-platform-concurrent',
        accessToken: login.access_token,
        permissionCode: 'platform.member_admin.view',
        scope: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(error.extensions?.degradation_reason, 'concurrent-role-facts-update');
      return true;
    }
  );
  assert.equal(syncCallCount, 2);

  const degraded = service._internals.auditTrail.find(
    (event) =>
      event.type === 'auth.platform.snapshot.degraded'
      && event.permission_code === 'platform.member_admin.view'
      && event.degradation_reason === 'concurrent-role-facts-update'
  );
  assert.ok(degraded);
});

test('authorizeRoute fails closed with 503 when platform snapshot sync returns unknown reason', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'route-authz-platform-unknown-sync-user',
        phone: '13830000062',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformPermission: {
          scopeLabel: '平台权限快照',
          canViewMemberAdmin: true,
          canOperateMemberAdmin: true,
          canViewBilling: true,
          canOperateBilling: true
        }
      }
    ]
  });

  service._internals.authStore.syncPlatformPermissionSnapshotByUserId = async () => ({
    synced: false,
    reason: 'unexpected-sync-state',
    permission: null
  });

  const login = await service.login({
    requestId: 'req-route-authz-platform-unknown-sync-login',
    phone: '13830000062',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-route-authz-platform-unknown-sync',
        accessToken: login.access_token,
        permissionCode: 'platform.member_admin.view',
        scope: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(error.extensions?.degradation_reason, 'unexpected-sync-state');
      return true;
    }
  );

  const degraded = service._internals.auditTrail.find(
    (event) =>
      event.type === 'auth.platform.snapshot.degraded'
      && event.permission_code === 'platform.member_admin.view'
      && event.degradation_reason === 'unexpected-sync-state'
  );
  assert.ok(degraded);
});

test('authorizeRoute fails closed with 503 when platform snapshot sync reason is empty', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'route-authz-platform-empty-sync-user',
        phone: '13830000063',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformPermission: {
          scopeLabel: '平台权限快照',
          canViewMemberAdmin: true,
          canOperateMemberAdmin: true,
          canViewBilling: true,
          canOperateBilling: true
        }
      }
    ]
  });

  service._internals.authStore.syncPlatformPermissionSnapshotByUserId = async () => ({
    synced: false,
    reason: '   ',
    permission: null
  });

  const login = await service.login({
    requestId: 'req-route-authz-platform-empty-sync-login',
    phone: '13830000063',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-route-authz-platform-empty-sync',
        accessToken: login.access_token,
        permissionCode: 'platform.member_admin.view',
        scope: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      assert.equal(error.extensions?.degradation_reason, 'unknown');
      return true;
    }
  );

  const degraded = service._internals.auditTrail.find(
    (event) =>
      event.type === 'auth.platform.snapshot.degraded'
      && event.permission_code === 'platform.member_admin.view'
      && event.degradation_reason === 'unknown'
  );
  assert.ok(degraded);
});

test('authorizeRoute uses platform role union and ignores explicit deny flags', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'route-authz-platform-union-user',
        phone: '13830000056',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-view',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          },
          {
            roleId: 'platform-operate',
            status: 'active',
            permission: {
              canViewMemberAdmin: false,
              canOperateMemberAdmin: true,
              canViewBilling: true,
              canOperateBilling: false,
              denyMemberAdminOperate: true
            }
          },
          {
            roleId: 'platform-disabled',
            status: 'disabled',
            permission: {
              canViewMemberAdmin: false,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-route-authz-platform-union-login',
    phone: '13830000056',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  const result = await service.authorizeRoute({
    requestId: 'req-route-authz-platform-union',
    accessToken: login.access_token,
    permissionCode: 'platform.member_admin.operate',
    scope: 'platform'
  });

  assert.equal(result.session_id, login.session_id);
  assert.equal(result.user_id, 'route-authz-platform-union-user');
});

test('authorizeRoute deduplicates duplicate platform role_id facts using latest payload', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'route-authz-platform-duplicate-role-user',
        phone: '13830000059',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-dup',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          },
          {
            roleId: 'platform-dup',
            status: 'active',
            permission: {
              canViewMemberAdmin: false,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  const login = await service.login({
    requestId: 'req-route-authz-platform-duplicate-role-login',
    phone: '13830000059',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-route-authz-platform-duplicate-role',
        accessToken: login.access_token,
        permissionCode: 'platform.member_admin.view',
        scope: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-FORBIDDEN');
      return true;
    }
  );
});

test('provisionPlatformUserByPhone creates user with hashed default credential and allows first login without forced password change', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-default-password-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-provision-platform-operator-login'
  );
  const provisionResult = await service.provisionPlatformUserByPhone({
    requestId: 'req-provision-platform-new-user',
    accessToken: operatorLogin.access_token,
    phone: '13835550000'
  });
  assert.equal(provisionResult.created_user, true);
  assert.equal(provisionResult.reused_existing_user, false);
  assert.equal(provisionResult.credential_initialized, true);
  assert.equal(provisionResult.first_login_force_password_change, false);
  assert.equal(provisionResult.entry_domain, 'platform');

  const provisionedUser = await service._internals.authStore.findUserByPhone('13835550000');
  assert.ok(provisionedUser);
  assert.ok(String(provisionedUser.passwordHash || '').startsWith('pbkdf2$'));
  assert.notEqual(provisionedUser.passwordHash, defaultPassword);

  const loginResult = await service.login({
    requestId: 'req-provision-platform-login',
    phone: '13835550000',
    password: defaultPassword,
    entryDomain: 'platform'
  });
  assert.equal(loginResult.request_id, 'req-provision-platform-login');
  assert.equal(Object.prototype.hasOwnProperty.call(loginResult, 'force_password_change_required'), false);
});

test('provisionPlatformUserByPhone accepts pre-authorized route context without access token', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-platform-authorized-route-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-provision-platform-authorized-route-operator-login'
  );

  const provisionResult = await service.provisionPlatformUserByPhone({
    requestId: 'req-provision-platform-authorized-route',
    phone: '13835550098',
    authorizedRoute: {
      user_id: 'platform-role-facts-operator',
      session_id: operatorLogin.session_id,
      entry_domain: 'platform',
      active_tenant_id: null
    }
  });

  assert.equal(provisionResult.created_user, true);
  assert.equal(provisionResult.reused_existing_user, false);
  assert.equal(provisionResult.entry_domain, 'platform');
  assert.equal(provisionResult.request_id, 'req-provision-platform-authorized-route');
});

test('provisionPlatformUserByPhone rejects tenantName payload with AUTH-400-INVALID-PAYLOAD', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-platform-tenant-name-invalid-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-provision-platform-tenant-name-invalid-operator-login'
  );

  await assert.rejects(
    () =>
      service.provisionPlatformUserByPhone({
        requestId: 'req-provision-platform-tenant-name-invalid',
        accessToken: operatorLogin.access_token,
        phone: '13835550044',
        tenantName: 'Tenant Should Not Be Accepted'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('provisionPlatformUserByPhone rejects unknown payload fields with AUTH-400-INVALID-PAYLOAD', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-platform-unknown-field-invalid-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-provision-platform-unknown-field-operator-login'
  );

  await assert.rejects(
    () =>
      service.provisionPlatformUserByPhone({
        requestId: 'req-provision-platform-unknown-field-invalid',
        accessToken: operatorLogin.access_token,
        payload: {
          phone: '13835550043',
          extra_flag: true
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('provisionPlatformUserByPhone reuses existing user without mutating password hash and rejects duplicate relationship requests', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-reuse-default-password-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'provision-reuse-target',
        phone: '13835550001',
        password: 'Passw0rd!',
        status: 'active',
        domains: []
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-provision-platform-reuse-operator-login'
  );
  const previousUser = await service._internals.authStore.findUserByPhone('13835550001');
  const previousPasswordHash = previousUser.passwordHash;

  const firstProvision = await service.provisionPlatformUserByPhone({
    requestId: 'req-provision-platform-reuse-first',
    accessToken: operatorLogin.access_token,
    phone: '13835550001'
  });
  assert.equal(firstProvision.created_user, false);
  assert.equal(firstProvision.reused_existing_user, true);

  const currentUser = await service._internals.authStore.findUserByPhone('13835550001');
  assert.equal(currentUser.passwordHash, previousPasswordHash);

  await assert.rejects(
    () =>
      service.provisionPlatformUserByPhone({
        requestId: 'req-provision-platform-reuse-duplicate',
        accessToken: operatorLogin.access_token,
        phone: '13835550001'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 409);
      assert.equal(error.errorCode, 'AUTH-409-PROVISION-CONFLICT');
      return true;
    }
  );
});

test('provisionPlatformUserByPhone returns conflict when platform relationship is concurrently provisioned', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-platform-race-default-password-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'provision-platform-race-target',
        phone: '13835550012',
        password: 'LegacyPass!2026',
        status: 'active',
        domains: []
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });
  const authStore = service._internals.authStore;
  const originalFindDomainAccessByUserId = authStore.findDomainAccessByUserId.bind(authStore);
  const originalEnsureDefaultDomainAccessForUser = authStore.ensureDefaultDomainAccessForUser
    .bind(authStore);
  let targetDomainAccessLookupCount = 0;

  authStore.findDomainAccessByUserId = async (userId) => {
    if (String(userId) === 'provision-platform-race-target') {
      targetDomainAccessLookupCount += 1;
      if (targetDomainAccessLookupCount === 1) {
        return { platform: false, tenant: false };
      }
      return { platform: true, tenant: false };
    }
    return originalFindDomainAccessByUserId(userId);
  };
  authStore.ensureDefaultDomainAccessForUser = async (userId) => {
    if (String(userId) === 'provision-platform-race-target') {
      return { inserted: false };
    }
    return originalEnsureDefaultDomainAccessForUser(userId);
  };

  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-provision-platform-race-operator-login'
  );

  await assert.rejects(
    () =>
      service.provisionPlatformUserByPhone({
        requestId: 'req-provision-platform-race',
        accessToken: operatorLogin.access_token,
        phone: '13835550012'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 409);
      assert.equal(error.errorCode, 'AUTH-409-PROVISION-CONFLICT');
      return true;
    }
  );
});

test('provisionPlatformUserByPhone returns success when concurrent provisioning already committed relationship for newly created user', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-platform-race-preserve-user-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });
  const authStore = service._internals.authStore;
  const originalEnsureDefaultDomainAccessForUser = authStore.ensureDefaultDomainAccessForUser
    .bind(authStore);
  const originalDeleteUserById = authStore.deleteUserById.bind(authStore);
  const racePhone = '13835550092';
  let preservedUserId = null;
  let deleteAttempts = 0;

  authStore.ensureDefaultDomainAccessForUser = async (userId) => {
    const foundUser = await authStore.findUserById(userId);
    if (foundUser?.phone === racePhone) {
      preservedUserId = String(userId);
      await originalEnsureDefaultDomainAccessForUser(userId);
      return { inserted: false };
    }
    return originalEnsureDefaultDomainAccessForUser(userId);
  };
  authStore.deleteUserById = async (userId) => {
    deleteAttempts += 1;
    return originalDeleteUserById(userId);
  };

  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-provision-platform-race-preserve-operator-login'
  );

  const provisioned = await service.provisionPlatformUserByPhone({
    requestId: 'req-provision-platform-race-preserve',
    accessToken: operatorLogin.access_token,
    phone: racePhone
  });

  assert.ok(preservedUserId);
  assert.equal(provisioned.created_user, true);
  assert.equal(provisioned.reused_existing_user, false);
  assert.equal(provisioned.active_tenant_id, null);
  assert.equal(deleteAttempts, 0);
  const preservedUser = await authStore.findUserByPhone(racePhone);
  assert.ok(preservedUser);
  const preservedDomainAccess = await authStore.findDomainAccessByUserId(preservedUserId);
  assert.deepEqual(preservedDomainAccess, { platform: true, tenant: false });
});

test('provisionPlatformUserByPhone rolls back newly created user when relationship provisioning fails', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-platform-rollback-user-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });
  const authStore = service._internals.authStore;
  const originalEnsureDefaultDomainAccessForUser = authStore.ensureDefaultDomainAccessForUser
    .bind(authStore);
  const rollbackPhone = '13835550090';
  let rollbackUserId = null;

  authStore.ensureDefaultDomainAccessForUser = async (userId) => {
    const foundUser = await authStore.findUserById(userId);
    if (foundUser?.phone === rollbackPhone) {
      rollbackUserId = String(userId);
      return { inserted: false };
    }
    return originalEnsureDefaultDomainAccessForUser(userId);
  };

  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-provision-platform-rollback-operator-login'
  );

  await assert.rejects(
    () =>
      service.provisionPlatformUserByPhone({
        requestId: 'req-provision-platform-rollback',
        accessToken: operatorLogin.access_token,
        phone: rollbackPhone
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 409);
      assert.equal(error.errorCode, 'AUTH-409-PROVISION-CONFLICT');
      return true;
    }
  );

  assert.ok(rollbackUserId);
  const rolledBackUser = await authStore.findUserByPhone(rollbackPhone);
  assert.equal(rolledBackUser, null);
});

test('provisionTenantUserByPhone creates tenant relationship and rejects duplicate relationship requests', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-default-password-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-operator',
        phone: '13835550003',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-a',
            tenantName: 'Tenant Provision A',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-operator-login',
    phone: '13835550003',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });
  const provisioned = await service.provisionTenantUserByPhone({
    requestId: 'req-provision-tenant-first',
    accessToken: operatorLogin.access_token,
    phone: '13835550004',
    tenantName: 'Tenant Provision A'
  });
  assert.equal(provisioned.created_user, true);
  assert.equal(provisioned.entry_domain, 'tenant');
  assert.equal(provisioned.active_tenant_id, 'tenant-provision-a');

  const tenantLogin = await service.login({
    requestId: 'req-provision-tenant-login',
    phone: '13835550004',
    password: defaultPassword,
    entryDomain: 'tenant'
  });
  assert.equal(tenantLogin.entry_domain, 'tenant');
  assert.equal(tenantLogin.active_tenant_id, 'tenant-provision-a');

  await assert.rejects(
    () =>
      service.provisionTenantUserByPhone({
        requestId: 'req-provision-tenant-duplicate',
        accessToken: operatorLogin.access_token,
        phone: '13835550004',
        tenantName: 'Tenant Provision A'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 409);
      assert.equal(error.errorCode, 'AUTH-409-PROVISION-CONFLICT');
      return true;
    }
  );
});

test('provisionTenantUserByPhone returns conflict when tenant domain access remains unavailable after relationship provisioning', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-domain-disabled-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-domain-disabled-operator',
        phone: '13835550030',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-domain-disabled-a',
            tenantName: 'Tenant Provision Domain Disabled A',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'tenant-provision-domain-disabled-target',
        phone: '13835550031',
        password: 'LegacyPass!2026',
        status: 'active',
        domains: []
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });
  const authStore = service._internals.authStore;
  const originalFindDomainAccessByUserId = authStore.findDomainAccessByUserId.bind(authStore);
  const originalEnsureTenantDomainAccessForUser = authStore.ensureTenantDomainAccessForUser
    .bind(authStore);

  authStore.findDomainAccessByUserId = async (userId) => {
    if (String(userId) === 'tenant-provision-domain-disabled-target') {
      return { platform: false, tenant: false };
    }
    return originalFindDomainAccessByUserId(userId);
  };
  authStore.ensureTenantDomainAccessForUser = async (userId) => {
    if (String(userId) === 'tenant-provision-domain-disabled-target') {
      return { inserted: false };
    }
    return originalEnsureTenantDomainAccessForUser(userId);
  };

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-domain-disabled-operator-login',
    phone: '13835550030',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  await assert.rejects(
    () =>
      service.provisionTenantUserByPhone({
        requestId: 'req-provision-tenant-domain-disabled',
        accessToken: operatorLogin.access_token,
        phone: '13835550031',
        tenantName: 'Tenant Provision Domain Disabled A'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 409);
      assert.equal(error.errorCode, 'AUTH-409-PROVISION-CONFLICT');
      return true;
    }
  );
  const tenantOptions = await authStore.listTenantOptionsByUserId(
    'tenant-provision-domain-disabled-target'
  );
  assert.equal(
    tenantOptions.some((option) => option.tenantId === 'tenant-provision-domain-disabled-a'),
    false
  );
});

test('provisionTenantUserByPhone rolls back membership when tenant domain access grant throws unexpectedly', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-domain-throw-rollback-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-domain-throw-operator',
        phone: '13835550093',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-domain-throw-a',
            tenantName: 'Tenant Provision Domain Throw A',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'tenant-provision-domain-throw-target',
        phone: '13835550094',
        password: 'LegacyPass!2026',
        status: 'active',
        domains: []
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });
  const authStore = service._internals.authStore;
  const originalEnsureTenantDomainAccessForUser = authStore.ensureTenantDomainAccessForUser
    .bind(authStore);

  authStore.ensureTenantDomainAccessForUser = async (userId) => {
    if (String(userId) === 'tenant-provision-domain-throw-target') {
      throw new Error('tenant-domain-access-write-failed');
    }
    return originalEnsureTenantDomainAccessForUser(userId);
  };

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-domain-throw-operator-login',
    phone: '13835550093',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  await assert.rejects(
    () =>
      service.provisionTenantUserByPhone({
        requestId: 'req-provision-tenant-domain-throw',
        accessToken: operatorLogin.access_token,
        phone: '13835550094',
        tenantName: 'Tenant Provision Domain Throw A'
      }),
    (error) => {
      assert.equal(error instanceof AuthProblemError, false);
      assert.equal(error?.message, 'tenant-domain-access-write-failed');
      return true;
    }
  );
  const tenantOptions = await authStore.listTenantOptionsByUserId(
    'tenant-provision-domain-throw-target'
  );
  assert.equal(
    tenantOptions.some((option) => option.tenantId === 'tenant-provision-domain-throw-a'),
    false
  );
});

test('provisionTenantUserByPhone rolls back tenant membership and tenant domain access when post-grant verification reports conflict', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-domain-verify-rollback-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-domain-verify-operator',
        phone: '13835550110',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-domain-verify-a',
            tenantName: 'Tenant Provision Domain Verify A',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'tenant-provision-domain-verify-target',
        phone: '13835550111',
        password: 'LegacyPass!2026',
        status: 'active',
        domains: []
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });
  const authStore = service._internals.authStore;
  const originalFindDomainAccessByUserId = authStore.findDomainAccessByUserId
    .bind(authStore);
  let staleReadInjected = false;
  authStore.findDomainAccessByUserId = async (userId) => {
    if (String(userId) !== 'tenant-provision-domain-verify-target') {
      return originalFindDomainAccessByUserId(userId);
    }
    const actualAccess = await originalFindDomainAccessByUserId(userId);
    if (!staleReadInjected && actualAccess.tenant) {
      staleReadInjected = true;
      return { platform: false, tenant: false };
    }
    return actualAccess;
  };

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-domain-verify-operator-login',
    phone: '13835550110',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  await assert.rejects(
    () =>
      service.provisionTenantUserByPhone({
        requestId: 'req-provision-tenant-domain-verify',
        accessToken: operatorLogin.access_token,
        phone: '13835550111',
        tenantName: 'Tenant Provision Domain Verify A'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 409);
      assert.equal(error.errorCode, 'AUTH-409-PROVISION-CONFLICT');
      return true;
    }
  );

  const tenantOptions = await authStore.listTenantOptionsByUserId(
    'tenant-provision-domain-verify-target'
  );
  assert.equal(
    tenantOptions.some((option) => option.tenantId === 'tenant-provision-domain-verify-a'),
    false
  );
  const recoveredDomainAccess = await originalFindDomainAccessByUserId(
    'tenant-provision-domain-verify-target'
  );
  assert.deepEqual(recoveredDomainAccess, { platform: false, tenant: false });
});

test('provisionTenantUserByPhone reuses existing user without mutating password hash', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-reuse-default-password-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-operator-reuse',
        phone: '13835550013',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-reuse-a',
            tenantName: 'Tenant Provision Reuse A',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'tenant-provision-reuse-target',
        phone: '13835550014',
        password: 'LegacyPass!2026',
        status: 'active',
        domains: []
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-reuse-operator-login',
    phone: '13835550013',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });
  const previousUser = await service._internals.authStore.findUserByPhone('13835550014');
  const previousPasswordHash = previousUser.passwordHash;

  const provisioned = await service.provisionTenantUserByPhone({
    requestId: 'req-provision-tenant-reuse-first',
    accessToken: operatorLogin.access_token,
    phone: '13835550014',
    tenantName: 'Tenant Provision Reuse A'
  });
  assert.equal(provisioned.created_user, false);
  assert.equal(provisioned.reused_existing_user, true);
  assert.equal(provisioned.active_tenant_id, 'tenant-provision-reuse-a');

  const currentUser = await service._internals.authStore.findUserByPhone('13835550014');
  assert.equal(currentUser.passwordHash, previousPasswordHash);
});

test('provisionTenantUserByPhone rejoin updates tenant_name to canonical active tenant name', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-rejoin-name-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-operator-rejoin-name',
        phone: '13835550041',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-rejoin-name-a',
            tenantName: 'Tenant Provision Rejoin Name A',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'tenant-provision-rejoin-name-target',
        phone: '13835550042',
        password: 'LegacyPass!2026',
        status: 'active',
        domains: [],
        tenants: [
          {
            membershipId: 'membership-rejoin-name-old',
            tenantId: 'tenant-provision-rejoin-name-a',
            tenantName: 'Tenant Provision Rejoin Name OLD',
            status: 'left',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: true,
              canOperateBilling: true
            }
          }
        ]
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-rejoin-name-operator-login',
    phone: '13835550041',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  const provisioned = await service.provisionTenantUserByPhone({
    requestId: 'req-provision-tenant-rejoin-name',
    accessToken: operatorLogin.access_token,
    phone: '13835550042',
    tenantName: 'Tenant Provision Rejoin Name A'
  });
  assert.equal(provisioned.created_user, false);
  assert.equal(provisioned.reused_existing_user, true);

  const membership = await service.findTenantMembershipByUserAndTenantId({
    userId: 'tenant-provision-rejoin-name-target',
    tenantId: 'tenant-provision-rejoin-name-a'
  });
  assert.ok(membership);
  assert.notEqual(membership.membership_id, 'membership-rejoin-name-old');
  assert.equal(membership.status, 'active');
  assert.equal(membership.tenant_name, 'Tenant Provision Rejoin Name A');
});

test('findTenantMembershipByUserAndTenantId fails closed when store returns unsupported membership status', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  authStore.findTenantMembershipByUserAndTenantId = async () => ({
    membership_id: 'membership-invalid-status',
    user_id: 'tenant-user-invalid-status',
    tenant_id: 'tenant-invalid-status',
    tenant_name: 'Tenant Invalid Status',
    phone: '13835559991',
    status: 'archived',
    joined_at: '2026-02-19T00:00:00.000Z',
    left_at: null
  });

  await assert.rejects(
    () =>
      service.findTenantMembershipByUserAndTenantId({
        userId: 'tenant-user-invalid-status',
        tenantId: 'tenant-invalid-status'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('findTenantMembershipByUserAndTenantId fails closed when store returns malformed membership identity', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  authStore.findTenantMembershipByUserAndTenantId = async () => ({
    membership_id: 'membership-bad\u0000',
    user_id: 'tenant-user-malformed-find',
    tenant_id: 'tenant-malformed-find',
    tenant_name: 'Tenant Malformed Find',
    phone: '13835559990',
    status: 'active',
    joined_at: '2026-02-19T00:00:00.000Z',
    left_at: null
  });

  await assert.rejects(
    () =>
      service.findTenantMembershipByUserAndTenantId({
        userId: 'tenant-user-malformed-find',
        tenantId: 'tenant-malformed-find'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantMembers fails closed when store returns unsupported membership status', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  authStore.listTenantMembersByTenantId = async () => ([
    {
      membership_id: 'membership-invalid-status-list',
      user_id: 'tenant-user-invalid-status-list',
      tenant_id: 'tenant-invalid-status-list',
      tenant_name: 'Tenant Invalid Status List',
      phone: '13835559992',
      status: 'archived',
      joined_at: '2026-02-19T00:00:00.000Z',
      left_at: null
    }
  ]);

  await assert.rejects(
    () =>
      service.listTenantMembers({
        tenantId: 'tenant-invalid-status-list'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantMembers fails closed when store returns membership_id with control characters', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  authStore.listTenantMembersByTenantId = async () => ([
    {
      membership_id: 'membership-invalid\u0000id',
      user_id: 'tenant-user-invalid-membership-id',
      tenant_id: 'tenant-invalid-membership-id',
      tenant_name: 'Tenant Invalid Membership Id',
      phone: '13835559995',
      status: 'active',
      joined_at: '2026-02-19T00:00:00.000Z',
      left_at: null
    }
  ]);

  await assert.rejects(
    () =>
      service.listTenantMembers({
        tenantId: 'tenant-invalid-membership-id'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantMembers fails closed when store returns malformed membership record', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  authStore.listTenantMembersByTenantId = async () => ([
    {
      membership_id: '',
      user_id: 'tenant-user-malformed',
      tenant_id: 'tenant-malformed',
      tenant_name: 'Tenant Malformed',
      phone: '13835559993',
      status: 'active',
      joined_at: '2026-02-19T00:00:00.000Z',
      left_at: null
    }
  ]);

  await assert.rejects(
    () =>
      service.listTenantMembers({
        tenantId: 'tenant-malformed'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantMembers fails closed when store returns cross-tenant record', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  authStore.listTenantMembersByTenantId = async () => ([
    {
      membership_id: 'membership-cross-tenant',
      user_id: 'tenant-user-cross-tenant',
      tenant_id: 'tenant-cross-tenant-other',
      tenant_name: 'Tenant Cross Tenant Other',
      phone: '13835559994',
      status: 'active',
      joined_at: '2026-02-19T00:00:00.000Z',
      left_at: null
    }
  ]);

  await assert.rejects(
    () =>
      service.listTenantMembers({
        tenantId: 'tenant-cross-tenant'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantMembers fails closed when store returns non-array payload', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  authStore.listTenantMembersByTenantId = async () => ({
    membership_id: 'membership-invalid-shape'
  });

  await assert.rejects(
    () =>
      service.listTenantMembers({
        tenantId: 'tenant-invalid-shape'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('findTenantMembershipByMembershipIdAndTenantId returns membership projection from in-memory store', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-member-profile-read-target',
        phone: '13835559990',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: 'membership-profile-read-success',
            tenantId: 'tenant-profile-read-success',
            tenantName: 'Tenant Profile Read Success',
            status: 'active',
            displayName: '成员甲',
            departmentName: '研发一部',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  const membership = await service.findTenantMembershipByMembershipIdAndTenantId({
    membershipId: 'membership-profile-read-success',
    tenantId: 'tenant-profile-read-success'
  });

  assert.ok(membership);
  assert.equal(membership.membership_id, 'membership-profile-read-success');
  assert.equal(membership.tenant_id, 'tenant-profile-read-success');
  assert.equal(membership.phone, '13835559990');
  assert.equal(membership.display_name, '成员甲');
  assert.equal(membership.department_name, '研发一部');
});

test('findTenantMembershipByMembershipIdAndTenantId fails closed when in-memory seed profile contains surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-member-profile-read-seed-whitespace-user',
        phone: '13835559989',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: 'membership-profile-read-seed-whitespace',
            tenantId: 'tenant-profile-read-seed-whitespace',
            tenantName: 'Tenant Profile Read Seed Whitespace',
            status: 'active',
            displayName: ' 成员甲',
            departmentName: '研发一部',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  await assert.rejects(
    () =>
      service.findTenantMembershipByMembershipIdAndTenantId({
        membershipId: 'membership-profile-read-seed-whitespace',
        tenantId: 'tenant-profile-read-seed-whitespace'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('findTenantMembershipByMembershipIdAndTenantId fails closed when store returns profile fields with surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  authStore.findTenantMembershipByMembershipIdAndTenantId = async () => ({
    membership_id: 'membership-profile-read-whitespace',
    user_id: 'tenant-user-profile-read-whitespace',
    tenant_id: 'tenant-a',
    tenant_name: 'Tenant A',
    phone: '13835559991',
    status: 'active',
    display_name: ' 成员甲',
    department_name: '研发一部',
    joined_at: '2026-02-19T00:00:00.000Z',
    left_at: null
  });

  await assert.rejects(
    () =>
      service.findTenantMembershipByMembershipIdAndTenantId({
        membershipId: 'membership-profile-read-whitespace',
        tenantId: 'tenant-a'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('findTenantMembershipByMembershipIdAndTenantId fails closed when store returns membership without phone', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  authStore.findTenantMembershipByMembershipIdAndTenantId = async () => ({
    membership_id: 'membership-profile-read-missing-phone',
    user_id: 'tenant-user-profile-read-missing-phone',
    tenant_id: 'tenant-a',
    tenant_name: 'Tenant A',
    phone: '',
    status: 'active',
    display_name: '成员甲',
    department_name: '研发一部',
    joined_at: '2026-02-19T00:00:00.000Z',
    left_at: null
  });

  await assert.rejects(
    () =>
      service.findTenantMembershipByMembershipIdAndTenantId({
        membershipId: 'membership-profile-read-missing-phone',
        tenantId: 'tenant-a'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('updateTenantMemberProfile updates member profile under tenant authorized route', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  const profileUpdateCalls = [];
  authStore.updateTenantMembershipProfile = async (payload) => {
    profileUpdateCalls.push(payload);
    return {
      membership_id: payload.membershipId,
      user_id: 'tenant-user-profile-update',
      tenant_id: payload.tenantId,
      tenant_name: 'Tenant A',
      phone: '13835559992',
      status: 'active',
      display_name: payload.displayName,
      department_name: payload.departmentName,
      joined_at: '2026-02-19T00:00:00.000Z',
      left_at: null
    };
  };

  const updated = await service.updateTenantMemberProfile({
    requestId: 'req-tenant-member-profile-update-success',
    membershipId: 'MEMBERSHIP-PROFILE-UPDATE',
    tenantId: 'tenant-a',
    displayName: '成员乙',
    departmentName: '产品部',
    departmentNameProvided: true,
    authorizedRoute: {
      user_id: 'tenant-operator-profile-update',
      session_id: 'tenant-session-profile-update',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-a'
    }
  });

  assert.equal(profileUpdateCalls.length, 1);
  assert.equal(profileUpdateCalls[0].membershipId, 'membership-profile-update');
  assert.equal(profileUpdateCalls[0].tenantId, 'tenant-a');
  assert.equal(profileUpdateCalls[0].displayName, '成员乙');
  assert.equal(profileUpdateCalls[0].departmentName, '产品部');
  assert.equal(updated.membership_id, 'membership-profile-update');
  assert.equal(updated.tenant_id, 'tenant-a');
  assert.equal(updated.display_name, '成员乙');
  assert.equal(updated.department_name, '产品部');
});

test('updateTenantMemberProfile keeps department unchanged when departmentNameProvided is false', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  const profileUpdateCalls = [];
  authStore.updateTenantMembershipProfile = async (payload) => {
    profileUpdateCalls.push(payload);
    return {
      membership_id: payload.membershipId,
      user_id: 'tenant-user-profile-update',
      tenant_id: payload.tenantId,
      tenant_name: 'Tenant A',
      phone: '13835559992',
      status: 'active',
      display_name: payload.displayName,
      department_name: '研发一部',
      joined_at: '2026-02-19T00:00:00.000Z',
      left_at: null
    };
  };

  const updated = await service.updateTenantMemberProfile({
    requestId: 'req-tenant-member-profile-update-no-dept',
    membershipId: 'membership-profile-update-no-dept',
    tenantId: 'tenant-a',
    displayName: '成员丙',
    departmentNameProvided: false,
    authorizedRoute: {
      user_id: 'tenant-operator-profile-update',
      session_id: 'tenant-session-profile-update',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-a'
    }
  });

  assert.equal(profileUpdateCalls.length, 1);
  assert.equal(profileUpdateCalls[0].departmentNameProvided, false);
  assert.equal(updated.department_name, '研发一部');
  const lastAuditEvent = service._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'auth.tenant.member.profile.updated');
  assert.deepEqual(lastAuditEvent.changed_fields, ['display_name']);
});

test('updateTenantMemberProfile maps missing membership to stable 404', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  authStore.updateTenantMembershipProfile = async () => null;

  await assert.rejects(
    () =>
      service.updateTenantMemberProfile({
        requestId: 'req-tenant-member-profile-update-not-found',
        membershipId: 'membership-profile-update-not-found',
        displayName: '成员乙',
        departmentName: '产品部',
        departmentNameProvided: true,
        authorizedRoute: {
          user_id: 'tenant-operator-profile-update',
          session_id: 'tenant-session-profile-update',
          entry_domain: 'tenant',
          active_tenant_id: 'tenant-a'
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 404);
      assert.equal(error.errorCode, 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND');
      return true;
    }
  );
});

test('updateTenantMemberProfile fails closed when store returns membership without phone', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  authStore.updateTenantMembershipProfile = async () => ({
    membership_id: 'membership-profile-update-missing-phone',
    user_id: 'tenant-user-profile-update-missing-phone',
    tenant_id: 'tenant-a',
    tenant_name: 'Tenant A',
    phone: '',
    status: 'active',
    display_name: '成员乙',
    department_name: '产品部',
    joined_at: '2026-02-19T00:00:00.000Z',
    left_at: null
  });

  await assert.rejects(
    () =>
      service.updateTenantMemberProfile({
        requestId: 'req-tenant-member-profile-update-missing-phone',
        membershipId: 'membership-profile-update-missing-phone',
        displayName: '成员乙',
        departmentName: '产品部',
        departmentNameProvided: true,
        authorizedRoute: {
          user_id: 'tenant-operator-profile-update',
          session_id: 'tenant-session-profile-update',
          entry_domain: 'tenant',
          active_tenant_id: 'tenant-a'
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('updateTenantMemberProfile fails closed when store returns membership phone with surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const authStore = service._internals.authStore;
  authStore.updateTenantMembershipProfile = async () => ({
    membership_id: 'membership-profile-update-whitespace-phone',
    user_id: 'tenant-user-profile-update-whitespace-phone',
    tenant_id: 'tenant-a',
    tenant_name: 'Tenant A',
    phone: ' 13835559993',
    status: 'active',
    display_name: '成员乙',
    department_name: '产品部',
    joined_at: '2026-02-19T00:00:00.000Z',
    left_at: null
  });

  await assert.rejects(
    () =>
      service.updateTenantMemberProfile({
        requestId: 'req-tenant-member-profile-update-whitespace-phone',
        membershipId: 'membership-profile-update-whitespace-phone',
        displayName: '成员乙',
        departmentName: '产品部',
        departmentNameProvided: true,
        authorizedRoute: {
          user_id: 'tenant-operator-profile-update',
          session_id: 'tenant-session-profile-update',
          entry_domain: 'tenant',
          active_tenant_id: 'tenant-a'
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('updateTenantMemberProfile fails closed without mutation when existing department is malformed and request omits department update', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-profile-invalid-department-user',
        phone: '13835559994',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: 'membership-profile-invalid-department',
            tenantId: 'tenant-a',
            tenantName: 'Tenant A',
            status: 'active',
            displayName: '成员甲',
            departmentName: '研发一部 ',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  await assert.rejects(
    () =>
      service.updateTenantMemberProfile({
        requestId: 'req-tenant-member-profile-update-malformed-department',
        membershipId: 'membership-profile-invalid-department',
        displayName: '成员乙',
        departmentNameProvided: false,
        authorizedRoute: {
          user_id: 'tenant-profile-invalid-department-user',
          session_id: 'tenant-profile-invalid-department-session',
          entry_domain: 'tenant',
          active_tenant_id: 'tenant-a'
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );

  const persistedMembership =
    await service._internals.authStore.findTenantMembershipByMembershipIdAndTenantId({
      membershipId: 'membership-profile-invalid-department',
      tenantId: 'tenant-a'
    });
  assert.equal(persistedMembership.display_name, '成员甲');
});

test('provisionTenantUserByPhone rejects duplicate user-tenant relationship even when existing membership is inactive', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-inactive-relationship-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-operator-inactive-relationship',
        phone: '13835550017',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-inactive-a',
            tenantName: 'Tenant Provision Inactive A',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'tenant-provision-inactive-target',
        phone: '13835550018',
        password: 'LegacyPass!2026',
        status: 'active',
        domains: [],
        tenants: [
          {
            tenantId: 'tenant-provision-inactive-a',
            tenantName: 'Tenant Provision Inactive A',
            status: 'disabled',
            permission: {
              canViewMemberAdmin: false,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-inactive-relationship-operator-login',
    phone: '13835550017',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  await assert.rejects(
    () =>
      service.provisionTenantUserByPhone({
        requestId: 'req-provision-tenant-inactive-relationship',
        accessToken: operatorLogin.access_token,
        phone: '13835550018',
        tenantName: 'Tenant Provision Inactive A'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 409);
      assert.equal(error.errorCode, 'AUTH-409-PROVISION-CONFLICT');
      return true;
    }
  );
});

test('provisionTenantUserByPhone heals tenant domain access when active relationship already exists', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-domain-heal-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-operator-domain-heal',
        phone: '13835550040',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-domain-heal-a',
            tenantName: 'Tenant Provision Domain Heal A',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'tenant-provision-domain-heal-target',
        phone: '13835550041',
        password: 'LegacyPass!2026',
        status: 'active',
        domains: [],
        tenants: [
          {
            tenantId: 'tenant-provision-domain-heal-a',
            tenantName: 'Tenant Provision Domain Heal A',
            permission: {
              canViewMemberAdmin: false,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-domain-heal-operator-login',
    phone: '13835550040',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  const provisioned = await service.provisionTenantUserByPhone({
    requestId: 'req-provision-tenant-domain-heal',
    accessToken: operatorLogin.access_token,
    phone: '13835550041',
    tenantName: 'Tenant Provision Domain Heal A'
  });
  assert.equal(provisioned.created_user, false);
  assert.equal(provisioned.reused_existing_user, true);
  assert.equal(provisioned.active_tenant_id, 'tenant-provision-domain-heal-a');

  const domainAccess = await service._internals.authStore.findDomainAccessByUserId(
    'tenant-provision-domain-heal-target'
  );
  assert.deepEqual(domainAccess, { platform: false, tenant: true });
});

test('provisionTenantUserByPhone rejects oversized tenant_name with AUTH-400-INVALID-PAYLOAD', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-name-validation-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-operator-name-validation',
        phone: '13835550015',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-name-validation-a',
            tenantName: 'Tenant Provision Name Validation A',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-name-validation-operator-login',
    phone: '13835550015',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  await assert.rejects(
    () =>
      service.provisionTenantUserByPhone({
        requestId: 'req-provision-tenant-name-validation-invalid',
        accessToken: operatorLogin.access_token,
        phone: '13835550016',
        tenantName: 'X'.repeat(129)
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('provisionTenantUserByPhone rejects tenant_name whose raw payload length exceeds max length', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-raw-length-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-operator-raw-length',
        phone: '13835550029',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-raw-length-a',
            tenantName: 'Tenant Provision Raw Length A',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-raw-length-operator-login',
    phone: '13835550029',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });
  const paddedTenantName = ` ${'X'.repeat(128)} `;

  await assert.rejects(
    () =>
      service.provisionTenantUserByPhone({
        requestId: 'req-provision-tenant-raw-length-invalid',
        accessToken: operatorLogin.access_token,
        phone: '13835550030',
        tenantName: paddedTenantName
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('provisionTenantUserByPhone rejects blank tenant_name with AUTH-400-INVALID-PAYLOAD', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-name-blank-validation-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-operator-name-blank-validation',
        phone: '13835550095',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-name-blank-validation-a',
            tenantName: 'Tenant Provision Name Blank Validation A',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-name-blank-validation-operator-login',
    phone: '13835550095',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  await assert.rejects(
    () =>
      service.provisionTenantUserByPhone({
        requestId: 'req-provision-tenant-name-blank-validation-invalid',
        accessToken: operatorLogin.access_token,
        phone: '13835550096',
        tenantName: '   '
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('provisionTenantUserByPhone rejects unknown payload fields with AUTH-400-INVALID-PAYLOAD', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-unknown-field-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-operator-unknown-field',
        phone: '13835550032',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-unknown-field-a',
            tenantName: 'Tenant Provision Unknown Field A',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-unknown-field-operator-login',
    phone: '13835550032',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  await assert.rejects(
    () =>
      service.provisionTenantUserByPhone({
        requestId: 'req-provision-tenant-unknown-field-invalid',
        accessToken: operatorLogin.access_token,
        payload: {
          phone: '13835550033',
          tenant_name: 'Tenant Provision Unknown Field A',
          extra_flag: true
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('provisionTenantUserByPhone rejects tenant_name that mismatches active tenant canonical name', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-name-canonical-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-operator-name-canonical',
        phone: '13835550019',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-name-canonical-a',
            tenantName: 'Tenant Provision Name Canonical A',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-name-canonical-operator-login',
    phone: '13835550019',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  await assert.rejects(
    () =>
      service.provisionTenantUserByPhone({
        requestId: 'req-provision-tenant-name-canonical-invalid',
        accessToken: operatorLogin.access_token,
        phone: '13835550020',
        tenantName: 'Tenant Name Spoofed By Caller'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
  const unexpectedUser = await service._internals.authStore.findUserByPhone('13835550020');
  assert.equal(unexpectedUser, null);
});

test('provisionTenantUserByPhone rejects caller tenant_name when active tenant canonical name is unavailable', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-name-missing-canonical-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-operator-name-missing-canonical',
        phone: '13835550042',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-name-missing-canonical-a',
            tenantName: null,
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-name-missing-canonical-operator-login',
    phone: '13835550042',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  await assert.rejects(
    () =>
      service.provisionTenantUserByPhone({
        requestId: 'req-provision-tenant-name-missing-canonical',
        accessToken: operatorLogin.access_token,
        phone: '13835550043',
        tenantName: 'Tenant Name Spoofed By Caller'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
  const unexpectedUser = await service._internals.authStore.findUserByPhone('13835550043');
  assert.equal(unexpectedUser, null);
});

test('provisionTenantUserByPhone rejects request when active tenant canonical name is unavailable even without tenant_name payload', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'provision-tenant-name-missing-canonical-implicit-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-provision-operator-name-missing-canonical-implicit',
        phone: '13835550044',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-provision-name-missing-canonical-implicit-a',
            tenantName: null,
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });

  const operatorLogin = await service.login({
    requestId: 'req-provision-tenant-name-missing-canonical-implicit-operator-login',
    phone: '13835550044',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  await assert.rejects(
    () =>
      service.provisionTenantUserByPhone({
        requestId: 'req-provision-tenant-name-missing-canonical-implicit',
        accessToken: operatorLogin.access_token,
        phone: '13835550045'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
  const unexpectedUser = await service._internals.authStore.findUserByPhone('13835550045');
  assert.equal(unexpectedUser, null);
});

test('provisioning supports legacy v1 key derivation for encrypted default password', async () => {
  const defaultPassword = 'InitPass!2026';
  const decryptionKey = 'legacy-provisioning-key-compatibility';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValueLegacy({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-provision-legacy-key-operator-login'
  );

  const provisioned = await service.provisionPlatformUserByPhone({
    requestId: 'req-provision-legacy-key',
    accessToken: operatorLogin.access_token,
    phone: '13835550112'
  });
  assert.equal(provisioned.created_user, true);
  assert.equal(provisioned.credential_initialized, true);

  const login = await service.login({
    requestId: 'req-provision-legacy-key-login',
    phone: '13835550112',
    password: defaultPassword,
    entryDomain: 'platform'
  });
  assert.equal(login.entry_domain, 'platform');
});

test('provisioning is fail-closed when auth.default_password secure config is unavailable', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()],
    sensitiveConfigProvider: {
      getEncryptedConfig: async () => ''
    },
    sensitiveConfigDecryptionKey: ''
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-provision-config-missing-operator-login'
  );

  await assert.rejects(
    () =>
      service.provisionPlatformUserByPhone({
        requestId: 'req-provision-config-missing',
        accessToken: operatorLogin.access_token,
        phone: '13835550002'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE');
      return true;
    }
  );

  const configFailedAudit = service._internals.auditTrail
    .filter((event) => event.type === 'auth.user.provision.config_failed')
    .at(-1);
  assert.ok(configFailedAudit);
  assert.equal(configFailedAudit.detail, 'default password resolution failed');
  assert.equal(
    configFailedAudit.failure_reason,
    'encrypted-config-missing-or-key-missing'
  );
});

test('in-memory auth store createTenantMembershipForUser returns created=false when user does not exist', async () => {
  const service = createAuthService();
  const result = await service._internals.authStore.createTenantMembershipForUser({
    userId: 'missing-user-id',
    tenantId: 'tenant-a'
  });
  assert.deepEqual(result, { created: false });
});

test('in-memory auth store deleteUserById clears platform role facts and snapshot caches', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'in-memory-delete-cleanup-user',
        phone: '13835550100',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-member-admin-cleanup',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });
  const store = service._internals.authStore;

  const beforeDelete = await store.findPlatformPermissionByUserId({
    userId: 'in-memory-delete-cleanup-user'
  });
  assert.ok(beforeDelete);

  const deleteResult = await store.deleteUserById('in-memory-delete-cleanup-user');
  assert.deepEqual(deleteResult, { deleted: true });

  const afterDelete = await store.findPlatformPermissionByUserId({
    userId: 'in-memory-delete-cleanup-user'
  });
  assert.equal(afterDelete, null);

  const syncAfterDelete = await store.syncPlatformPermissionSnapshotByUserId({
    userId: 'in-memory-delete-cleanup-user',
    forceWhenNoRoleFacts: true
  });
  assert.equal(syncAfterDelete.synced, false);
  assert.equal(syncAfterDelete.reason, 'invalid-user-id');
});

test('getOrCreateUserIdentityByPhone reuses existing user without mutating password hash', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'bootstrap-reuse-user',
        phone: '13835550103',
        password: 'LegacyPass!2026',
        status: 'active'
      }
    ]
  });
  const store = service._internals.authStore;
  const beforeUser = await store.findUserByPhone('13835550103');
  assert.ok(beforeUser);
  const previousPasswordHash = beforeUser.passwordHash;

  const result = await service.getOrCreateUserIdentityByPhone({
    requestId: 'req-bootstrap-reuse-user-identity',
    phone: '13835550103',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-bootstrap-reuse-session'
  });

  assert.equal(result.user_id, 'bootstrap-reuse-user');
  assert.equal(result.created_user, false);
  assert.equal(result.reused_existing_user, true);
  assert.equal(result.credential_initialized, false);
  const afterUser = await store.findUserByPhone('13835550103');
  assert.equal(afterUser.passwordHash, previousPasswordHash);
  const reusedAudit = service._internals.auditTrail
    .filter((event) => event.type === 'auth.user.bootstrap.reused')
    .at(-1);
  assert.ok(reusedAudit);
  assert.equal(reusedAudit.request_id, 'req-bootstrap-reuse-user-identity');
});

test('getOrCreateUserIdentityByPhone creates new user with hashed default credential', async () => {
  const defaultPassword = 'BootstrapPass!2026';
  const decryptionKey = 'bootstrap-default-password-key';
  const encryptedDefaultPassword = buildEncryptedSensitiveConfigValue({
    plainText: defaultPassword,
    decryptionKey
  });
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()],
    sensitiveConfigProvider: createSensitiveConfigProvider({
      encryptedDefaultPassword
    }),
    sensitiveConfigDecryptionKey: decryptionKey
  });
  const store = service._internals.authStore;

  const result = await service.getOrCreateUserIdentityByPhone({
    requestId: 'req-bootstrap-create-user-identity',
    phone: '13835550104',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-bootstrap-create-session'
  });

  assert.equal(result.created_user, true);
  assert.equal(result.reused_existing_user, false);
  assert.equal(result.credential_initialized, true);
  const createdUser = await store.findUserByPhone('13835550104');
  assert.ok(createdUser);
  assert.ok(String(createdUser.passwordHash || '').startsWith('pbkdf2$'));
  assert.notEqual(createdUser.passwordHash, defaultPassword);
  const createdAudit = service._internals.auditTrail
    .filter((event) => event.type === 'auth.user.bootstrap.created')
    .at(-1);
  assert.ok(createdAudit);
  assert.equal(createdAudit.request_id, 'req-bootstrap-create-user-identity');
});

test('rollbackProvisionedUserIdentity removes unreferenced provisioned user', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const store = service._internals.authStore;
  const createdUser = await store.createUserByPhone({
    phone: '13835550105',
    passwordHash: 'pbkdf2$bootstrap-rollback',
    status: 'active'
  });
  assert.ok(createdUser);

  await service.rollbackProvisionedUserIdentity({
    requestId: 'req-bootstrap-rollback-user',
    userId: createdUser.id
  });

  const afterRollback = await store.findUserById(createdUser.id);
  assert.equal(afterRollback, null);
});

test('rollbackProvisionedUserIdentity fails closed when user rollback delete fails', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const store = service._internals.authStore;
  const createdUser = await store.createUserByPhone({
    phone: '13835550106',
    passwordHash: 'pbkdf2$bootstrap-rollback-delete-failure',
    status: 'active'
  });
  assert.ok(createdUser);

  const originalDeleteUserById = store.deleteUserById;
  store.deleteUserById = async () => {
    throw new Error('rollback-delete-failed');
  };
  try {
    await assert.rejects(
      () =>
        service.rollbackProvisionedUserIdentity({
          requestId: 'req-bootstrap-rollback-delete-failure',
          userId: createdUser.id
        }),
      /rollback-delete-failed/
    );
  } finally {
    store.deleteUserById = originalDeleteUserById;
  }

  const afterFailedRollback = await store.findUserById(createdUser.id);
  assert.ok(afterFailedRollback);
});

test('rollbackProvisionedUserIdentity fails closed when rollback delete result is malformed', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const store = service._internals.authStore;
  const createdUser = await store.createUserByPhone({
    phone: '13835550116',
    passwordHash: 'pbkdf2$bootstrap-rollback-delete-result-invalid',
    status: 'active'
  });
  assert.ok(createdUser);

  const originalDeleteUserById = store.deleteUserById;
  store.deleteUserById = async () => ({
    synced: false,
    reason: 'db-deadlock'
  });
  try {
    await assert.rejects(
      () =>
        service.rollbackProvisionedUserIdentity({
          requestId: 'req-bootstrap-rollback-delete-result-invalid',
          userId: createdUser.id
        }),
      /rollback-provisioned-user-delete-result-invalid/
    );
  } finally {
    store.deleteUserById = originalDeleteUserById;
  }

  const afterMalformedDeleteResult = await store.findUserById(createdUser.id);
  assert.ok(afterMalformedDeleteResult);
});

test('rollbackProvisionedUserIdentity fails closed when rollback guard checks fail', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const store = service._internals.authStore;
  const createdUser = await store.createUserByPhone({
    phone: '13835550107',
    passwordHash: 'pbkdf2$bootstrap-rollback-guard-failure',
    status: 'active'
  });
  assert.ok(createdUser);

  const originalFindDomainAccessByUserId = store.findDomainAccessByUserId;
  store.findDomainAccessByUserId = async () => {
    throw new Error('rollback-guard-check-failed');
  };
  try {
    await assert.rejects(
      () =>
        service.rollbackProvisionedUserIdentity({
          requestId: 'req-bootstrap-rollback-guard-failure',
          userId: createdUser.id
        }),
      /rollback-guard-check-failed/
    );
  } finally {
    store.findDomainAccessByUserId = originalFindDomainAccessByUserId;
  }

  const afterGuardFailure = await store.findUserById(createdUser.id);
  assert.ok(afterGuardFailure);
});

test('in-memory auth store deleteUserById rejects users referenced by organization governance records', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'in-memory-org-owner-user',
        phone: '13835550101',
        password: 'Passw0rd!',
        status: 'active'
      },
      {
        id: 'in-memory-org-operator-user',
        phone: '13835550102',
        password: 'Passw0rd!',
        status: 'active'
      }
    ]
  });
  const store = service._internals.authStore;

  await service.createOrganizationWithOwner({
    orgId: 'in-memory-org-delete-guard',
    orgName: '删除保护组织',
    ownerUserId: 'in-memory-org-owner-user',
    operatorUserId: 'in-memory-org-operator-user'
  });

  await assert.rejects(
    () => store.deleteUserById('in-memory-org-owner-user'),
    (error) => {
      assert.equal(error.code, 'ER_ROW_IS_REFERENCED_2');
      assert.equal(error.errno, 1451);
      return true;
    }
  );
  await assert.rejects(
    () => store.deleteUserById('in-memory-org-operator-user'),
    (error) => {
      assert.equal(error.code, 'ER_ROW_IS_REFERENCED_2');
      assert.equal(error.errno, 1451);
      return true;
    }
  );

  const ownerUser = await store.findUserById('in-memory-org-owner-user');
  const operatorUser = await store.findUserById('in-memory-org-operator-user');
  assert.ok(ownerUser);
  assert.ok(operatorUser);
});

test('in-memory createOrganizationWithOwner mirrors mysql data-too-long error for org_name overflow', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'in-memory-org-owner-overflow',
        phone: '13835550111',
        password: 'Passw0rd!',
        status: 'active'
      },
      {
        id: 'in-memory-org-operator-overflow',
        phone: '13835550112',
        password: 'Passw0rd!',
        status: 'active'
      }
    ]
  });

  await assert.rejects(
    () =>
      service.createOrganizationWithOwner({
        orgId: 'in-memory-org-overflow',
        orgName: 'x'.repeat(129),
        ownerUserId: 'in-memory-org-owner-overflow',
        operatorUserId: 'in-memory-org-operator-overflow'
      }),
    (error) => {
      assert.equal(error.code, 'ER_DATA_TOO_LONG');
      assert.equal(error.errno, 1406);
      return true;
    }
  );
});

test('createOrganizationWithOwner skips out-of-transaction audit fallback when store reports audit_recorded', async () => {
  const service = createAuthService({
    authStore: {
      createOrganizationWithOwner: async ({
        orgId,
        orgName,
        ownerUserId,
        operatorUserId,
        operatorSessionId,
        auditContext
      }) => {
        assert.equal(orgId, 'org-create-atomic-audit');
        assert.equal(orgName, 'Atomic Audit Org');
        assert.equal(ownerUserId, 'owner-user');
        assert.equal(operatorUserId, 'operator-user');
        assert.equal(operatorSessionId, 'operator-session');
        assert.equal(typeof auditContext, 'object');
        assert.equal(String(auditContext?.requestId || ''), 'req-org-create-atomic-audit');
        assert.equal(
          String(auditContext?.traceparent || ''),
          '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
        );
        assert.equal(String(auditContext?.actorUserId || ''), 'operator-user');
        assert.equal(String(auditContext?.actorSessionId || ''), 'operator-session');
        return {
          org_id: orgId,
          owner_user_id: ownerUserId,
          audit_recorded: true
        };
      },
      recordAuditEvent: async () => {
        throw new Error('recordAuditEvent-should-not-be-called');
      }
    },
    allowInMemoryOtpStores: true
  });

  const createdOrg = await service.createOrganizationWithOwner({
    requestId: 'req-org-create-atomic-audit',
    traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
    orgId: 'org-create-atomic-audit',
    orgName: 'Atomic Audit Org',
    ownerUserId: 'owner-user',
    operatorUserId: 'operator-user',
    operatorSessionId: 'operator-session'
  });

  assert.deepEqual(createdOrg, {
    org_id: 'org-create-atomic-audit',
    owner_user_id: 'owner-user'
  });
});

test('createOrganizationWithOwner maps ERR_AUDIT_WRITE_FAILED to AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE', async () => {
  const service = createAuthService({
    authStore: {
      createOrganizationWithOwner: async () => {
        const error = new Error('org-create-audit-write-failed');
        error.code = 'ERR_AUDIT_WRITE_FAILED';
        throw error;
      }
    },
    allowInMemoryOtpStores: true
  });

  await assert.rejects(
    () =>
      service.createOrganizationWithOwner({
        requestId: 'req-org-create-audit-write-failed',
        orgId: 'org-create-audit-write-failed',
        orgName: 'Org Create Audit Failed',
        ownerUserId: 'owner-user',
        operatorUserId: 'operator-user',
        operatorSessionId: 'operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
      assert.equal(error.extensions?.degradation_reason, 'audit-write-failed');
      return true;
    }
  );
});

test('createOrganizationWithOwner rejects malformed dependency result payload', async () => {
  const service = createAuthService({
    authStore: {
      createOrganizationWithOwner: async () => ({})
    },
    allowInMemoryOtpStores: true
  });

  await assert.rejects(
    () =>
      service.createOrganizationWithOwner({
        requestId: 'req-org-create-result-invalid',
        orgId: 'org-create-result-invalid',
        orgName: 'Org Create Result Invalid',
        ownerUserId: 'owner-user',
        operatorUserId: 'operator-user',
        operatorSessionId: 'operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
      assert.equal(error.extensions?.degradation_reason, 'org-create-result-invalid');
      return true;
    }
  );
});

test('updateOrganizationStatus treats disabled as soft-delete and keeps tenant access removed after re-enable', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'org-status-owner-user',
        phone: '13835550121',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        platformRoles: [
          {
            roleId: 'org-status-owner-platform-view',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ],
        tenants: [{
          tenantId: 'org-status-governance-1',
          tenantName: '组织状态治理-1',
          permission: tenantPermissionA
        }]
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'org-status-governance-1',
    orgName: '组织状态治理-1',
    ownerUserId: 'org-status-owner-user',
    operatorUserId: 'platform-role-facts-operator'
  });

  const ownerLogin = await service.login({
    requestId: 'req-org-status-owner-login-before-disable',
    phone: '13835550121',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });
  assert.equal(ownerLogin.active_tenant_id, 'org-status-governance-1');
  const ownerPlatformLogin = await service.login({
    requestId: 'req-org-status-owner-platform-login-before-disable',
    phone: '13835550121',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });
  const tenantAuthorizedBeforeDisable = await service.authorizeRoute({
    requestId: 'req-org-status-tenant-authorize-before-disable',
    accessToken: ownerLogin.access_token,
    permissionCode: 'tenant.member_admin.view',
    scope: 'tenant'
  });
  assert.equal(tenantAuthorizedBeforeDisable.user_id, 'org-status-owner-user');

  const disabled = await service.updateOrganizationStatus({
    requestId: 'req-org-status-disable',
    orgId: 'org-status-governance-1',
    nextStatus: 'disabled',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-role-facts-session',
    reason: 'manual-governance'
  });
  assert.deepEqual(disabled, {
    org_id: 'org-status-governance-1',
    previous_status: 'active',
    current_status: 'disabled',
    affected_membership_count: 1,
    affected_role_count: 0,
    affected_role_binding_count: 0,
    revoked_session_count: 1,
    revoked_refresh_token_count: 1
  });
  const disableAuditEvent = service._internals.auditTrail.at(-1);
  assert.equal(disableAuditEvent.type, 'auth.org.status.updated');
  assert.equal(disableAuditEvent.affected_membership_count, 1);
  assert.equal(disableAuditEvent.affected_role_count, 0);
  assert.equal(disableAuditEvent.affected_role_binding_count, 0);
  assert.equal(disableAuditEvent.revoked_session_count, 1);
  assert.equal(disableAuditEvent.revoked_refresh_token_count, 1);

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-org-status-tenant-authorize-after-disable',
        accessToken: ownerLogin.access_token,
        permissionCode: 'tenant.member_admin.view',
        scope: 'tenant'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
      return true;
    }
  );

  await assert.rejects(
    () =>
      service.tenantOptions({
        requestId: 'req-org-status-options-after-disable',
        accessToken: ownerLogin.access_token
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
      return true;
    }
  );

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-org-status-login-disabled',
        phone: '13835550121',
        password: 'Passw0rd!',
        entryDomain: 'tenant'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );

  const authorizedPlatformAfterDisable = await service.authorizeRoute({
    requestId: 'req-org-status-platform-authorize-after-disable',
    accessToken: ownerPlatformLogin.access_token,
    permissionCode: 'platform.member_admin.view',
    scope: 'platform'
  });
  assert.equal(authorizedPlatformAfterDisable.user_id, 'org-status-owner-user');

  const reenabled = await service.updateOrganizationStatus({
    requestId: 'req-org-status-enable',
    orgId: 'org-status-governance-1',
    nextStatus: 'active',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-role-facts-session',
    reason: 'manual-recovery'
  });
  assert.deepEqual(reenabled, {
    org_id: 'org-status-governance-1',
    previous_status: 'disabled',
    current_status: 'active',
    affected_membership_count: 0,
    affected_role_count: 0,
    affected_role_binding_count: 0,
    revoked_session_count: 0,
    revoked_refresh_token_count: 0
  });

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-org-status-login-enabled',
        phone: '13835550121',
        password: 'Passw0rd!',
        entryDomain: 'tenant'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );
});

test('in-memory tenant access is fail-closed when membership points to missing org', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'orphan-tenant-owner-user',
        phone: '13835550124',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [{
          tenantId: 'existing-org-for-guard',
          tenantName: 'Existing Org For Guard',
          permission: tenantPermissionA
        }]
      },
      {
        id: 'orphan-tenant-user',
        phone: '13835550123',
        password: 'Passw0rd!',
        status: 'active'
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'existing-org-for-guard',
    orgName: 'Existing Org For Guard',
    ownerUserId: 'orphan-tenant-owner-user',
    operatorUserId: 'platform-role-facts-operator'
  });

  await service._internals.authStore.createTenantMembershipForUser({
    userId: 'orphan-tenant-user',
    tenantId: 'orphan-org-1',
    tenantName: 'Orphan Org'
  });
  await service._internals.authStore.ensureTenantDomainAccessForUser('orphan-tenant-user');

  const options = await service._internals.authStore.listTenantOptionsByUserId('orphan-tenant-user');
  assert.deepEqual(options, []);

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-orphan-tenant-login',
        phone: '13835550123',
        password: 'Passw0rd!',
        entryDomain: 'tenant'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );
});

test('updateOrganizationStatus treats same-status update as no-op and keeps existing access session valid', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'org-status-noop-owner-user',
        phone: '13835550122',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [{
          tenantId: 'org-status-governance-noop',
          tenantName: '组织状态治理-noop',
          permission: tenantPermissionA
        }]
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'org-status-governance-noop',
    orgName: '组织状态治理-noop',
    ownerUserId: 'org-status-noop-owner-user',
    operatorUserId: 'platform-role-facts-operator'
  });

  const ownerLogin = await service.login({
    requestId: 'req-org-status-noop-owner-login',
    phone: '13835550122',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  const result = await service.updateOrganizationStatus({
    requestId: 'req-org-status-noop',
    orgId: 'org-status-governance-noop',
    nextStatus: 'active',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-role-facts-session'
  });
  assert.deepEqual(result, {
    org_id: 'org-status-governance-noop',
    previous_status: 'active',
    current_status: 'active',
    affected_membership_count: 0,
    affected_role_count: 0,
    affected_role_binding_count: 0,
    revoked_session_count: 0,
    revoked_refresh_token_count: 0
  });

  const options = await service.tenantOptions({
    requestId: 'req-org-status-noop-options',
    accessToken: ownerLogin.access_token
  });
  assert.equal(options.active_tenant_id, 'org-status-governance-noop');
});

test('updateOrganizationStatus returns AUTH-404-ORG-NOT-FOUND for missing org', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  await assert.rejects(
    () =>
      service.updateOrganizationStatus({
        requestId: 'req-org-status-missing',
        orgId: 'org-status-missing',
        nextStatus: 'disabled',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 404);
      assert.equal(error.errorCode, 'AUTH-404-ORG-NOT-FOUND');
      return true;
    }
  );
});

test('updateOrganizationStatus skips out-of-transaction audit fallback when store reports audit_recorded', async () => {
  const orgStatusById = new Map([['org-status-atomic-audit', 'active']]);
  const service = createAuthService({
    authStore: {
      updateOrganizationStatus: async ({
        orgId,
        nextStatus,
        auditContext
      }) => {
        assert.equal(typeof auditContext, 'object');
        assert.equal(String(auditContext?.requestId || ''), 'req-org-status-atomic-audit');
        assert.equal(String(auditContext?.actorUserId || ''), 'operator-user');
        assert.equal(String(auditContext?.actorSessionId || ''), 'operator-session');
        assert.equal(String(auditContext?.reason || ''), 'manual-governance');
        const previousStatus = orgStatusById.get(orgId) || 'active';
        orgStatusById.set(orgId, nextStatus);
        return {
          previous_status: previousStatus,
          current_status: nextStatus,
          affected_membership_count: 0,
          affected_role_count: 0,
          affected_role_binding_count: 0,
          revoked_session_count: 0,
          revoked_refresh_token_count: 0,
          audit_recorded: true
        };
      },
      recordAuditEvent: async () => {
        throw new Error('recordAuditEvent-should-not-be-called');
      }
    },
    allowInMemoryOtpStores: true
  });

  const result = await service.updateOrganizationStatus({
    requestId: 'req-org-status-atomic-audit',
    orgId: 'org-status-atomic-audit',
    nextStatus: 'disabled',
    operatorUserId: 'operator-user',
    operatorSessionId: 'operator-session',
    reason: 'manual-governance'
  });

  assert.deepEqual(result, {
    org_id: 'org-status-atomic-audit',
    previous_status: 'active',
    current_status: 'disabled',
    affected_membership_count: 0,
    affected_role_count: 0,
    affected_role_binding_count: 0,
    revoked_session_count: 0,
    revoked_refresh_token_count: 0
  });
});

test('updateOrganizationStatus maps ERR_AUDIT_WRITE_FAILED to AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE', async () => {
  const service = createAuthService({
    authStore: {
      updateOrganizationStatus: async () => {
        const error = new Error('org-status-audit-write-failed');
        error.code = 'ERR_AUDIT_WRITE_FAILED';
        throw error;
      }
    },
    allowInMemoryOtpStores: true
  });

  await assert.rejects(
    () =>
      service.updateOrganizationStatus({
        requestId: 'req-org-status-audit-write-failed',
        orgId: 'org-status-audit-write-failed',
        nextStatus: 'disabled',
        operatorUserId: 'operator-user',
        operatorSessionId: 'operator-session',
        reason: 'manual-governance'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
      assert.equal(error.extensions?.degradation_reason, 'audit-write-failed');
      return true;
    }
  );
});

test('validateOwnerTransferRequest returns normalized transfer context for active org and active candidate owner', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-current-owner',
        phone: '13835550140',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      },
      {
        id: 'owner-transfer-new-owner',
        phone: '13835550141',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'owner-transfer-org-1',
    orgName: '负责人变更测试组织-1',
    ownerUserId: 'owner-transfer-current-owner',
    operatorUserId: 'platform-role-facts-operator'
  });

  const result = await service.validateOwnerTransferRequest({
    requestId: 'req-owner-transfer-validate-success',
    orgId: 'owner-transfer-org-1',
    newOwnerPhone: '13835550141',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-role-facts-session',
    reason: '治理责任移交'
  });

  assert.deepEqual(result, {
    org_id: 'owner-transfer-org-1',
    old_owner_user_id: 'owner-transfer-current-owner',
    new_owner_user_id: 'owner-transfer-new-owner'
  });
});

test('executeOwnerTransferTakeover completes owner switch and takeover convergence with minimum tenant governance permissions', async () => {
  const orgId = 'owner-transfer-org-execute-success';
  const takeoverRoleId = toOwnerTransferTakeoverRoleIdForOrg(orgId);
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-execute-old-owner',
        phone: '13835550210',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      },
      {
        id: 'owner-transfer-execute-new-owner',
        phone: '13835550211',
        password: 'Passw0rd!',
        status: 'active'
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId,
    orgName: '负责人变更执行闭环-成功路径',
    ownerUserId: 'owner-transfer-execute-old-owner',
    operatorUserId: 'platform-role-facts-operator'
  });

  await service._internals.authStore.createTenantMembershipForUser({
    userId: 'owner-transfer-execute-old-owner',
    tenantId: orgId,
    tenantName: '负责人变更执行闭环-成功路径'
  });
  await service._internals.authStore.ensureTenantDomainAccessForUser(
    'owner-transfer-execute-old-owner'
  );
  const oldMembership = await service._internals.authStore.findTenantMembershipByUserAndTenantId({
    userId: 'owner-transfer-execute-old-owner',
    tenantId: orgId
  });
  assert.ok(oldMembership);

  await service.createPlatformRoleCatalogEntry({
    roleId: 'owner_transfer_execute_old_role',
    code: 'OWNER_TRANSFER_EXECUTE_OLD_ROLE',
    name: '负责人变更旧负责人角色',
    scope: 'tenant',
    tenantId: orgId,
    status: 'active',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-role-facts-session'
  });
  await service.replaceTenantRolePermissionGrants({
    requestId: 'req-owner-transfer-execute-old-role-grants',
    tenantId: orgId,
    roleId: 'owner_transfer_execute_old_role',
    permissionCodes: ['tenant.member_admin.operate'],
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-role-facts-session'
  });
  await service.replaceTenantMemberRoleBindings({
    requestId: 'req-owner-transfer-execute-old-role-bindings',
    tenantId: orgId,
    membershipId: oldMembership.membership_id,
    roleIds: ['owner_transfer_execute_old_role'],
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-role-facts-session'
  });

  const oldPermissionBefore = await service._internals.authStore.findTenantPermissionByUserAndTenantId({
    userId: 'owner-transfer-execute-old-owner',
    tenantId: orgId
  });
  assert.equal(oldPermissionBefore.canViewMemberAdmin, true);
  assert.equal(oldPermissionBefore.canOperateMemberAdmin, true);

  const takeoverResult = await service.executeOwnerTransferTakeover({
    requestId: 'req-owner-transfer-execute-success',
    orgId,
    newOwnerPhone: '13835550211',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-role-facts-session',
    reason: '治理责任移交'
  });

  assert.deepEqual(takeoverResult, {
    org_id: orgId,
    old_owner_user_id: 'owner-transfer-execute-old-owner',
    new_owner_user_id: 'owner-transfer-execute-new-owner'
  });

  const orgAfterTransfer = await service._internals.authStore.findOrganizationById({
    orgId
  });
  assert.equal(
    orgAfterTransfer.owner_user_id,
    'owner-transfer-execute-new-owner'
  );

  const tenantOwnerRole = await service._internals.authStore.findPlatformRoleCatalogEntryByRoleId({
    roleId: takeoverRoleId,
    scope: 'tenant',
    tenantId: orgId
  });
  assert.ok(tenantOwnerRole);
  assert.equal(tenantOwnerRole.status, 'active');
  const tenantOwnerRolePermissionCodes =
    await service._internals.authStore.listTenantRolePermissionGrants({
      roleId: takeoverRoleId
    });
  assert.ok(
    tenantOwnerRolePermissionCodes.includes('tenant.member_admin.view')
  );
  assert.ok(
    tenantOwnerRolePermissionCodes.includes('tenant.member_admin.operate')
  );

  const newMembership = await service._internals.authStore.findTenantMembershipByUserAndTenantId({
    userId: 'owner-transfer-execute-new-owner',
    tenantId: orgId
  });
  assert.ok(newMembership);
  assert.equal(newMembership.status, 'active');
  const newRoleBindings = await service._internals.authStore.listTenantMembershipRoleBindings({
    membershipId: newMembership.membership_id,
    tenantId: orgId
  });
  assert.ok(newRoleBindings.includes(takeoverRoleId));
  const newPermission = await service._internals.authStore.findTenantPermissionByUserAndTenantId({
    userId: 'owner-transfer-execute-new-owner',
    tenantId: orgId
  });
  assert.equal(newPermission.canViewMemberAdmin, true);
  assert.equal(newPermission.canOperateMemberAdmin, true);

  const oldMembershipAfter = await service._internals.authStore.findTenantMembershipByUserAndTenantId({
    userId: 'owner-transfer-execute-old-owner',
    tenantId: orgId
  });
  assert.ok(oldMembershipAfter);
  const oldPermissionAfter = await service._internals.authStore.findTenantPermissionByUserAndTenantId({
    userId: 'owner-transfer-execute-old-owner',
    tenantId: orgId
  });
  assert.equal(oldPermissionAfter.canViewMemberAdmin, true);
  assert.equal(oldPermissionAfter.canOperateMemberAdmin, true);
  const ownerTransferAuditEvents = await service.listAuditEvents({
    domain: 'tenant',
    tenantId: orgId,
    requestId: 'req-owner-transfer-execute-success',
    eventType: 'auth.org.owner_transfer.executed'
  });
  assert.equal(ownerTransferAuditEvents.total, 1);
  assert.equal(
    ownerTransferAuditEvents.events[0]?.metadata?.reason,
    '治理责任移交'
  );
});

test('executeOwnerTransferTakeover uses tenant-scoped takeover role ids so cross-org transfers do not collide', async () => {
  const orgIdA = 'owner-transfer-role-scope-org-a';
  const orgIdB = 'owner-transfer-role-scope-org-b';
  const takeoverRoleIdA = toOwnerTransferTakeoverRoleIdForOrg(orgIdA);
  const takeoverRoleIdB = toOwnerTransferTakeoverRoleIdForOrg(orgIdB);
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-role-scope-old-owner-a',
        phone: '13835550220',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      },
      {
        id: 'owner-transfer-role-scope-new-owner-a',
        phone: '13835550221',
        password: 'Passw0rd!',
        status: 'active'
      },
      {
        id: 'owner-transfer-role-scope-old-owner-b',
        phone: '13835550222',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      },
      {
        id: 'owner-transfer-role-scope-new-owner-b',
        phone: '13835550223',
        password: 'Passw0rd!',
        status: 'active'
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: orgIdA,
    orgName: '负责人变更角色隔离-A',
    ownerUserId: 'owner-transfer-role-scope-old-owner-a',
    operatorUserId: 'platform-role-facts-operator'
  });
  await service.createOrganizationWithOwner({
    orgId: orgIdB,
    orgName: '负责人变更角色隔离-B',
    ownerUserId: 'owner-transfer-role-scope-old-owner-b',
    operatorUserId: 'platform-role-facts-operator'
  });

  await service.executeOwnerTransferTakeover({
    requestId: 'req-owner-transfer-role-scope-a',
    orgId: orgIdA,
    newOwnerPhone: '13835550221',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-role-facts-session',
    reason: '治理责任移交-A'
  });
  await service.executeOwnerTransferTakeover({
    requestId: 'req-owner-transfer-role-scope-b',
    orgId: orgIdB,
    newOwnerPhone: '13835550223',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-role-facts-session',
    reason: '治理责任移交-B'
  });

  assert.notEqual(takeoverRoleIdA, takeoverRoleIdB);

  const roleA = await service._internals.authStore.findPlatformRoleCatalogEntryByRoleId({
    roleId: takeoverRoleIdA,
    scope: 'tenant',
    tenantId: orgIdA
  });
  const roleB = await service._internals.authStore.findPlatformRoleCatalogEntryByRoleId({
    roleId: takeoverRoleIdB,
    scope: 'tenant',
    tenantId: orgIdB
  });
  assert.ok(roleA);
  assert.ok(roleB);

  const membershipA = await service._internals.authStore.findTenantMembershipByUserAndTenantId({
    userId: 'owner-transfer-role-scope-new-owner-a',
    tenantId: orgIdA
  });
  const membershipB = await service._internals.authStore.findTenantMembershipByUserAndTenantId({
    userId: 'owner-transfer-role-scope-new-owner-b',
    tenantId: orgIdB
  });
  assert.ok(membershipA);
  assert.ok(membershipB);
  const roleBindingsA = await service._internals.authStore.listTenantMembershipRoleBindings({
    membershipId: membershipA.membership_id,
    tenantId: orgIdA
  });
  const roleBindingsB = await service._internals.authStore.listTenantMembershipRoleBindings({
    membershipId: membershipB.membership_id,
    tenantId: orgIdB
  });
  assert.ok(roleBindingsA.includes(takeoverRoleIdA));
  assert.ok(roleBindingsB.includes(takeoverRoleIdB));
});

test('executeOwnerTransferTakeover fails closed when takeover dependency returns malformed payload', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-malformed-old-owner',
        phone: '13835550212',
        password: 'Passw0rd!',
        status: 'active'
      },
      {
        id: 'owner-transfer-malformed-new-owner',
        phone: '13835550213',
        password: 'Passw0rd!',
        status: 'active'
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'owner-transfer-org-malformed-result',
    orgName: '负责人变更执行闭环-畸形回包',
    ownerUserId: 'owner-transfer-malformed-old-owner',
    operatorUserId: 'platform-role-facts-operator'
  });

  service._internals.authStore.executeOwnerTransferTakeover = async () => ({
    org_id: 'owner-transfer-org-malformed-result',
    old_owner_user_id: 'owner-transfer-malformed-old-owner'
  });

  await assert.rejects(
    () =>
      service.executeOwnerTransferTakeover({
        requestId: 'req-owner-transfer-malformed-result',
        orgId: 'owner-transfer-org-malformed-result',
        newOwnerPhone: '13835550213',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session',
        reason: '治理责任移交'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(
        error.errorCode,
        'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
      );
      assert.equal(
        error.extensions.degradation_reason,
        'owner-transfer-takeover-result-invalid'
      );
      return true;
    }
  );
});

test('executeOwnerTransferTakeover fails closed when takeover role definition is poisoned with mismatched code', async () => {
  const orgId = 'owner-transfer-org-role-invalid';
  const takeoverRoleId = toOwnerTransferTakeoverRoleIdForOrg(orgId);
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-role-invalid-old-owner',
        phone: '13835550216',
        password: 'Passw0rd!',
        status: 'active'
      },
      {
        id: 'owner-transfer-role-invalid-new-owner',
        phone: '13835550217',
        password: 'Passw0rd!',
        status: 'active'
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId,
    orgName: '负责人变更执行闭环-角色定义异常',
    ownerUserId: 'owner-transfer-role-invalid-old-owner',
    operatorUserId: 'platform-role-facts-operator'
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: takeoverRoleId,
    code: 'TENANT_BILLING_GUARD',
    name: '异常接管角色定义',
    scope: 'tenant',
    tenantId: orgId,
    status: 'active',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-role-facts-session'
  });

  await assert.rejects(
    () =>
      service.executeOwnerTransferTakeover({
        requestId: 'req-owner-transfer-role-invalid-definition',
        orgId,
        newOwnerPhone: '13835550217',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session',
        reason: '治理责任移交'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(
        error.errorCode,
        'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
      );
      assert.equal(
        error.extensions.degradation_reason,
        'owner-transfer-takeover-role-invalid'
      );
      return true;
    }
  );

  const orgAfterFailure = await service._internals.authStore.findOrganizationById({
    orgId
  });
  assert.equal(
    orgAfterFailure.owner_user_id,
    'owner-transfer-role-invalid-old-owner'
  );
});

test('executeOwnerTransferTakeover fails closed when takeover role code is already occupied by another role id', async () => {
  const orgId = 'owner-transfer-org-role-code-occupied';
  const takeoverRoleId = toOwnerTransferTakeoverRoleIdForOrg(orgId);
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-role-code-occupied-old-owner',
        phone: '13835550218',
        password: 'Passw0rd!',
        status: 'active'
      },
      {
        id: 'owner-transfer-role-code-occupied-new-owner',
        phone: '13835550219',
        password: 'Passw0rd!',
        status: 'active'
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId,
    orgName: '负责人变更执行闭环-接管角色编码冲突',
    ownerUserId: 'owner-transfer-role-code-occupied-old-owner',
    operatorUserId: 'platform-role-facts-operator'
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'owner_transfer_conflict_existing_role',
    code: 'TENANT_OWNER',
    name: '冲突接管角色定义',
    scope: 'tenant',
    tenantId: orgId,
    status: 'active',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-role-facts-session'
  });

  await assert.rejects(
    () =>
      service.executeOwnerTransferTakeover({
        requestId: 'req-owner-transfer-role-code-occupied',
        orgId,
        newOwnerPhone: '13835550219',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session',
        reason: '治理责任移交'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(
        error.errorCode,
        'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
      );
      assert.equal(
        error.extensions.degradation_reason,
        'owner-transfer-takeover-role-invalid'
      );
      return true;
    }
  );

  const orgAfterFailure = await service._internals.authStore.findOrganizationById({
    orgId
  });
  assert.equal(
    orgAfterFailure.owner_user_id,
    'owner-transfer-role-code-occupied-old-owner'
  );
  const takeoverRole = await service._internals.authStore.findPlatformRoleCatalogEntryByRoleId({
    roleId: takeoverRoleId,
    scope: 'tenant',
    tenantId: orgId
  });
  assert.equal(takeoverRole, null);
});

test('executeOwnerTransferTakeover rolls back in-memory owner switch when takeover transaction fails mid-way', async () => {
  const orgId = 'owner-transfer-org-memory-rollback';
  const authStore = createInMemoryAuthStore({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-memory-rollback-old-owner',
        phone: '13835550214',
        password: 'Passw0rd!',
        status: 'active'
      },
      {
        id: 'owner-transfer-memory-rollback-new-owner',
        phone: '13835550215',
        password: 'Passw0rd!',
        status: 'active'
      }
    ],
    hashPassword: (password) =>
      createHash('sha256').update(String(password || '')).digest('hex'),
    faultInjector: {
      afterOwnerTransferTakeoverOwnerSwitch: () => {
        throw new Error('injected-owner-transfer-takeover-midway-failure');
      }
    }
  });
  const service = createAuthService({
    authStore,
    otpStore: noOpOtpStore,
    rateLimitStore: passRateLimitStore
  });

  await service.createOrganizationWithOwner({
    orgId,
    orgName: '负责人变更执行闭环-回滚验证',
    ownerUserId: 'owner-transfer-memory-rollback-old-owner',
    operatorUserId: 'platform-role-facts-operator'
  });

  await assert.rejects(
    () =>
      service.executeOwnerTransferTakeover({
        requestId: 'req-owner-transfer-memory-rollback',
        orgId,
        newOwnerPhone: '13835550215',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session',
        reason: '治理责任移交'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(
        error.errorCode,
        'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
      );
      return true;
    }
  );

  const orgAfterFailure = await authStore.findOrganizationById({ orgId });
  assert.equal(
    orgAfterFailure.owner_user_id,
    'owner-transfer-memory-rollback-old-owner'
  );
  const newOwnerMembership = await authStore.findTenantMembershipByUserAndTenantId({
    userId: 'owner-transfer-memory-rollback-new-owner',
    tenantId: orgId
  });
  assert.equal(newOwnerMembership, null);
});

test('validateOwnerTransferRequest rejects orgId with leading or trailing whitespace', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-org-whitespace-current',
        phone: '13835550190',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      },
      {
        id: 'owner-transfer-org-whitespace-next',
        phone: '13835550191',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'owner-transfer-org-whitespace-org-id',
    orgName: '负责人变更测试组织-org-whitespace',
    ownerUserId: 'owner-transfer-org-whitespace-current',
    operatorUserId: 'platform-role-facts-operator'
  });

  await assert.rejects(
    () =>
      service.validateOwnerTransferRequest({
        requestId: 'req-owner-transfer-org-whitespace',
        orgId: ' owner-transfer-org-whitespace-org-id ',
        newOwnerPhone: '13835550191',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('validateOwnerTransferRequest rejects orgId containing internal whitespace', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-org-internal-whitespace-current',
        phone: '13835550194',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      },
      {
        id: 'owner-transfer-org-internal-whitespace-next',
        phone: '13835550195',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'owner-transfer-org-internal-whitespace',
    orgName: '负责人变更测试组织-org-internal-whitespace',
    ownerUserId: 'owner-transfer-org-internal-whitespace-current',
    operatorUserId: 'platform-role-facts-operator'
  });

  await assert.rejects(
    () =>
      service.validateOwnerTransferRequest({
        requestId: 'req-owner-transfer-org-internal-whitespace',
        orgId: 'owner-transfer-org internal-whitespace',
        newOwnerPhone: '13835550195',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('validateOwnerTransferRequest rejects newOwnerPhone with leading or trailing whitespace', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-phone-whitespace-current',
        phone: '13835550192',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      },
      {
        id: 'owner-transfer-phone-whitespace-next',
        phone: '13835550193',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'owner-transfer-org-phone-whitespace',
    orgName: '负责人变更测试组织-phone-whitespace',
    ownerUserId: 'owner-transfer-phone-whitespace-current',
    operatorUserId: 'platform-role-facts-operator'
  });

  await assert.rejects(
    () =>
      service.validateOwnerTransferRequest({
        requestId: 'req-owner-transfer-phone-whitespace',
        orgId: 'owner-transfer-org-phone-whitespace',
        newOwnerPhone: ' 13835550193 ',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('validateOwnerTransferRequest rejects reason with leading or trailing whitespace', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-whitespace-owner-current',
        phone: '13835550172',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      },
      {
        id: 'owner-transfer-whitespace-owner-next',
        phone: '13835550173',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'owner-transfer-org-whitespace-reason',
    orgName: '负责人变更测试组织-whitespace-reason',
    ownerUserId: 'owner-transfer-whitespace-owner-current',
    operatorUserId: 'platform-role-facts-operator'
  });

  await assert.rejects(
    () =>
      service.validateOwnerTransferRequest({
        requestId: 'req-owner-transfer-reason-whitespace',
        orgId: 'owner-transfer-org-whitespace-reason',
        newOwnerPhone: '13835550173',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session',
        reason: ' 治理责任移交 '
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('validateOwnerTransferRequest rejects non-string reason payloads', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-nonstring-owner-current',
        phone: '13835550174',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      },
      {
        id: 'owner-transfer-nonstring-owner-next',
        phone: '13835550175',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'owner-transfer-org-nonstring-reason',
    orgName: '负责人变更测试组织-nonstring-reason',
    ownerUserId: 'owner-transfer-nonstring-owner-current',
    operatorUserId: 'platform-role-facts-operator'
  });

  await assert.rejects(
    () =>
      service.validateOwnerTransferRequest({
        requestId: 'req-owner-transfer-reason-nonstring',
        orgId: 'owner-transfer-org-nonstring-reason',
        newOwnerPhone: '13835550175',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session',
        reason: 12345
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('validateOwnerTransferRequest rejects reason containing control characters', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-control-char-owner-current',
        phone: '13835550176',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      },
      {
        id: 'owner-transfer-control-char-owner-next',
        phone: '13835550177',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'owner-transfer-org-control-char-reason',
    orgName: '负责人变更测试组织-control-char-reason',
    ownerUserId: 'owner-transfer-control-char-owner-current',
    operatorUserId: 'platform-role-facts-operator'
  });

  await assert.rejects(
    () =>
      service.validateOwnerTransferRequest({
        requestId: 'req-owner-transfer-reason-control-char',
        orgId: 'owner-transfer-org-control-char-reason',
        newOwnerPhone: '13835550177',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session',
        reason: '治理责任移交\n'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('validateOwnerTransferRequest rejects reason exceeding 256 characters', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-reason-too-long-owner-current',
        phone: '13835550178',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      },
      {
        id: 'owner-transfer-reason-too-long-owner-next',
        phone: '13835550179',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'owner-transfer-org-reason-too-long',
    orgName: '负责人变更测试组织-reason-too-long',
    ownerUserId: 'owner-transfer-reason-too-long-owner-current',
    operatorUserId: 'platform-role-facts-operator'
  });

  await assert.rejects(
    () =>
      service.validateOwnerTransferRequest({
        requestId: 'req-owner-transfer-reason-too-long',
        orgId: 'owner-transfer-org-reason-too-long',
        newOwnerPhone: '13835550179',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session',
        reason: 'x'.repeat(257)
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('validateOwnerTransferRequest rejects disabled org with AUTH-409-ORG-NOT-ACTIVE', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-disabled-org-owner',
        phone: '13835550142',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      },
      {
        id: 'owner-transfer-disabled-org-candidate',
        phone: '13835550143',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'owner-transfer-org-disabled',
    orgName: '负责人变更测试组织-disabled',
    ownerUserId: 'owner-transfer-disabled-org-owner',
    operatorUserId: 'platform-role-facts-operator'
  });
  await service.updateOrganizationStatus({
    requestId: 'req-owner-transfer-disable-org',
    orgId: 'owner-transfer-org-disabled',
    nextStatus: 'disabled',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: 'platform-role-facts-session',
    reason: 'manual-disable'
  });

  await assert.rejects(
    () =>
      service.validateOwnerTransferRequest({
        requestId: 'req-owner-transfer-disabled-org',
        orgId: 'owner-transfer-org-disabled',
        newOwnerPhone: '13835550143',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 409);
      assert.equal(error.errorCode, 'AUTH-409-ORG-NOT-ACTIVE');
      assert.equal(error.extensions.org_id, 'owner-transfer-org-disabled');
      assert.equal(
        error.extensions.old_owner_user_id,
        'owner-transfer-disabled-org-owner'
      );
      return true;
    }
  );
});

test('validateOwnerTransferRequest rejects missing candidate owner with AUTH-404-USER-NOT-FOUND', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-missing-owner-current',
        phone: '13835550144',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'owner-transfer-org-missing-candidate',
    orgName: '负责人变更测试组织-missing-candidate',
    ownerUserId: 'owner-transfer-missing-owner-current',
    operatorUserId: 'platform-role-facts-operator'
  });

  await assert.rejects(
    () =>
      service.validateOwnerTransferRequest({
        requestId: 'req-owner-transfer-missing-candidate',
        orgId: 'owner-transfer-org-missing-candidate',
        newOwnerPhone: '13835550145',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 404);
      assert.equal(error.errorCode, 'AUTH-404-USER-NOT-FOUND');
      assert.equal(error.extensions.org_id, 'owner-transfer-org-missing-candidate');
      assert.equal(
        error.extensions.old_owner_user_id,
        'owner-transfer-missing-owner-current'
      );
      return true;
    }
  );
});

test('validateOwnerTransferRequest rejects disabled candidate owner with AUTH-409-OWNER-TRANSFER-TARGET-USER-INACTIVE', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-inactive-owner-current',
        phone: '13835550146',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      },
      {
        id: 'owner-transfer-inactive-owner-candidate',
        phone: '13835550147',
        password: 'Passw0rd!',
        status: 'disabled',
        domains: ['tenant']
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'owner-transfer-org-inactive-candidate',
    orgName: '负责人变更测试组织-inactive-candidate',
    ownerUserId: 'owner-transfer-inactive-owner-current',
    operatorUserId: 'platform-role-facts-operator'
  });

  await assert.rejects(
    () =>
      service.validateOwnerTransferRequest({
        requestId: 'req-owner-transfer-inactive-candidate',
        orgId: 'owner-transfer-org-inactive-candidate',
        newOwnerPhone: '13835550147',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 409);
      assert.equal(error.errorCode, 'AUTH-409-OWNER-TRANSFER-TARGET-USER-INACTIVE');
      assert.equal(error.extensions.org_id, 'owner-transfer-org-inactive-candidate');
      assert.equal(
        error.extensions.old_owner_user_id,
        'owner-transfer-inactive-owner-current'
      );
      assert.equal(
        error.extensions.new_owner_user_id,
        'owner-transfer-inactive-owner-candidate'
      );
      return true;
    }
  );
});

test('validateOwnerTransferRequest rejects same owner transfer with AUTH-409-OWNER-TRANSFER-SAME-OWNER', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'owner-transfer-same-owner',
        phone: '13835550148',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant']
      }
    ]
  });

  await service.createOrganizationWithOwner({
    orgId: 'owner-transfer-org-same-owner',
    orgName: '负责人变更测试组织-same-owner',
    ownerUserId: 'owner-transfer-same-owner',
    operatorUserId: 'platform-role-facts-operator'
  });

  await assert.rejects(
    () =>
      service.validateOwnerTransferRequest({
        requestId: 'req-owner-transfer-same-owner',
        orgId: 'owner-transfer-org-same-owner',
        newOwnerPhone: '13835550148',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: 'platform-role-facts-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 409);
      assert.equal(error.errorCode, 'AUTH-409-OWNER-TRANSFER-SAME-OWNER');
      assert.equal(error.extensions.org_id, 'owner-transfer-org-same-owner');
      assert.equal(error.extensions.old_owner_user_id, 'owner-transfer-same-owner');
      assert.equal(error.extensions.new_owner_user_id, 'owner-transfer-same-owner');
      return true;
    }
  );
});

test('acquireOwnerTransferLock delegates to authStore lock methods', async () => {
  const calls = [];
  const service = createAuthService({
    allowInMemoryOtpStores: true,
    authStore: {
      acquireOwnerTransferLock: async (payload) => {
        calls.push(['acquire', payload]);
        return true;
      },
      releaseOwnerTransferLock: async (payload) => {
        calls.push(['release', payload]);
        return true;
      }
    }
  });

  const acquired = await service.acquireOwnerTransferLock({
    orgId: 'owner-transfer-lock-org',
    requestId: 'req-owner-transfer-lock',
    operatorUserId: 'platform-role-facts-operator',
    timeoutSeconds: 0
  });
  const released = await service.releaseOwnerTransferLock({
    orgId: 'owner-transfer-lock-org'
  });

  assert.equal(acquired, true);
  assert.equal(released, true);
  assert.deepEqual(calls, [
    [
      'acquire',
      {
        orgId: 'owner-transfer-lock-org',
        requestId: 'req-owner-transfer-lock',
        operatorUserId: 'platform-role-facts-operator',
        timeoutSeconds: 0
      }
    ],
    [
      'release',
      {
        orgId: 'owner-transfer-lock-org'
      }
    ]
  ]);
});

test('acquireOwnerTransferLock blocks same-org reentry within one auth service instance', async () => {
  let acquireCount = 0;
  const service = createAuthService({
    allowInMemoryOtpStores: true,
    authStore: {
      acquireOwnerTransferLock: async () => {
        acquireCount += 1;
        return true;
      },
      releaseOwnerTransferLock: async () => true
    }
  });

  const firstAcquire = await service.acquireOwnerTransferLock({
    orgId: 'owner-transfer-lock-reentry-org',
    requestId: 'req-owner-transfer-lock-reentry-1',
    operatorUserId: 'platform-role-facts-operator'
  });
  const secondAcquire = await service.acquireOwnerTransferLock({
    orgId: 'owner-transfer-lock-reentry-org',
    requestId: 'req-owner-transfer-lock-reentry-2',
    operatorUserId: 'platform-role-facts-operator'
  });
  const released = await service.releaseOwnerTransferLock({
    orgId: 'owner-transfer-lock-reentry-org'
  });

  assert.equal(firstAcquire, true);
  assert.equal(secondAcquire, false);
  assert.equal(acquireCount, 1);
  assert.equal(released, true);
});

test('in-memory owner-transfer locks are isolated per auth service instance', async () => {
  const serviceA = createAuthService();
  const serviceB = createAuthService();

  const acquiredByA = await serviceA.acquireOwnerTransferLock({
    orgId: 'owner-transfer-lock-isolation-org',
    requestId: 'req-owner-transfer-lock-isolation-a',
    operatorUserId: 'platform-role-facts-operator'
  });
  const acquiredByB = await serviceB.acquireOwnerTransferLock({
    orgId: 'owner-transfer-lock-isolation-org',
    requestId: 'req-owner-transfer-lock-isolation-b',
    operatorUserId: 'platform-role-facts-operator'
  });

  assert.equal(acquiredByA, true);
  assert.equal(acquiredByB, true);

  await serviceA.releaseOwnerTransferLock({
    orgId: 'owner-transfer-lock-isolation-org'
  });
  await serviceB.releaseOwnerTransferLock({
    orgId: 'owner-transfer-lock-isolation-org'
  });
});

test('acquireOwnerTransferLock returns false for orgId containing internal whitespace', async () => {
  let acquireCalled = false;
  const service = createAuthService({
    allowInMemoryOtpStores: true,
    authStore: {
      acquireOwnerTransferLock: async () => {
        acquireCalled = true;
        return true;
      },
      releaseOwnerTransferLock: async () => true
    }
  });

  const acquired = await service.acquireOwnerTransferLock({
    orgId: 'owner transfer lock org',
    requestId: 'req-owner-transfer-lock-invalid-org-id',
    operatorUserId: 'platform-role-facts-operator'
  });

  assert.equal(acquired, false);
  assert.equal(acquireCalled, false);
});

test('acquireOwnerTransferLock maps store errors to AUTH-503-OWNER-TRANSFER-LOCK-UNAVAILABLE', async () => {
  const service = createAuthService({
    allowInMemoryOtpStores: true,
    authStore: {
      acquireOwnerTransferLock: async () => {
        throw new Error('lock backend unavailable');
      },
      releaseOwnerTransferLock: async () => true
    }
  });

  await assert.rejects(
    () =>
      service.acquireOwnerTransferLock({
        orgId: 'owner-transfer-lock-failure',
        requestId: 'req-owner-transfer-lock-failure',
        operatorUserId: 'platform-role-facts-operator'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-OWNER-TRANSFER-LOCK-UNAVAILABLE');
      assert.equal(error.extensions.retryable, true);
      return true;
    }
  );
});

test('acquireOwnerTransferLock fails closed when authStore lock methods are not paired', async () => {
  let acquireCalled = false;
  const service = createAuthService({
    allowInMemoryOtpStores: true,
    authStore: {
      acquireOwnerTransferLock: async () => {
        acquireCalled = true;
        return true;
      }
    }
  });

  await assert.rejects(
    () =>
      service.acquireOwnerTransferLock({
        orgId: 'owner-transfer-lock-unpaired-store-methods',
        requestId: 'req-owner-transfer-lock-unpaired-store-methods',
        operatorUserId: 'platform-role-facts-operator'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-OWNER-TRANSFER-LOCK-UNAVAILABLE');
      assert.equal(error.extensions.retryable, true);
      return true;
    }
  );

  assert.equal(acquireCalled, false);
  assert.equal(
    await service.releaseOwnerTransferLock({
      orgId: 'owner-transfer-lock-unpaired-store-methods'
    }),
    false
  );
});

test('updatePlatformUserStatus disables platform-domain access immediately and restores it after re-enable', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-status-target-user',
        phone: '13835550131',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-status-target-view',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-platform-status-operator-login'
  );
  const targetLogin = await service.login({
    requestId: 'req-platform-status-target-login-before-disable',
    phone: '13835550131',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  const authorizedBeforeDisable = await service.authorizeRoute({
    requestId: 'req-platform-status-authorize-before-disable',
    accessToken: targetLogin.access_token,
    permissionCode: 'platform.member_admin.view',
    scope: 'platform'
  });
  assert.equal(authorizedBeforeDisable.user_id, 'platform-status-target-user');

  const disabled = await service.updatePlatformUserStatus({
    requestId: 'req-platform-status-disable',
    userId: 'platform-status-target-user',
    nextStatus: 'disabled',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: operatorLogin.session_id,
    reason: 'manual-disable'
  });
  assert.deepEqual(disabled, {
    user_id: 'platform-status-target-user',
    previous_status: 'active',
    current_status: 'disabled'
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-platform-status-authorize-after-disable',
        accessToken: targetLogin.access_token,
        permissionCode: 'platform.member_admin.view',
        scope: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
      return true;
    }
  );

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-platform-status-login-disabled',
        phone: '13835550131',
        password: 'Passw0rd!',
        entryDomain: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );

  const reenabled = await service.updatePlatformUserStatus({
    requestId: 'req-platform-status-enable',
    userId: 'platform-status-target-user',
    nextStatus: 'active',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: operatorLogin.session_id,
    reason: 'manual-enable'
  });
  assert.deepEqual(reenabled, {
    user_id: 'platform-status-target-user',
    previous_status: 'disabled',
    current_status: 'active'
  });

  const loginAfterEnable = await service.login({
    requestId: 'req-platform-status-login-enabled',
    phone: '13835550131',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });
  const authorizedAfterEnable = await service.authorizeRoute({
    requestId: 'req-platform-status-authorize-after-enable',
    accessToken: loginAfterEnable.access_token,
    permissionCode: 'platform.member_admin.view',
    scope: 'platform'
  });
  assert.equal(authorizedAfterEnable.user_id, 'platform-status-target-user');
});

test('updatePlatformUserStatus disabled only affects platform domain and keeps tenant domain access', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-status-scope-user',
        phone: '13835550135',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform', 'tenant'],
        platformRoles: [
          {
            roleId: 'platform-status-scope-view',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ],
        tenants: [
          {
            tenantId: 'platform-status-scope-tenant',
            tenantName: '平台状态域边界租户',
            status: 'active',
            permission: tenantPermissionA
          }
        ]
      }
    ]
  });

  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-platform-status-scope-operator-login'
  );
  const platformLogin = await service.login({
    requestId: 'req-platform-status-scope-platform-login',
    phone: '13835550135',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });
  const tenantLogin = await service.login({
    requestId: 'req-platform-status-scope-tenant-login',
    phone: '13835550135',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });

  const disabled = await service.updatePlatformUserStatus({
    requestId: 'req-platform-status-scope-disable',
    userId: 'platform-status-scope-user',
    nextStatus: 'disabled',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: operatorLogin.session_id
  });
  assert.deepEqual(disabled, {
    user_id: 'platform-status-scope-user',
    previous_status: 'active',
    current_status: 'disabled'
  });

  await assert.rejects(
    () =>
      service.authorizeRoute({
        requestId: 'req-platform-status-scope-platform-authorize-after-disable',
        accessToken: platformLogin.access_token,
        permissionCode: 'platform.member_admin.view',
        scope: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
      return true;
    }
  );

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-platform-status-scope-platform-login-disabled',
        phone: '13835550135',
        password: 'Passw0rd!',
        entryDomain: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 403);
      assert.equal(error.errorCode, 'AUTH-403-NO-DOMAIN');
      return true;
    }
  );

  const tenantAuthorized = await service.authorizeRoute({
    requestId: 'req-platform-status-scope-tenant-authorize-after-disable',
    accessToken: tenantLogin.access_token,
    permissionCode: 'tenant.member_admin.view',
    scope: 'tenant'
  });
  assert.equal(tenantAuthorized.user_id, 'platform-status-scope-user');
  assert.equal(tenantAuthorized.entry_domain, 'tenant');
  assert.equal(tenantAuthorized.active_tenant_id, 'platform-status-scope-tenant');

  const tenantLoginAfterDisable = await service.login({
    requestId: 'req-platform-status-scope-tenant-login-after-disable',
    phone: '13835550135',
    password: 'Passw0rd!',
    entryDomain: 'tenant'
  });
  assert.equal(tenantLoginAfterDisable.entry_domain, 'tenant');
});

test('updatePlatformUserStatus treats same-status update as no-op and keeps current session valid', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-status-noop-user',
        phone: '13835550132',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform'],
        platformRoles: [
          {
            roleId: 'platform-status-noop-view',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-platform-status-noop-operator-login'
  );
  const targetLogin = await service.login({
    requestId: 'req-platform-status-noop-target-login',
    phone: '13835550132',
    password: 'Passw0rd!',
    entryDomain: 'platform'
  });

  const result = await service.updatePlatformUserStatus({
    requestId: 'req-platform-status-noop',
    userId: 'platform-status-noop-user',
    nextStatus: 'active',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: operatorLogin.session_id
  });
  assert.deepEqual(result, {
    user_id: 'platform-status-noop-user',
    previous_status: 'active',
    current_status: 'active'
  });

  const logoutResult = await service.logout({
    requestId: 'req-platform-status-noop-logout',
    accessToken: targetLogin.access_token
  });
  assert.equal(logoutResult.ok, true);
  assert.equal(logoutResult.request_id, 'req-platform-status-noop-logout');
});

test('updatePlatformUserStatus persists audit event with request_id and traceparent', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-status-audit-user',
        phone: '13835550143',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform']
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-platform-status-audit-operator-login'
  );
  const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

  const result = await service.updatePlatformUserStatus({
    requestId: 'req-platform-status-audit',
    traceparent,
    userId: 'platform-status-audit-user',
    nextStatus: 'disabled',
    operatorUserId: 'platform-role-facts-operator',
    operatorSessionId: operatorLogin.session_id,
    reason: 'audit-check'
  });
  assert.equal(result.current_status, 'disabled');

  const auditEvents = await service.listAuditEvents({
    domain: 'platform',
    requestId: 'req-platform-status-audit',
    eventType: 'auth.platform.user.status.updated'
  });
  assert.equal(auditEvents.total, 1);
  assert.equal(auditEvents.events[0].event_type, 'auth.platform.user.status.updated');
  assert.equal(auditEvents.events[0].request_id, 'req-platform-status-audit');
  assert.equal(auditEvents.events[0].traceparent, traceparent);
  assert.equal(auditEvents.events[0].target_type, 'user');
  assert.equal(auditEvents.events[0].target_id, 'platform-status-audit-user');
});

test('updatePlatformUserStatus skips out-of-transaction audit fallback when store reports audit_recorded', async () => {
  const userStatusById = new Map([['platform-user-atomic-audit', 'active']]);
  const service = createAuthService({
    authStore: {
      updatePlatformUserStatus: async ({
        userId,
        nextStatus,
        auditContext
      }) => {
        assert.equal(typeof auditContext, 'object');
        assert.equal(String(auditContext.requestId || ''), 'req-platform-user-atomic-audit');
        const previousStatus = userStatusById.get(userId) || 'disabled';
        userStatusById.set(userId, nextStatus);
        return {
          previous_status: previousStatus,
          current_status: nextStatus,
          audit_recorded: true
        };
      },
      recordAuditEvent: async () => {
        throw new Error('recordAuditEvent-should-not-be-called');
      }
    },
    allowInMemoryOtpStores: true
  });

  const result = await service.updatePlatformUserStatus({
    requestId: 'req-platform-user-atomic-audit',
    userId: 'platform-user-atomic-audit',
    nextStatus: 'disabled',
    operatorUserId: 'operator-user',
    operatorSessionId: 'operator-session'
  });

  assert.deepEqual(result, {
    user_id: 'platform-user-atomic-audit',
    previous_status: 'active',
    current_status: 'disabled'
  });
  assert.equal(userStatusById.get('platform-user-atomic-audit'), 'disabled');
});

test('listAuditEvents maps dependency failures to AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE', async () => {
  const service = createAuthService({
    authStore: {
      listAuditEvents: async () => {
        throw new Error('invalid connection state');
      }
    },
    allowInMemoryOtpStores: true
  });

  await assert.rejects(
    () =>
      service.listAuditEvents({
        domain: 'platform'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
      assert.equal(error.extensions?.degradation_reason, 'invalid connection state');
      return true;
    }
  );
});

test('createPlatformRoleCatalogEntry skips out-of-transaction audit fallback when store reports audit_recorded', async () => {
  const service = createAuthService({
    authStore: {
      createPlatformRoleCatalogEntry: async ({
        roleId,
        code,
        name,
        status,
        scope,
        tenantId,
        isSystem,
        auditContext
      }) => {
        assert.equal(roleId, 'platform_role_atomic_audit_recorded_target');
        assert.equal(code, 'PLATFORM_ROLE_ATOMIC_AUDIT_RECORDED_TARGET');
        assert.equal(name, 'Platform Role Atomic Audit Recorded Target');
        assert.equal(status, 'active');
        assert.equal(scope, 'platform');
        assert.equal(tenantId, null);
        assert.equal(isSystem, false);
        assert.equal(typeof auditContext, 'object');
        assert.equal(String(auditContext?.requestId || ''), 'req-platform-role-create-atomic');
        assert.equal(String(auditContext?.actorUserId || ''), 'operator-user');
        assert.equal(String(auditContext?.actorSessionId || ''), 'operator-session');
        return {
          role_id: roleId,
          code,
          name,
          status,
          scope,
          tenant_id: tenantId,
          is_system: false,
          audit_recorded: true
        };
      },
      recordAuditEvent: async () => {
        throw new Error('recordAuditEvent-should-not-be-called');
      }
    },
    allowInMemoryOtpStores: true
  });

  const createdRole = await service.createPlatformRoleCatalogEntry({
    requestId: 'req-platform-role-create-atomic',
    traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
    roleId: 'PLATFORM_ROLE_ATOMIC_AUDIT_RECORDED_TARGET',
    code: 'PLATFORM_ROLE_ATOMIC_AUDIT_RECORDED_TARGET',
    name: 'Platform Role Atomic Audit Recorded Target',
    scope: 'platform',
    operatorUserId: 'operator-user',
    operatorSessionId: 'operator-session'
  });

  assert.deepEqual(createdRole, {
    role_id: 'platform_role_atomic_audit_recorded_target',
    code: 'PLATFORM_ROLE_ATOMIC_AUDIT_RECORDED_TARGET',
    name: 'Platform Role Atomic Audit Recorded Target',
    status: 'active',
    scope: 'platform',
    tenant_id: null,
    is_system: false
  });
});

test('createPlatformRoleCatalogEntry maps ERR_AUDIT_WRITE_FAILED to AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE', async () => {
  const service = createAuthService({
    authStore: {
      createPlatformRoleCatalogEntry: async () => {
        const error = new Error('platform-role-create-audit-write-failed');
        error.code = 'ERR_AUDIT_WRITE_FAILED';
        throw error;
      }
    },
    allowInMemoryOtpStores: true
  });

  await assert.rejects(
    () =>
      service.createPlatformRoleCatalogEntry({
        requestId: 'req-platform-role-create-audit-write-failed',
        roleId: 'platform_role_create_audit_failed',
        code: 'PLATFORM_ROLE_CREATE_AUDIT_FAILED',
        name: 'Platform Role Create Audit Failed',
        scope: 'platform',
        operatorUserId: 'operator-user',
        operatorSessionId: 'operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
      assert.equal(error.extensions?.degradation_reason, 'audit-write-failed');
      return true;
    }
  );
});

test('createPlatformRoleCatalogEntry rejects malformed dependency result payload', async () => {
  const service = createAuthService({
    authStore: {
      createPlatformRoleCatalogEntry: async () => ({})
    },
    allowInMemoryOtpStores: true
  });

  await assert.rejects(
    () =>
      service.createPlatformRoleCatalogEntry({
        requestId: 'req-platform-role-create-result-invalid',
        roleId: 'platform_role_create_result_invalid',
        code: 'PLATFORM_ROLE_CREATE_RESULT_INVALID',
        name: 'Platform Role Create Result Invalid',
        scope: 'platform',
        operatorUserId: 'operator-user',
        operatorSessionId: 'operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
      assert.equal(
        error.extensions?.degradation_reason,
        'platform-role-create-result-invalid'
      );
      return true;
    }
  );
});

test('updatePlatformRoleCatalogEntry skips out-of-transaction audit fallback when store reports audit_recorded', async () => {
  const service = createAuthService({
    authStore: {
      findPlatformRoleCatalogEntryByRoleId: async () => ({
        role_id: 'platform_role_update_atomic_audit_recorded_target',
        code: 'PLATFORM_ROLE_UPDATE_OLD_CODE',
        name: 'Platform Role Update Old Name',
        status: 'active'
      }),
      updatePlatformRoleCatalogEntry: async ({
        roleId,
        code,
        name,
        status,
        auditContext
      }) => {
        assert.equal(roleId, 'platform_role_update_atomic_audit_recorded_target');
        assert.equal(code, 'PLATFORM_ROLE_UPDATE_NEW_CODE');
        assert.equal(name, 'Platform Role Update New Name');
        assert.equal(status, 'disabled');
        assert.equal(typeof auditContext, 'object');
        assert.equal(String(auditContext?.requestId || ''), 'req-platform-role-update-atomic');
        assert.equal(String(auditContext?.actorUserId || ''), 'operator-user');
        assert.equal(String(auditContext?.actorSessionId || ''), 'operator-session');
        return {
          role_id: roleId,
          code,
          name,
          status,
          scope: 'platform',
          tenant_id: '',
          is_system: false,
          audit_recorded: true
        };
      },
      recordAuditEvent: async () => {
        throw new Error('recordAuditEvent-should-not-be-called');
      }
    },
    allowInMemoryOtpStores: true
  });

  const updatedRole = await service.updatePlatformRoleCatalogEntry({
    requestId: 'req-platform-role-update-atomic',
    traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
    roleId: 'platform_role_update_atomic_audit_recorded_target',
    scope: 'platform',
    code: 'PLATFORM_ROLE_UPDATE_NEW_CODE',
    name: 'Platform Role Update New Name',
    status: 'disabled',
    operatorUserId: 'operator-user',
    operatorSessionId: 'operator-session'
  });

  assert.deepEqual(updatedRole, {
    role_id: 'platform_role_update_atomic_audit_recorded_target',
    code: 'PLATFORM_ROLE_UPDATE_NEW_CODE',
    name: 'Platform Role Update New Name',
    status: 'disabled',
    scope: 'platform',
    tenant_id: '',
    is_system: false
  });
});

test('updatePlatformRoleCatalogEntry maps ERR_AUDIT_WRITE_FAILED to AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE', async () => {
  const service = createAuthService({
    authStore: {
      updatePlatformRoleCatalogEntry: async () => {
        const error = new Error('platform-role-update-audit-write-failed');
        error.code = 'ERR_AUDIT_WRITE_FAILED';
        throw error;
      }
    },
    allowInMemoryOtpStores: true
  });

  await assert.rejects(
    () =>
      service.updatePlatformRoleCatalogEntry({
        requestId: 'req-platform-role-update-audit-write-failed',
        roleId: 'platform_role_update_audit_failed',
        scope: 'platform',
        code: 'PLATFORM_ROLE_UPDATE_AUDIT_FAILED',
        operatorUserId: 'operator-user',
        operatorSessionId: 'operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
      assert.equal(error.extensions?.degradation_reason, 'audit-write-failed');
      return true;
    }
  );
});

test('updatePlatformRoleCatalogEntry rejects malformed dependency result payload', async () => {
  const service = createAuthService({
    authStore: {
      updatePlatformRoleCatalogEntry: async () => ({})
    },
    allowInMemoryOtpStores: true
  });

  await assert.rejects(
    () =>
      service.updatePlatformRoleCatalogEntry({
        requestId: 'req-platform-role-update-result-invalid',
        roleId: 'platform_role_update_result_invalid',
        scope: 'platform',
        code: 'PLATFORM_ROLE_UPDATE_RESULT_INVALID',
        operatorUserId: 'operator-user',
        operatorSessionId: 'operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
      assert.equal(
        error.extensions?.degradation_reason,
        'platform-role-update-result-invalid'
      );
      return true;
    }
  );
});

test('deletePlatformRoleCatalogEntry skips out-of-transaction audit fallback when store reports audit_recorded', async () => {
  const service = createAuthService({
    authStore: {
      deletePlatformRoleCatalogEntry: async ({
        roleId,
        auditContext
      }) => {
        assert.equal(roleId, 'platform_role_delete_atomic_audit_recorded_target');
        assert.equal(typeof auditContext, 'object');
        assert.equal(String(auditContext?.requestId || ''), 'req-platform-role-delete-atomic');
        assert.equal(String(auditContext?.actorUserId || ''), 'operator-user');
        assert.equal(String(auditContext?.actorSessionId || ''), 'operator-session');
        return {
          role_id: roleId,
          code: 'PLATFORM_ROLE_DELETE_ATOMIC_AUDIT_RECORDED_TARGET',
          name: 'Platform Role Delete Atomic Audit Recorded Target',
          status: 'disabled',
          scope: 'platform',
          tenant_id: '',
          is_system: false,
          audit_recorded: true
        };
      },
      recordAuditEvent: async () => {
        throw new Error('recordAuditEvent-should-not-be-called');
      }
    },
    allowInMemoryOtpStores: true
  });

  const deletedRole = await service.deletePlatformRoleCatalogEntry({
    requestId: 'req-platform-role-delete-atomic',
    traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
    roleId: 'platform_role_delete_atomic_audit_recorded_target',
    scope: 'platform',
    operatorUserId: 'operator-user',
    operatorSessionId: 'operator-session'
  });

  assert.deepEqual(deletedRole, {
    role_id: 'platform_role_delete_atomic_audit_recorded_target',
    code: 'PLATFORM_ROLE_DELETE_ATOMIC_AUDIT_RECORDED_TARGET',
    name: 'Platform Role Delete Atomic Audit Recorded Target',
    status: 'disabled',
    scope: 'platform',
    tenant_id: '',
    is_system: false
  });
});

test('deletePlatformRoleCatalogEntry maps ERR_AUDIT_WRITE_FAILED to AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE', async () => {
  const service = createAuthService({
    authStore: {
      deletePlatformRoleCatalogEntry: async () => {
        const error = new Error('platform-role-delete-audit-write-failed');
        error.code = 'ERR_AUDIT_WRITE_FAILED';
        throw error;
      }
    },
    allowInMemoryOtpStores: true
  });

  await assert.rejects(
    () =>
      service.deletePlatformRoleCatalogEntry({
        requestId: 'req-platform-role-delete-audit-write-failed',
        roleId: 'platform_role_delete_audit_failed',
        scope: 'platform',
        operatorUserId: 'operator-user',
        operatorSessionId: 'operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
      assert.equal(error.extensions?.degradation_reason, 'audit-write-failed');
      return true;
    }
  );
});

test('deletePlatformRoleCatalogEntry rejects malformed dependency result payload', async () => {
  const service = createAuthService({
    authStore: {
      deletePlatformRoleCatalogEntry: async () => ({})
    },
    allowInMemoryOtpStores: true
  });

  await assert.rejects(
    () =>
      service.deletePlatformRoleCatalogEntry({
        requestId: 'req-platform-role-delete-result-invalid',
        roleId: 'platform_role_delete_result_invalid',
        scope: 'platform',
        operatorUserId: 'operator-user',
        operatorSessionId: 'operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE');
      assert.equal(
        error.extensions?.degradation_reason,
        'platform-role-delete-result-invalid'
      );
      return true;
    }
  );
});

test('updatePlatformUserStatus returns AUTH-404-USER-NOT-FOUND for missing user', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-platform-status-missing-operator-login'
  );

  await assert.rejects(
    () =>
      service.updatePlatformUserStatus({
        requestId: 'req-platform-status-missing',
        userId: 'platform-status-missing-user',
        nextStatus: 'disabled',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: operatorLogin.session_id
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 404);
      assert.equal(error.errorCode, 'AUTH-404-USER-NOT-FOUND');
      return true;
    }
  );
});

test('updatePlatformUserStatus returns AUTH-404-USER-NOT-FOUND for user without platform domain access', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-status-tenant-only-user',
        phone: '13835550133',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'platform-status-tenant-only-org',
            tenantName: '平台状态-租户域用户',
            status: 'active',
            permission: tenantPermissionA
          }
        ]
      }
    ]
  });
  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-platform-status-tenant-only-operator-login'
  );

  await assert.rejects(
    () =>
      service.updatePlatformUserStatus({
        requestId: 'req-platform-status-tenant-only',
        userId: 'platform-status-tenant-only-user',
        nextStatus: 'disabled',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: operatorLogin.session_id
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 404);
      assert.equal(error.errorCode, 'AUTH-404-USER-NOT-FOUND');
      return true;
    }
  );
});

test('updatePlatformUserStatus returns AUTH-503-PLATFORM-SNAPSHOT-DEGRADED when store returns invalid status', async () => {
  const service = createAuthService({
    seedUsers: [
      buildPlatformRoleFactsOperatorSeed(),
      {
        id: 'platform-status-invalid-store-user',
        phone: '13835550134',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['platform']
      }
    ]
  });
  const authStore = service._internals.authStore;
  authStore.updatePlatformUserStatus = async () => ({
    user_id: 'platform-status-invalid-store-user',
    previous_status: 'active',
    current_status: 'archived'
  });

  const operatorLogin = await loginPlatformRoleFactsOperator(
    service,
    'req-platform-status-invalid-store-operator-login'
  );

  await assert.rejects(
    () =>
      service.updatePlatformUserStatus({
        requestId: 'req-platform-status-invalid-store',
        userId: 'platform-status-invalid-store-user',
        nextStatus: 'disabled',
        operatorUserId: 'platform-role-facts-operator',
        operatorSessionId: operatorLogin.session_id
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED');
      return true;
    }
  );
});

test('recordIdempotencyEvent records degraded outcomes with dedicated audit metadata', async () => {
  const service = createService();
  const authorizationContext = {
    user_id: 'idempotency-operator-user',
    session_id: 'idempotency-operator-session'
  };

  await service.recordIdempotencyEvent({
    requestId: 'req-idempotency-store-unavailable-audit',
    outcome: 'store_unavailable',
    routeKey: 'POST /auth/platform/member-admin/provision-user',
    idempotencyKey: 'idem-store-unavailable-audit',
    authorizationContext
  });
  await service.recordIdempotencyEvent({
    requestId: 'req-idempotency-pending-timeout-audit',
    outcome: 'pending_timeout',
    routeKey: 'POST /auth/platform/member-admin/provision-user',
    idempotencyKey: 'idem-pending-timeout-audit',
    authorizationContext
  });

  const degradedEvents = service._internals.auditTrail.filter(
    (event) => event.type === 'auth.idempotency.degraded'
  );
  assert.equal(degradedEvents.length, 2);
  assert.equal(degradedEvents[0].idempotency_outcome, 'store_unavailable');
  assert.equal(degradedEvents[1].idempotency_outcome, 'pending_timeout');
  assert.equal(degradedEvents[0].user_id, 'idempotency-operator-user');
  assert.equal(degradedEvents[0].session_id, 'idempotency-operator-session');
});

test('recordIdempotencyEvent classifies unknown outcomes without mislabeling as replay hit', async () => {
  const service = createService();

  await service.recordIdempotencyEvent({
    requestId: 'req-idempotency-unknown-outcome-audit',
    outcome: 'unexpected_outcome',
    routeKey: 'POST /platform/orgs',
    idempotencyKey: 'idem-unknown-outcome-audit',
    authorizationContext: {
      user_id: 'idempotency-operator-user',
      session_id: 'idempotency-operator-session'
    }
  });

  const unknownEvent = service._internals.auditTrail
    .filter((event) => event.type === 'auth.idempotency.unknown')
    .at(-1);
  assert.ok(unknownEvent);
  assert.equal(unknownEvent.idempotency_outcome, 'unknown');
  assert.equal(unknownEvent.detail, 'idempotency outcome is unrecognized');
});

test('auth audit trail keeps bounded size to avoid unbounded memory growth', async () => {
  const service = createService();
  const auditTrailLimit = 2000;
  const totalEvents = auditTrailLimit + 25;

  for (let index = 0; index < totalEvents; index += 1) {
    await service.recordIdempotencyEvent({
      requestId: `req-auth-audit-cap-${index}`,
      outcome: 'hit',
      routeKey: 'POST /platform/orgs',
      idempotencyKey: `idem-auth-audit-cap-${index}`,
      authorizationContext: {
        user_id: 'audit-cap-user',
        session_id: 'audit-cap-session'
      }
    });
  }

  const auditTrail = service._internals.auditTrail;
  assert.equal(auditTrail.length, auditTrailLimit);
  assert.equal(
    auditTrail[0].request_id,
    `req-auth-audit-cap-${totalEvents - auditTrailLimit}`
  );
  assert.equal(
    auditTrail.at(-1).request_id,
    `req-auth-audit-cap-${totalEvents - 1}`
  );
});

test('extractBearerToken accepts case-insensitive Authorization scheme', () => {
  const { extractBearerToken } = require('../src/modules/auth/auth.routes');

  assert.equal(extractBearerToken('Bearer abc123'), 'abc123');
  assert.equal(extractBearerToken(' Bearer abc123'), 'abc123');
  assert.equal(extractBearerToken('Bearer abc123 '), 'abc123');
  assert.equal(extractBearerToken('\tBearer abc123\t'), 'abc123');
  assert.equal(extractBearerToken('bearer abc123'), 'abc123');
  assert.equal(extractBearerToken('BEARER abc123'), 'abc123');
  assert.equal(extractBearerToken('bEaReR abc123'), 'abc123');
  assert.equal(extractBearerToken('Bearer   abc123'), 'abc123', 'multi-space between scheme and token');
  assert.equal(extractBearerToken('bearer\tabc123'), 'abc123', 'tab between scheme and token');
});

test('extractBearerToken rejects missing or malformed authorization', () => {
  const { extractBearerToken } = require('../src/modules/auth/auth.routes');

  assert.throws(() => extractBearerToken(undefined), (error) => {
    assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
    return true;
  });
  assert.throws(() => extractBearerToken('Basic abc123'), (error) => {
    assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
    return true;
  });
  assert.throws(() => extractBearerToken('Bearer'), (error) => {
    assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
    return true;
  });
  assert.throws(() => extractBearerToken('Bearer '), (error) => {
    assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
    return true;
  });
  assert.throws(() => extractBearerToken('Bearer abc def'), (error) => {
    assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
    return true;
  });
  assert.throws(() => extractBearerToken('Bearer token extra segments'), (error) => {
    assert.equal(error.errorCode, 'AUTH-401-INVALID-ACCESS');
    return true;
  });
});

test('updateTenantMemberStatus preserves tenant permission snapshot across disabled-to-active transition', async () => {
  const service = createAuthService({
    seedUsers: [
      ...seedUsers,
      {
        id: 'tenant-status-operator',
        phone: '13818880001',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: 'membership-operator-1',
            tenantId: 'tenant-permission-restore',
            tenantName: 'Tenant Permission Restore',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'tenant-status-target',
        phone: '13818880002',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: 'membership-target-restore-1',
            tenantId: 'tenant-permission-restore',
            tenantName: 'Tenant Permission Restore',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: true,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_permission_restore_role',
    code: 'TENANT_PERMISSION_RESTORE_ROLE',
    name: 'Tenant Permission Restore Role',
    scope: 'tenant',
    tenantId: 'tenant-permission-restore',
    isSystem: false
  });
  await service.replaceTenantRolePermissionGrants({
    requestId: 'req-tenant-permission-restore-grants',
    tenantId: 'tenant-permission-restore',
    roleId: 'tenant_permission_restore_role',
    permissionCodes: [
      'tenant.member_admin.view',
      'tenant.billing.view'
    ],
    operatorUserId: 'tenant-status-operator',
    operatorSessionId: 'tenant-status-session'
  });
  await service.replaceTenantMemberRoleBindings({
    requestId: 'req-tenant-permission-restore-bindings',
    tenantId: 'tenant-permission-restore',
    membershipId: 'membership-target-restore-1',
    roleIds: ['tenant_permission_restore_role'],
    operatorUserId: 'tenant-status-operator',
    operatorSessionId: 'tenant-status-session'
  });

  const disabled = await service.updateTenantMemberStatus({
    requestId: 'req-tenant-permission-restore-disable',
    membershipId: 'membership-target-restore-1',
    nextStatus: 'disabled',
    reason: 'manual-governance',
    authorizedRoute: {
      user_id: 'tenant-status-operator',
      session_id: 'tenant-status-session',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-permission-restore'
    }
  });
  assert.equal(disabled.current_status, 'disabled');

  const disabledPermission = await service._internals.authStore.findTenantPermissionByUserAndTenantId({
    userId: 'tenant-status-target',
    tenantId: 'tenant-permission-restore'
  });
  assert.equal(disabledPermission, null);

  const reactivated = await service.updateTenantMemberStatus({
    requestId: 'req-tenant-permission-restore-reactivate',
    membershipId: 'membership-target-restore-1',
    nextStatus: 'active',
    reason: 'manual-reactivate',
    authorizedRoute: {
      user_id: 'tenant-status-operator',
      session_id: 'tenant-status-session',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-permission-restore'
    }
  });
  assert.equal(reactivated.previous_status, 'disabled');
  assert.equal(reactivated.current_status, 'active');

  const restoredPermission = await service._internals.authStore.findTenantPermissionByUserAndTenantId({
    userId: 'tenant-status-target',
    tenantId: 'tenant-permission-restore'
  });
  assert.ok(restoredPermission);
  assert.equal(restoredPermission.canViewMemberAdmin, true);
  assert.equal(restoredPermission.canOperateMemberAdmin, false);
  assert.equal(restoredPermission.canViewBilling, true);
  assert.equal(restoredPermission.canOperateBilling, false);
});

test('updateTenantMemberStatus clears tenant permission snapshot across left-to-active rejoin transition', async () => {
  const service = createAuthService({
    seedUsers: [
      ...seedUsers,
      {
        id: 'tenant-status-operator-left',
        phone: '13818880011',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: 'membership-operator-left-1',
            tenantId: 'tenant-permission-rejoin',
            tenantName: 'Tenant Permission Rejoin',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      },
      {
        id: 'tenant-status-target-left',
        phone: '13818880012',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: 'membership-target-left-1',
            tenantId: 'tenant-permission-rejoin',
            tenantName: 'Tenant Permission Rejoin',
            status: 'left',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: true,
              canOperateBilling: true
            }
          }
        ]
      }
    ]
  });

  const reactivated = await service.updateTenantMemberStatus({
    requestId: 'req-tenant-permission-rejoin-reactivate',
    membershipId: 'membership-target-left-1',
    nextStatus: 'active',
    reason: 'manual-rejoin',
    authorizedRoute: {
      user_id: 'tenant-status-operator-left',
      session_id: 'tenant-status-session-left',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-permission-rejoin'
    }
  });
  assert.equal(reactivated.previous_status, 'left');
  assert.equal(reactivated.current_status, 'active');
  assert.notEqual(reactivated.membership_id, 'membership-target-left-1');

  const restoredPermission = await service._internals.authStore.findTenantPermissionByUserAndTenantId({
    userId: 'tenant-status-target-left',
    tenantId: 'tenant-permission-rejoin'
  });
  assert.ok(restoredPermission);
  assert.equal(restoredPermission.canViewMemberAdmin, false);
  assert.equal(restoredPermission.canOperateMemberAdmin, false);
  assert.equal(restoredPermission.canViewBilling, false);
  assert.equal(restoredPermission.canOperateBilling, false);
});

test('updateTenantMemberStatus fails closed when rejoin result reuses original membership_id', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  service._internals.authStore.updateTenantMembershipStatus = async () => ({
    membership_id: 'membership-rejoin-old',
    user_id: 'tenant-status-target-rejoin',
    tenant_id: 'tenant-a',
    previous_status: 'left',
    current_status: 'active'
  });

  await assert.rejects(
    () =>
      service.updateTenantMemberStatus({
        requestId: 'req-tenant-member-status-rejoin-old-membership',
        membershipId: 'membership-rejoin-old',
        nextStatus: 'active',
        reason: 'manual-rejoin',
        authorizedRoute: {
          user_id: 'platform-role-facts-operator',
          session_id: 'platform-role-facts-session',
          entry_domain: 'tenant',
          active_tenant_id: 'tenant-a'
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('updateTenantMemberStatus rejects membershipId containing control characters', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  await assert.rejects(
    () =>
      service.updateTenantMemberStatus({
        requestId: 'req-tenant-member-status-invalid-membership-id',
        membershipId: 'membership-invalid\u0000id',
        nextStatus: 'disabled',
        authorizedRoute: {
          user_id: 'platform-role-facts-operator',
          session_id: 'platform-role-facts-session',
          entry_domain: 'tenant',
          active_tenant_id: 'tenant-a'
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('updateTenantMemberStatus rejects membershipId with surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  await assert.rejects(
    () =>
      service.updateTenantMemberStatus({
        requestId: 'req-tenant-member-status-membership-id-whitespace',
        membershipId: ' membership-valid-id ',
        nextStatus: 'disabled',
        authorizedRoute: {
          user_id: 'platform-role-facts-operator',
          session_id: 'platform-role-facts-session',
          entry_domain: 'tenant',
          active_tenant_id: 'tenant-a'
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('updateTenantMemberStatus rejects reason containing control characters', async () => {
  const service = createAuthService({
    seedUsers: [buildPlatformRoleFactsOperatorSeed()]
  });

  await assert.rejects(
    () =>
      service.updateTenantMemberStatus({
        requestId: 'req-tenant-member-status-invalid-reason',
        membershipId: 'membership-valid-reason-check',
        nextStatus: 'disabled',
        reason: 'manual\nreason',
        authorizedRoute: {
          user_id: 'platform-role-facts-operator',
          session_id: 'platform-role-facts-session',
          entry_domain: 'tenant',
          active_tenant_id: 'tenant-a'
        }
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('updateTenantMemberStatus persists audit event with request_id and traceparent', async () => {
  const service = createAuthService({
    seedUsers: [
      {
        id: 'tenant-status-audit-target',
        phone: '13818880601',
        password: 'Passw0rd!',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            membershipId: 'membership-status-audit-1',
            tenantId: 'tenant-status-audit',
            tenantName: 'Tenant Status Audit',
            status: 'active',
            permission: {
              canViewMemberAdmin: true,
              canOperateMemberAdmin: false,
              canViewBilling: false,
              canOperateBilling: false
            }
          }
        ]
      }
    ]
  });
  const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

  const result = await service.updateTenantMemberStatus({
    requestId: 'req-tenant-member-status-audit',
    traceparent,
    membershipId: 'membership-status-audit-1',
    nextStatus: 'disabled',
    reason: 'manual-governance',
    authorizedRoute: {
      user_id: 'tenant-status-audit-operator',
      session_id: 'tenant-status-audit-session',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-status-audit'
    }
  });
  assert.equal(result.current_status, 'disabled');

  const auditEvents = await service.listAuditEvents({
    domain: 'tenant',
    tenantId: 'tenant-status-audit',
    requestId: 'req-tenant-member-status-audit',
    eventType: 'auth.tenant.member.status.updated'
  });
  assert.equal(auditEvents.total, 1);
  assert.equal(auditEvents.events[0].event_type, 'auth.tenant.member.status.updated');
  assert.equal(auditEvents.events[0].request_id, 'req-tenant-member-status-audit');
  assert.equal(auditEvents.events[0].traceparent, traceparent);
  assert.equal(auditEvents.events[0].target_type, 'membership');
  assert.equal(auditEvents.events[0].target_id, result.membership_id);
});

test('updateTenantMemberStatus skips out-of-transaction audit fallback when store reports audit_recorded', async () => {
  const service = createAuthService({
    authStore: {
      updateTenantMembershipStatus: async ({
        membershipId,
        nextStatus,
        auditContext
      }) => {
        assert.equal(membershipId, 'membership-tenant-atomic-audit');
        assert.equal(typeof auditContext, 'object');
        assert.equal(String(auditContext.requestId || ''), 'req-tenant-member-status-atomic-audit');
        return {
          membership_id: membershipId,
          user_id: 'tenant-user-atomic-audit',
          tenant_id: 'tenant-a',
          previous_status: 'active',
          current_status: nextStatus,
          audit_recorded: true
        };
      },
      recordAuditEvent: async () => {
        throw new Error('recordAuditEvent-should-not-be-called');
      }
    },
    allowInMemoryOtpStores: true
  });

  const result = await service.updateTenantMemberStatus({
    requestId: 'req-tenant-member-status-atomic-audit',
    membershipId: 'membership-tenant-atomic-audit',
    nextStatus: 'disabled',
    reason: 'manual-disable',
    authorizedRoute: {
      user_id: 'tenant-atomic-operator',
      session_id: 'tenant-atomic-session',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-a'
    }
  });

  assert.deepEqual(result, {
    membership_id: 'membership-tenant-atomic-audit',
    user_id: 'tenant-user-atomic-audit',
    tenant_id: 'tenant-a',
    previous_status: 'active',
    current_status: 'disabled'
  });
});

const buildTenantRoleBindingSeed = ({ membershipStatus = 'active' } = {}) => ({
  id: 'tenant-role-binding-user',
  phone: '13818889901',
  password: 'Passw0rd!',
  status: 'active',
  domains: ['tenant'],
  tenants: [
    {
      membershipId: 'membership-role-binding-1',
      tenantId: 'tenant-role-binding',
      tenantName: 'Tenant Role Binding',
      status: membershipStatus,
      permission: {
        canViewMemberAdmin: true,
        canOperateMemberAdmin: true,
        canViewBilling: false,
        canOperateBilling: false
      }
    }
  ]
});

test('replaceTenantMemberRoleBindings rejects non-active memberships', async () => {
  for (const membershipStatus of ['disabled', 'left']) {
    const service = createAuthService({
      seedUsers: [buildTenantRoleBindingSeed({ membershipStatus })]
    });

    await service.createPlatformRoleCatalogEntry({
      roleId: 'tenant_role_binding_non_active_target',
      code: 'TENANT_ROLE_BINDING_NON_ACTIVE_TARGET',
      name: 'Tenant Role Binding Non Active Target',
      scope: 'tenant',
      tenantId: 'tenant-role-binding',
      isSystem: false
    });

    await assert.rejects(
      () =>
        service.replaceTenantMemberRoleBindings({
          requestId: `req-tenant-role-binding-non-active-${membershipStatus}`,
          tenantId: 'tenant-role-binding',
          membershipId: 'membership-role-binding-1',
          roleIds: ['tenant_role_binding_non_active_target'],
          operatorUserId: 'tenant-role-binding-user',
          operatorSessionId: 'tenant-role-binding-session'
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.status, 404);
        assert.equal(error.errorCode, 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND');
        return true;
      }
    );
  }
});

test('replaceTenantMemberRoleBindings persists audit event with request_id and traceparent', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });
  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_audit_target',
    code: 'TENANT_ROLE_BINDING_AUDIT_TARGET',
    name: 'Tenant Role Binding Audit Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });
  const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

  const result = await service.replaceTenantMemberRoleBindings({
    requestId: 'req-tenant-role-binding-audit',
    traceparent,
    tenantId: 'tenant-role-binding',
    membershipId: 'membership-role-binding-1',
    roleIds: ['tenant_role_binding_audit_target'],
    operatorUserId: 'tenant-role-binding-user',
    operatorSessionId: 'tenant-role-binding-session'
  });
  assert.equal(result.membership_id, 'membership-role-binding-1');

  const auditEvents = await service.listAuditEvents({
    domain: 'tenant',
    tenantId: 'tenant-role-binding',
    requestId: 'req-tenant-role-binding-audit',
    eventType: 'auth.tenant_membership_roles.updated'
  });
  assert.equal(auditEvents.total, 1);
  assert.equal(auditEvents.events[0].event_type, 'auth.tenant_membership_roles.updated');
  assert.equal(auditEvents.events[0].request_id, 'req-tenant-role-binding-audit');
  assert.equal(auditEvents.events[0].traceparent, traceparent);
  assert.equal(auditEvents.events[0].target_type, 'membership_role_bindings');
  assert.equal(auditEvents.events[0].target_id, 'membership-role-binding-1');
});

test('replaceTenantMemberRoleBindings maps store-level non-active membership race to tenant membership not found', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_race_membership_target',
    code: 'TENANT_ROLE_BINDING_RACE_MEMBERSHIP_TARGET',
    name: 'Tenant Role Binding Race Membership Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  await service.updateTenantMemberStatus({
    requestId: 'req-tenant-role-binding-race-membership-disable',
    membershipId: 'membership-role-binding-1',
    nextStatus: 'disabled',
    reason: 'manual-disable',
    authorizedRoute: {
      user_id: 'tenant-role-binding-user',
      session_id: 'tenant-role-binding-session',
      entry_domain: 'tenant',
      active_tenant_id: 'tenant-role-binding'
    }
  });

  const authStore = service._internals.authStore;
  const originalFindMembership =
    authStore.findTenantMembershipByMembershipIdAndTenantId;
  authStore.findTenantMembershipByMembershipIdAndTenantId = async () => ({
    membership_id: 'membership-role-binding-1',
    user_id: 'tenant-role-binding-user',
    tenant_id: 'tenant-role-binding',
    phone: '13835550001',
    status: 'active'
  });

  try {
    await assert.rejects(
      () =>
        service.replaceTenantMemberRoleBindings({
          requestId: 'req-tenant-role-binding-race-membership-write',
          tenantId: 'tenant-role-binding',
          membershipId: 'membership-role-binding-1',
          roleIds: ['tenant_role_binding_race_membership_target'],
          operatorUserId: 'tenant-role-binding-user',
          operatorSessionId: 'tenant-role-binding-session'
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.status, 404);
        assert.equal(error.errorCode, 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND');
        return true;
      }
    );
  } finally {
    authStore.findTenantMembershipByMembershipIdAndTenantId =
      originalFindMembership;
  }
});

test('replaceTenantMemberRoleBindings fails closed when membership lookup returns record without phone', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  const authStore = service._internals.authStore;
  const originalFindMembership =
    authStore.findTenantMembershipByMembershipIdAndTenantId;
  authStore.findTenantMembershipByMembershipIdAndTenantId = async () => ({
    membership_id: 'membership-role-binding-1',
    user_id: 'tenant-role-binding-user',
    tenant_id: 'tenant-role-binding',
    tenant_name: 'Tenant Role Binding',
    phone: '',
    status: 'active'
  });

  try {
    await assert.rejects(
      () =>
        service.replaceTenantMemberRoleBindings({
          requestId: 'req-tenant-role-binding-missing-phone',
          tenantId: 'tenant-role-binding',
          membershipId: 'membership-role-binding-1',
          roleIds: ['tenant_role_binding_target'],
          operatorUserId: 'tenant-role-binding-user',
          operatorSessionId: 'tenant-role-binding-session'
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.status, 503);
        assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
        return true;
      }
    );
  } finally {
    authStore.findTenantMembershipByMembershipIdAndTenantId =
      originalFindMembership;
  }
});

test('replaceTenantMemberRoleBindings maps store-level role catalog race to role not found', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_race_role_target',
    code: 'TENANT_ROLE_BINDING_RACE_ROLE_TARGET',
    name: 'Tenant Role Binding Race Role Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });
  await service.updatePlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_race_role_target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    status: 'disabled',
    operatorUserId: 'tenant-role-binding-user',
    operatorSessionId: 'tenant-role-binding-session'
  });

  const authStore = service._internals.authStore;
  const originalFindRoleCatalogEntries =
    authStore.findPlatformRoleCatalogEntriesByRoleIds;
  authStore.findPlatformRoleCatalogEntriesByRoleIds = async ({
    roleIds = []
  } = {}) =>
    (Array.isArray(roleIds) ? roleIds : []).map((roleId) => ({
      roleId: String(roleId || '').trim().toLowerCase(),
      tenantId: 'tenant-role-binding',
      status: 'active',
      scope: 'tenant'
    }));

  try {
    await assert.rejects(
      () =>
        service.replaceTenantMemberRoleBindings({
          requestId: 'req-tenant-role-binding-race-role-write',
          tenantId: 'tenant-role-binding',
          membershipId: 'membership-role-binding-1',
          roleIds: ['tenant_role_binding_race_role_target'],
          operatorUserId: 'tenant-role-binding-user',
          operatorSessionId: 'tenant-role-binding-session'
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.status, 404);
        assert.equal(error.errorCode, 'AUTH-404-ROLE-NOT-FOUND');
        return true;
      }
    );
  } finally {
    authStore.findPlatformRoleCatalogEntriesByRoleIds =
      originalFindRoleCatalogEntries;
  }
});

test('replaceTenantMemberRoleBindings fails closed when role catalog lookup returns role ids with surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_catalog_whitespace_write_target',
    code: 'TENANT_ROLE_BINDING_CATALOG_WHITESPACE_WRITE_TARGET',
    name: 'Tenant Role Binding Catalog Whitespace Write Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  const authStore = service._internals.authStore;
  const originalFindRoleCatalogEntries =
    authStore.findPlatformRoleCatalogEntriesByRoleIds;
  authStore.findPlatformRoleCatalogEntriesByRoleIds = async () => [
    {
      role_id: ' tenant_role_binding_catalog_whitespace_write_target',
      tenant_id: 'tenant-role-binding',
      status: 'active',
      scope: 'tenant'
    }
  ];

  try {
    await assert.rejects(
      () =>
        service.replaceTenantMemberRoleBindings({
          requestId: 'req-tenant-role-binding-catalog-roleid-whitespace-write',
          tenantId: 'tenant-role-binding',
          membershipId: 'membership-role-binding-1',
          roleIds: ['tenant_role_binding_catalog_whitespace_write_target'],
          operatorUserId: 'tenant-role-binding-user',
          operatorSessionId: 'tenant-role-binding-session'
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.status, 503);
        assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
        return true;
      }
    );
  } finally {
    authStore.findPlatformRoleCatalogEntriesByRoleIds =
      originalFindRoleCatalogEntries;
  }
});

test('replaceTenantMemberRoleBindings fails closed when role catalog lookup returns scopes with surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_catalog_scope_whitespace_write_target',
    code: 'TENANT_ROLE_BINDING_CATALOG_SCOPE_WHITESPACE_WRITE_TARGET',
    name: 'Tenant Role Binding Catalog Scope Whitespace Write Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  const authStore = service._internals.authStore;
  const originalFindRoleCatalogEntries =
    authStore.findPlatformRoleCatalogEntriesByRoleIds;
  authStore.findPlatformRoleCatalogEntriesByRoleIds = async () => [
    {
      role_id: 'tenant_role_binding_catalog_scope_whitespace_write_target',
      tenant_id: 'tenant-role-binding',
      status: 'active',
      scope: ' tenant'
    }
  ];

  try {
    await assert.rejects(
      () =>
        service.replaceTenantMemberRoleBindings({
          requestId: 'req-tenant-role-binding-catalog-scope-whitespace-write',
          tenantId: 'tenant-role-binding',
          membershipId: 'membership-role-binding-1',
          roleIds: ['tenant_role_binding_catalog_scope_whitespace_write_target'],
          operatorUserId: 'tenant-role-binding-user',
          operatorSessionId: 'tenant-role-binding-session'
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.status, 503);
        assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
        return true;
      }
    );
  } finally {
    authStore.findPlatformRoleCatalogEntriesByRoleIds =
      originalFindRoleCatalogEntries;
  }
});

test('replaceTenantMemberRoleBindings maps store-level sync failure to tenant dependency unavailable', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_sync_failure_target',
    code: 'TENANT_ROLE_BINDING_SYNC_FAILURE_TARGET',
    name: 'Tenant Role Binding Sync Failure Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => {
    const syncError = new Error('tenant membership role bindings sync failed: unknown');
    syncError.code = 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_SYNC_FAILED';
    syncError.syncReason = 'unknown';
    throw syncError;
  };

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-sync-failed',
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1',
        roleIds: ['tenant_role_binding_sync_failure_target'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantRolePermissionGrants fails closed when grants dependency contains empty permission code', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_list_permission_target',
    code: 'TENANT_ROLE_BINDING_LIST_PERMISSION_TARGET',
    name: 'Tenant Role Binding List Permission Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.listTenantRolePermissionGrantsByRoleIds = async () => [
    {
      roleId: 'tenant_role_binding_list_permission_target',
      permissionCodes: ['']
    }
  ];

  await assert.rejects(
    () =>
      service.listTenantRolePermissionGrants({
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_binding_list_permission_target'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantRolePermissionGrants fails closed when grants dependency contains permission codes with surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_list_permission_whitespace_target',
    code: 'TENANT_ROLE_BINDING_LIST_PERMISSION_WHITESPACE_TARGET',
    name: 'Tenant Role Binding List Permission Whitespace Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.listTenantRolePermissionGrantsByRoleIds = async () => [
    {
      roleId: 'tenant_role_binding_list_permission_whitespace_target',
      permissionCodes: [' tenant.member_admin.view']
    }
  ];

  await assert.rejects(
    () =>
      service.listTenantRolePermissionGrants({
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_binding_list_permission_whitespace_target'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantRolePermissionGrants fails closed when role catalog lookup returns duplicate role entries', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_catalog_duplicate_target',
    code: 'TENANT_ROLE_BINDING_CATALOG_DUPLICATE_TARGET',
    name: 'Tenant Role Binding Catalog Duplicate Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.findPlatformRoleCatalogEntriesByRoleIds = async () => [
    {
      role_id: 'tenant_role_binding_catalog_duplicate_target',
      status: 'active',
      scope: 'tenant',
      tenant_id: 'tenant-role-binding'
    },
    {
      role_id: 'tenant_role_binding_catalog_duplicate_target',
      status: 'active',
      scope: 'tenant',
      tenant_id: 'tenant-role-binding'
    }
  ];

  await assert.rejects(
    () =>
      service.listTenantRolePermissionGrants({
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_binding_catalog_duplicate_target'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantRolePermissionGrants accepts snake_case catalog fields when camelCase shadow keys are undefined', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_catalog_shadow_fallback_target',
    code: 'TENANT_ROLE_BINDING_CATALOG_SHADOW_FALLBACK_TARGET',
    name: 'Tenant Role Binding Catalog Shadow Fallback Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  const authStore = service._internals.authStore;
  const originalFindCatalogEntries =
    authStore.findPlatformRoleCatalogEntriesByRoleIds;
  authStore.findPlatformRoleCatalogEntriesByRoleIds = async () => [
    {
      roleId: undefined,
      role_id: 'tenant_role_binding_catalog_shadow_fallback_target',
      status: 'active',
      scope: 'tenant',
      tenantId: undefined,
      tenant_id: 'tenant-role-binding'
    }
  ];

  try {
    const result = await service.listTenantRolePermissionGrants({
      tenantId: 'tenant-role-binding',
      roleId: 'tenant_role_binding_catalog_shadow_fallback_target'
    });
    assert.equal(result.role_id, 'tenant_role_binding_catalog_shadow_fallback_target');
    assert.deepEqual(result.permission_codes, []);
    assert.ok(Array.isArray(result.available_permission_codes));
  } finally {
    authStore.findPlatformRoleCatalogEntriesByRoleIds =
      originalFindCatalogEntries;
  }
});

test('listTenantRolePermissionGrants fails closed when role catalog lookup returns role ids with surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_catalog_whitespace_target',
    code: 'TENANT_ROLE_BINDING_CATALOG_WHITESPACE_TARGET',
    name: 'Tenant Role Binding Catalog Whitespace Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.findPlatformRoleCatalogEntriesByRoleIds = async () => [
    {
      role_id: ' tenant_role_binding_catalog_whitespace_target',
      status: 'active',
      scope: 'tenant',
      tenant_id: 'tenant-role-binding'
    }
  ];

  await assert.rejects(
    () =>
      service.listTenantRolePermissionGrants({
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_binding_catalog_whitespace_target'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantRolePermissionGrants fails closed when role catalog lookup returns status with surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_catalog_status_whitespace_target',
    code: 'TENANT_ROLE_BINDING_CATALOG_STATUS_WHITESPACE_TARGET',
    name: 'Tenant Role Binding Catalog Status Whitespace Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.findPlatformRoleCatalogEntriesByRoleIds = async () => [
    {
      role_id: 'tenant_role_binding_catalog_status_whitespace_target',
      status: ' active',
      scope: 'tenant',
      tenant_id: 'tenant-role-binding'
    }
  ];

  await assert.rejects(
    () =>
      service.listTenantRolePermissionGrants({
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_binding_catalog_status_whitespace_target'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantRolePermissionGrants fails closed when grants dependency role ids contain surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_grant_role_whitespace_target',
    code: 'TENANT_ROLE_BINDING_GRANT_ROLE_WHITESPACE_TARGET',
    name: 'Tenant Role Binding Grant Role Whitespace Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.listTenantRolePermissionGrantsByRoleIds = async () => [
    {
      roleId: ' tenant_role_binding_grant_role_whitespace_target',
      permissionCodes: ['tenant.member_admin.view']
    }
  ];

  await assert.rejects(
    () =>
      service.listTenantRolePermissionGrants({
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_binding_grant_role_whitespace_target'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantRolePermissionGrants fails closed when grants dependency returns duplicate role entries', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_grant_duplicate_target',
    code: 'TENANT_ROLE_BINDING_GRANT_DUPLICATE_TARGET',
    name: 'Tenant Role Binding Grant Duplicate Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.listTenantRolePermissionGrantsByRoleIds = async () => [
    {
      roleId: 'tenant_role_binding_grant_duplicate_target',
      permissionCodes: ['tenant.member_admin.view']
    },
    {
      roleId: 'tenant_role_binding_grant_duplicate_target',
      permissionCodes: ['tenant.billing.view']
    }
  ];

  await assert.rejects(
    () =>
      service.listTenantRolePermissionGrants({
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_binding_grant_duplicate_target'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantMemberRoleBindings fails closed when store returns malformed role ids', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  service._internals.authStore.listTenantMembershipRoleBindings = async () => [
    'tenant_role_valid',
    'tenant role invalid'
  ];

  await assert.rejects(
    () =>
      service.listTenantMemberRoleBindings({
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantMemberRoleBindings fails closed when membership lookup returns record without phone', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  const authStore = service._internals.authStore;
  const originalFindMembership =
    authStore.findTenantMembershipByMembershipIdAndTenantId;
  authStore.findTenantMembershipByMembershipIdAndTenantId = async () => ({
    membership_id: 'membership-role-binding-1',
    user_id: 'tenant-role-binding-user',
    tenant_id: 'tenant-role-binding',
    tenant_name: 'Tenant Role Binding',
    phone: '',
    status: 'active'
  });

  try {
    await assert.rejects(
      () =>
        service.listTenantMemberRoleBindings({
          tenantId: 'tenant-role-binding',
          membershipId: 'membership-role-binding-1'
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.status, 503);
        assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
        return true;
      }
    );
  } finally {
    authStore.findTenantMembershipByMembershipIdAndTenantId =
      originalFindMembership;
  }
});

test('listTenantMemberRoleBindings fails closed when store returns role ids with surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  service._internals.authStore.listTenantMembershipRoleBindings = async () => [
    ' tenant_role_valid'
  ];

  await assert.rejects(
    () =>
      service.listTenantMemberRoleBindings({
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantMemberRoleBindings fails closed when store returns more than 5 role ids', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  service._internals.authStore.listTenantMembershipRoleBindings = async () => [
    'tenant_role_1',
    'tenant_role_2',
    'tenant_role_3',
    'tenant_role_4',
    'tenant_role_5',
    'tenant_role_6'
  ];

  await assert.rejects(
    () =>
      service.listTenantMemberRoleBindings({
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantMemberRoleBindings fails closed when store returns cross-tenant role ids', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_other_tenant',
    code: 'TENANT_ROLE_BINDING_OTHER_TENANT',
    name: 'Tenant Role Binding Other Tenant',
    scope: 'tenant',
    tenantId: 'tenant-role-binding-other',
    isSystem: false
  });

  service._internals.authStore.listTenantMembershipRoleBindings = async () => [
    'tenant_role_binding_other_tenant'
  ];

  await assert.rejects(
    () =>
      service.listTenantMemberRoleBindings({
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantMemberRoleBindings accepts snake_case write result fields when camelCase shadow keys are undefined', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_shadow_fallback_target',
    code: 'TENANT_ROLE_BINDING_SHADOW_FALLBACK_TARGET',
    name: 'Tenant Role Binding Shadow Fallback Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  const authStore = service._internals.authStore;
  const originalReplaceBindings =
    authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot;
  authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => ({
    membershipId: undefined,
    membership_id: 'membership-role-binding-1',
    roleIds: undefined,
    role_ids: ['tenant_role_binding_shadow_fallback_target'],
    affectedUserIds: undefined,
    affected_user_ids: ['tenant-role-binding-user'],
    affectedUserCount: undefined,
    affected_user_count: 1
  });

  try {
    const result = await service.replaceTenantMemberRoleBindings({
      requestId: 'req-tenant-role-binding-write-shadow-fallback',
      tenantId: 'tenant-role-binding',
      membershipId: 'membership-role-binding-1',
      roleIds: ['tenant_role_binding_shadow_fallback_target'],
      operatorUserId: 'tenant-role-binding-user',
      operatorSessionId: 'tenant-role-binding-session'
    });

    assert.equal(result.membership_id, 'membership-role-binding-1');
    assert.deepEqual(result.role_ids, ['tenant_role_binding_shadow_fallback_target']);
  } finally {
    authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot =
      originalReplaceBindings;
  }
});

test('replaceTenantMemberRoleBindings fails closed when store write result contains malformed role ids', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_a',
    code: 'TENANT_ROLE_BINDING_A',
    name: 'Tenant Role Binding A',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });
  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_b',
    code: 'TENANT_ROLE_BINDING_B',
    name: 'Tenant Role Binding B',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => ({
    membershipId: 'membership-role-binding-1',
    roleIds: ['tenant_role_binding_a', 'tenant role invalid'],
    affectedUserIds: ['tenant-role-binding-user'],
    affectedUserCount: 1
  });

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-malformed-result',
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1',
        roleIds: ['tenant_role_binding_a', 'tenant_role_binding_b'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantMemberRoleBindings fails closed when store write result role ids contain surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_ws_a',
    code: 'TENANT_ROLE_BINDING_WS_A',
    name: 'Tenant Role Binding WS A',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => ({
    membershipId: 'membership-role-binding-1',
    roleIds: [' tenant_role_binding_ws_a'],
    affectedUserIds: ['tenant-role-binding-user'],
    affectedUserCount: 1
  });

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-role-ids-whitespace',
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1',
        roleIds: ['tenant_role_binding_ws_a'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantMemberRoleBindings fails closed when store write result mismatches requested role ids', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_a',
    code: 'TENANT_ROLE_BINDING_A',
    name: 'Tenant Role Binding A',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });
  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_b',
    code: 'TENANT_ROLE_BINDING_B',
    name: 'Tenant Role Binding B',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => ({
    membershipId: 'membership-role-binding-1',
    roleIds: ['tenant_role_binding_a'],
    affectedUserIds: ['tenant-role-binding-user'],
    affectedUserCount: 1
  });

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-mismatch-result',
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1',
        roleIds: ['tenant_role_binding_a', 'tenant_role_binding_b'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrants rolls back grants and snapshots when sync fails mid-flight', async () => {
  const { service, authStore } = await setupTenantGrantSyncFailureScenario();

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-grant-sync-failure-write',
        tenantId: TENANT_GRANT_SYNC_FAILURE_TENANT_ID,
        roleId: TENANT_GRANT_SYNC_FAILURE_ROLE_ID,
        permissionCodes: ['tenant.member_admin.operate'],
        operatorUserId: TENANT_GRANT_SYNC_FAILURE_OPERATOR_USER_ID,
        operatorSessionId: 'tenant-grant-sync-operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );

  const grants = await service.listTenantRolePermissionGrants({
    tenantId: TENANT_GRANT_SYNC_FAILURE_TENANT_ID,
    roleId: TENANT_GRANT_SYNC_FAILURE_ROLE_ID
  });
  assert.deepEqual(grants.permission_codes, ['tenant.member_admin.view']);

  const permissionA = await authStore.findTenantPermissionByUserAndTenantId({
    userId: TENANT_GRANT_SYNC_FAILURE_USER_A,
    tenantId: TENANT_GRANT_SYNC_FAILURE_TENANT_ID
  });
  const permissionB = await authStore.findTenantPermissionByUserAndTenantId({
    userId: TENANT_GRANT_SYNC_FAILURE_USER_B,
    tenantId: TENANT_GRANT_SYNC_FAILURE_TENANT_ID
  });
  assert.ok(permissionA);
  assert.ok(permissionB);
  assert.equal(permissionA.canViewMemberAdmin, true);
  assert.equal(permissionA.canOperateMemberAdmin, false);
  assert.equal(permissionB.canViewMemberAdmin, true);
  assert.equal(permissionB.canOperateMemberAdmin, false);
});

test('replaceTenantRolePermissionGrants failed rollback keeps tenant session active', async () => {
  const { service, authStore } = await setupTenantGrantSyncFailureScenario();
  const userA = await authStore.findUserById(TENANT_GRANT_SYNC_FAILURE_USER_A);
  const sessionId = 'tenant-grant-sync-session-a';
  await authStore.createSession({
    sessionId,
    userId: TENANT_GRANT_SYNC_FAILURE_USER_A,
    sessionVersion: Number(userA?.sessionVersion || 1),
    entryDomain: 'tenant',
    activeTenantId: TENANT_GRANT_SYNC_FAILURE_TENANT_ID
  });

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-grant-sync-failure-session-write',
        tenantId: TENANT_GRANT_SYNC_FAILURE_TENANT_ID,
        roleId: TENANT_GRANT_SYNC_FAILURE_ROLE_ID,
        permissionCodes: ['tenant.member_admin.operate'],
        operatorUserId: TENANT_GRANT_SYNC_FAILURE_OPERATOR_USER_ID,
        operatorSessionId: 'tenant-grant-sync-operator-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );

  const session = await authStore.findSessionById(sessionId);
  assert.ok(session);
  assert.equal(session.status, 'active');
});

test('replaceTenantRolePermissionGrants fails closed when store write result mismatches requested permission codes', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_target',
    code: 'TENANT_ROLE_PERMISSION_TARGET',
    name: 'Tenant Role Permission Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'tenant_role_permission_target',
    permissionCodes: ['tenant.billing.view'],
    affectedUserIds: [],
    affectedUserCount: 0
  });

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-role-permission-write-mismatch-result',
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_permission_target',
        permissionCodes: ['tenant.member_admin.view'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrants accepts snake_case write result fields when camelCase shadow keys are undefined', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_shadow_fallback_target',
    code: 'TENANT_ROLE_PERMISSION_SHADOW_FALLBACK_TARGET',
    name: 'Tenant Role Permission Shadow Fallback Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  const authStore = service._internals.authStore;
  const originalReplaceAtomic =
    authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots;
  authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: undefined,
    role_id: 'tenant_role_permission_shadow_fallback_target',
    permissionCodes: undefined,
    permission_codes: ['tenant.member_admin.view'],
    affectedUserIds: undefined,
    affected_user_ids: ['tenant-role-binding-user'],
    affectedUserCount: undefined,
    affected_user_count: 1
  });

  try {
    const result = await service.replaceTenantRolePermissionGrants({
      requestId: 'req-tenant-role-permission-write-shadow-fallback',
      tenantId: 'tenant-role-binding',
      roleId: 'tenant_role_permission_shadow_fallback_target',
      permissionCodes: ['tenant.member_admin.view'],
      operatorUserId: 'tenant-role-binding-user',
      operatorSessionId: 'tenant-role-binding-session'
    });

    assert.equal(result.role_id, 'tenant_role_permission_shadow_fallback_target');
    assert.deepEqual(result.permission_codes, ['tenant.member_admin.view']);
    assert.equal(result.affected_user_count, 1);
  } finally {
    authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots =
      originalReplaceAtomic;
  }
});

test('replaceTenantRolePermissionGrants fails closed when store write result contains permission codes with surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_whitespace_target',
    code: 'TENANT_ROLE_PERMISSION_WHITESPACE_TARGET',
    name: 'Tenant Role Permission Whitespace Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'tenant_role_permission_whitespace_target',
    permissionCodes: [' tenant.member_admin.view'],
    affectedUserIds: [],
    affectedUserCount: 0
  });

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-role-permission-write-permission-whitespace',
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_permission_whitespace_target',
        permissionCodes: ['tenant.member_admin.view'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrants skips out-of-transaction audit fallback when atomic store reports audit_recorded', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_atomic_audit_recorded_target',
    code: 'TENANT_ROLE_PERMISSION_ATOMIC_AUDIT_RECORDED_TARGET',
    name: 'Tenant Role Permission Atomic Audit Recorded Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  const authStore = service._internals.authStore;
  const originalReplaceAtomic =
    authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots;
  const originalRecordAuditEvent = authStore.recordAuditEvent;
  authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async ({
    tenantId,
    roleId,
    permissionCodes,
    auditContext
  }) => {
    assert.equal(tenantId, 'tenant-role-binding');
    assert.equal(roleId, 'tenant_role_permission_atomic_audit_recorded_target');
    assert.deepEqual(permissionCodes, ['tenant.member_admin.view']);
    assert.equal(typeof auditContext, 'object');
    assert.equal(
      String(auditContext?.requestId || ''),
      'req-tenant-role-permission-atomic-audit-recorded'
    );
    assert.equal(String(auditContext?.actorUserId || ''), 'tenant-role-binding-user');
    assert.equal(String(auditContext?.actorSessionId || ''), 'tenant-role-binding-session');
    return {
      roleId: 'tenant_role_permission_atomic_audit_recorded_target',
      permissionCodes: ['tenant.member_admin.view'],
      affectedUserIds: ['tenant-role-binding-user'],
      affectedUserCount: 1,
      audit_recorded: true
    };
  };
  authStore.recordAuditEvent = async () => {
    throw new Error('recordAuditEvent-should-not-be-called');
  };

  try {
    const result = await service.replaceTenantRolePermissionGrants({
      requestId: 'req-tenant-role-permission-atomic-audit-recorded',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
      tenantId: 'tenant-role-binding',
      roleId: 'tenant_role_permission_atomic_audit_recorded_target',
      permissionCodes: ['tenant.member_admin.view'],
      operatorUserId: 'tenant-role-binding-user',
      operatorSessionId: 'tenant-role-binding-session'
    });

    assert.deepEqual(result, {
      role_id: 'tenant_role_permission_atomic_audit_recorded_target',
      permission_codes: ['tenant.member_admin.view'],
      affected_user_count: 1
    });
  } finally {
    authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots =
      originalReplaceAtomic;
    authStore.recordAuditEvent = originalRecordAuditEvent;
  }
});

test('replaceTenantRolePermissionGrants maps ERR_AUDIT_WRITE_FAILED from atomic store to tenant dependency unavailable', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_atomic_audit_failed_target',
    code: 'TENANT_ROLE_PERMISSION_ATOMIC_AUDIT_FAILED_TARGET',
    name: 'Tenant Role Permission Atomic Audit Failed Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async () => {
    const error = new Error('tenant-atomic-audit-write-failed');
    error.code = 'ERR_AUDIT_WRITE_FAILED';
    throw error;
  };

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-role-permission-atomic-audit-failed',
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_permission_atomic_audit_failed_target',
        permissionCodes: ['tenant.member_admin.view'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      assert.equal(error.extensions?.degradation_reason, 'audit-write-failed');
      return true;
    }
  );
});

test('replaceTenantMemberRoleBindings fails closed when store write result exceeds 5 role ids', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_a',
    code: 'TENANT_ROLE_BINDING_A',
    name: 'Tenant Role Binding A',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });
  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_b',
    code: 'TENANT_ROLE_BINDING_B',
    name: 'Tenant Role Binding B',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => ({
    membershipId: 'membership-role-binding-1',
    roleIds: [
      'tenant_role_1',
      'tenant_role_2',
      'tenant_role_3',
      'tenant_role_4',
      'tenant_role_5',
      'tenant_role_6'
    ],
    affectedUserIds: ['tenant-role-binding-user'],
    affectedUserCount: 1
  });

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-over-limit-result',
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1',
        roleIds: ['tenant_role_binding_a', 'tenant_role_binding_b'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantMemberRoleBindings fails closed when store returns non-string role ids', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_numeric',
    code: 'TENANT_ROLE_BINDING_NUMERIC',
    name: 'Tenant Role Binding Numeric',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.listTenantMembershipRoleBindings = async () => [123];

  await assert.rejects(
    () =>
      service.listTenantMemberRoleBindings({
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantMemberRoleBindings fails closed when store write result mismatches requested membership_id', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_a',
    code: 'TENANT_ROLE_BINDING_A',
    name: 'Tenant Role Binding A',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => ({
    membershipId: 'membership-role-binding-2',
    roleIds: ['tenant_role_binding_a'],
    affectedUserIds: ['tenant-role-binding-user'],
    affectedUserCount: 1
  });

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-membership-mismatch',
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1',
        roleIds: ['tenant_role_binding_a'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantMemberRoleBindings fails closed when store write result membership_id contains surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_membership_whitespace_a',
    code: 'TENANT_ROLE_BINDING_MEMBERSHIP_WHITESPACE_A',
    name: 'Tenant Role Binding Membership Whitespace A',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => ({
    membershipId: ' membership-role-binding-1',
    roleIds: ['tenant_role_binding_membership_whitespace_a'],
    affectedUserIds: ['tenant-role-binding-user'],
    affectedUserCount: 1
  });

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-membership-whitespace',
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1',
        roleIds: ['tenant_role_binding_membership_whitespace_a'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantMemberRoleBindings fails closed when store write result has invalid affected user ids', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_a',
    code: 'TENANT_ROLE_BINDING_A',
    name: 'Tenant Role Binding A',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => ({
    membershipId: 'membership-role-binding-1',
    roleIds: ['tenant_role_binding_a'],
    affectedUserIds: ['tenant-role-binding-user', 123],
    affectedUserCount: 2
  });

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-affected-user-ids-invalid',
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1',
        roleIds: ['tenant_role_binding_a'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantMemberRoleBindings fails closed when store write result affected user ids contain surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_a',
    code: 'TENANT_ROLE_BINDING_A',
    name: 'Tenant Role Binding A',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => ({
    membershipId: 'membership-role-binding-1',
    roleIds: ['tenant_role_binding_a'],
    affectedUserIds: [' tenant-role-binding-user'],
    affectedUserCount: 1
  });

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-affected-user-ids-whitespace',
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1',
        roleIds: ['tenant_role_binding_a'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantMemberRoleBindings fails closed when store write result omits affected user metadata', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_a',
    code: 'TENANT_ROLE_BINDING_A',
    name: 'Tenant Role Binding A',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => ({
    membershipId: 'membership-role-binding-1',
    roleIds: ['tenant_role_binding_a']
  });

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-affected-user-metadata-missing',
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1',
        roleIds: ['tenant_role_binding_a'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantMemberRoleBindings fails closed when affected user ids are null', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_a',
    code: 'TENANT_ROLE_BINDING_A',
    name: 'Tenant Role Binding A',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => ({
    membershipId: 'membership-role-binding-1',
    roleIds: ['tenant_role_binding_a'],
    affectedUserIds: null,
    affectedUserCount: 0
  });

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-affected-user-ids-null',
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1',
        roleIds: ['tenant_role_binding_a'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantMemberRoleBindings fails closed when affected user count is null', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_a',
    code: 'TENANT_ROLE_BINDING_A',
    name: 'Tenant Role Binding A',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => ({
    membershipId: 'membership-role-binding-1',
    roleIds: ['tenant_role_binding_a'],
    affectedUserIds: ['tenant-role-binding-user'],
    affectedUserCount: null
  });

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-affected-user-count-null',
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1',
        roleIds: ['tenant_role_binding_a'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantMemberRoleBindings fails closed when affected user count mismatches affected user ids', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_a',
    code: 'TENANT_ROLE_BINDING_A',
    name: 'Tenant Role Binding A',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot = async () => ({
    membershipId: 'membership-role-binding-1',
    roleIds: ['tenant_role_binding_a'],
    affectedUserIds: ['tenant-role-binding-user'],
    affectedUserCount: 2
  });

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-affected-user-count-mismatch',
        tenantId: 'tenant-role-binding',
        membershipId: 'membership-role-binding-1',
        roleIds: ['tenant_role_binding_a'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrants fails closed when role catalog lookup returns role ids with surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_catalog_whitespace_target',
    code: 'TENANT_ROLE_PERMISSION_CATALOG_WHITESPACE_TARGET',
    name: 'Tenant Role Permission Catalog Whitespace Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  const authStore = service._internals.authStore;
  const originalFindRoleCatalogEntries =
    authStore.findPlatformRoleCatalogEntriesByRoleIds;
  authStore.findPlatformRoleCatalogEntriesByRoleIds = async () => [
    {
      role_id: ' tenant_role_permission_catalog_whitespace_target',
      tenant_id: 'tenant-role-binding',
      status: 'active',
      scope: 'tenant'
    }
  ];

  try {
    await assert.rejects(
      () =>
        service.replaceTenantRolePermissionGrants({
          requestId: 'req-tenant-role-permission-catalog-roleid-whitespace-write',
          tenantId: 'tenant-role-binding',
          roleId: 'tenant_role_permission_catalog_whitespace_target',
          permissionCodes: ['tenant.member_admin.view'],
          operatorUserId: 'tenant-role-binding-user',
          operatorSessionId: 'tenant-role-binding-session'
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.status, 503);
        assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
        return true;
      }
    );
  } finally {
    authStore.findPlatformRoleCatalogEntriesByRoleIds =
      originalFindRoleCatalogEntries;
  }
});

test('replaceTenantRolePermissionGrants fails closed when role catalog lookup returns tenant ids with surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_catalog_tenant_whitespace_target',
    code: 'TENANT_ROLE_PERMISSION_CATALOG_TENANT_WHITESPACE_TARGET',
    name: 'Tenant Role Permission Catalog Tenant Whitespace Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  const authStore = service._internals.authStore;
  const originalFindRoleCatalogEntries =
    authStore.findPlatformRoleCatalogEntriesByRoleIds;
  authStore.findPlatformRoleCatalogEntriesByRoleIds = async () => [
    {
      role_id: 'tenant_role_permission_catalog_tenant_whitespace_target',
      tenant_id: ' tenant-role-binding',
      status: 'active',
      scope: 'tenant'
    }
  ];

  try {
    await assert.rejects(
      () =>
        service.replaceTenantRolePermissionGrants({
          requestId: 'req-tenant-role-permission-catalog-tenantid-whitespace-write',
          tenantId: 'tenant-role-binding',
          roleId: 'tenant_role_permission_catalog_tenant_whitespace_target',
          permissionCodes: ['tenant.member_admin.view'],
          operatorUserId: 'tenant-role-binding-user',
          operatorSessionId: 'tenant-role-binding-session'
        }),
      (error) => {
        assert.ok(error instanceof AuthProblemError);
        assert.equal(error.status, 503);
        assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
        return true;
      }
    );
  } finally {
    authStore.findPlatformRoleCatalogEntriesByRoleIds =
      originalFindRoleCatalogEntries;
  }
});

test('replaceTenantRolePermissionGrants fails closed when store write result mismatches requested role_id', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_target',
    code: 'TENANT_ROLE_PERMISSION_TARGET',
    name: 'Tenant Role Permission Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'tenant_role_permission_other',
    permissionCodes: ['tenant.member_admin.view'],
    affectedUserIds: [],
    affectedUserCount: 0
  });

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-role-permission-write-role-mismatch',
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_permission_target',
        permissionCodes: ['tenant.member_admin.view'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrants fails closed when store write result role_id contains surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_roleid_whitespace_target',
    code: 'TENANT_ROLE_PERMISSION_ROLEID_WHITESPACE_TARGET',
    name: 'Tenant Role Permission RoleId Whitespace Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: ' tenant_role_permission_roleid_whitespace_target',
    permissionCodes: ['tenant.member_admin.view'],
    affectedUserIds: [],
    affectedUserCount: 0
  });

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-role-permission-write-role-whitespace',
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_permission_roleid_whitespace_target',
        permissionCodes: ['tenant.member_admin.view'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrants fails closed when store write result has invalid affected user ids', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_target',
    code: 'TENANT_ROLE_PERMISSION_TARGET',
    name: 'Tenant Role Permission Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'tenant_role_permission_target',
    permissionCodes: ['tenant.member_admin.view'],
    affectedUserIds: ['tenant-role-binding-user', 123],
    affectedUserCount: 2
  });

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-role-permission-write-affected-user-ids-invalid',
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_permission_target',
        permissionCodes: ['tenant.member_admin.view'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrants fails closed when store write result affected user ids contain surrounding whitespace', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_target',
    code: 'TENANT_ROLE_PERMISSION_TARGET',
    name: 'Tenant Role Permission Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'tenant_role_permission_target',
    permissionCodes: ['tenant.member_admin.view'],
    affectedUserIds: [' tenant-role-binding-user'],
    affectedUserCount: 1
  });

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-role-permission-write-affected-user-ids-whitespace',
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_permission_target',
        permissionCodes: ['tenant.member_admin.view'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrants fails closed when store write result has invalid affected user count', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_target',
    code: 'TENANT_ROLE_PERMISSION_TARGET',
    name: 'Tenant Role Permission Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'tenant_role_permission_target',
    permissionCodes: ['tenant.member_admin.view'],
    affectedUserIds: ['tenant-role-binding-user'],
    affectedUserCount: -1
  });

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-role-permission-write-affected-user-count-invalid',
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_permission_target',
        permissionCodes: ['tenant.member_admin.view'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrants fails closed when store write result omits affected user metadata', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_target',
    code: 'TENANT_ROLE_PERMISSION_TARGET',
    name: 'Tenant Role Permission Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'tenant_role_permission_target',
    permissionCodes: ['tenant.member_admin.view']
  });

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-role-permission-write-affected-user-metadata-missing',
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_permission_target',
        permissionCodes: ['tenant.member_admin.view'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrants fails closed when affected user ids are null', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_target',
    code: 'TENANT_ROLE_PERMISSION_TARGET',
    name: 'Tenant Role Permission Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'tenant_role_permission_target',
    permissionCodes: ['tenant.member_admin.view'],
    affectedUserIds: null,
    affectedUserCount: 0
  });

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-role-permission-write-affected-user-ids-null',
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_permission_target',
        permissionCodes: ['tenant.member_admin.view'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrants fails closed when affected user count is null', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_target',
    code: 'TENANT_ROLE_PERMISSION_TARGET',
    name: 'Tenant Role Permission Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'tenant_role_permission_target',
    permissionCodes: ['tenant.member_admin.view'],
    affectedUserIds: ['tenant-role-binding-user'],
    affectedUserCount: null
  });

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-role-permission-write-affected-user-count-null',
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_permission_target',
        permissionCodes: ['tenant.member_admin.view'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrants fails closed when affected user count mismatches affected user ids', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_permission_target',
    code: 'TENANT_ROLE_PERMISSION_TARGET',
    name: 'Tenant Role Permission Target',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  service._internals.authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots = async () => ({
    roleId: 'tenant_role_permission_target',
    permissionCodes: ['tenant.member_admin.view'],
    affectedUserIds: ['tenant-role-binding-user'],
    affectedUserCount: 2
  });

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-role-permission-write-affected-user-count-mismatch',
        tenantId: 'tenant-role-binding',
        roleId: 'tenant_role_permission_target',
        permissionCodes: ['tenant.member_admin.view'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
});

test('listTenantRolePermissionGrants rejects role_id with surrounding whitespace as invalid payload', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await assert.rejects(
    () =>
      service.listTenantRolePermissionGrants({
        tenantId: 'tenant-role-binding',
        roleId: ' tenant_role_binding_a'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('replaceTenantRolePermissionGrants rejects malformed role_id as invalid payload', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await assert.rejects(
    () =>
      service.replaceTenantRolePermissionGrants({
        requestId: 'req-tenant-role-permission-write-invalid-role-id',
        tenantId: 'tenant-role-binding',
        roleId: 'tenant role invalid',
        permissionCodes: ['tenant.member_admin.view'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('listTenantMemberRoleBindings rejects membership_id with surrounding whitespace as invalid payload', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await assert.rejects(
    () =>
      service.listTenantMemberRoleBindings({
        tenantId: 'tenant-role-binding',
        membershipId: ' membership-role-binding-1'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('replaceTenantMemberRoleBindings rejects membership_id with surrounding whitespace as invalid payload', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await assert.rejects(
    () =>
      service.replaceTenantMemberRoleBindings({
        requestId: 'req-tenant-role-binding-write-invalid-membership-id',
        tenantId: 'tenant-role-binding',
        membershipId: ' membership-role-binding-1',
        roleIds: ['tenant_role_binding_a'],
        operatorUserId: 'tenant-role-binding-user',
        operatorSessionId: 'tenant-role-binding-session'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );
});

test('listTenantMemberRoleBindings normalizes uppercase membership_id to lowercase', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  const result = await service.listTenantMemberRoleBindings({
    tenantId: 'tenant-role-binding',
    membershipId: 'MEMBERSHIP-ROLE-BINDING-1'
  });

  assert.equal(result.membership_id, 'membership-role-binding-1');
  assert.deepEqual(result.role_ids, []);
});

test('replaceTenantMemberRoleBindings normalizes uppercase membership_id to lowercase', async () => {
  const service = createAuthService({
    seedUsers: [buildTenantRoleBindingSeed()]
  });

  await service.createPlatformRoleCatalogEntry({
    roleId: 'tenant_role_binding_uppercase_membership',
    code: 'TENANT_ROLE_BINDING_UPPERCASE_MEMBERSHIP',
    name: 'Tenant Role Binding Uppercase Membership',
    scope: 'tenant',
    tenantId: 'tenant-role-binding',
    isSystem: false
  });

  const result = await service.replaceTenantMemberRoleBindings({
    requestId: 'req-tenant-role-binding-uppercase-membership-id',
    tenantId: 'tenant-role-binding',
    membershipId: 'MEMBERSHIP-ROLE-BINDING-1',
    roleIds: ['tenant_role_binding_uppercase_membership'],
    operatorUserId: 'tenant-role-binding-user',
    operatorSessionId: 'tenant-role-binding-session'
  });

  assert.equal(result.membership_id, 'membership-role-binding-1');
  assert.deepEqual(result.role_ids, ['tenant_role_binding_uppercase_membership']);
});

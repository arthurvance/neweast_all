const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const { createAuthService, AuthProblemError } = require('../src/modules/auth/auth.service');
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
const noOpOtpStore = {
  upsertOtp: async () => ({ sent_at_ms: Date.now() }),
  getSentAt: async () => null,
  verifyAndConsumeOtp: async () => ({ ok: false, reason: 'missing' })
};
const passRateLimitStore = {
  consume: async () => ({ allowed: true, count: 1, remainingSeconds: 60 })
};

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

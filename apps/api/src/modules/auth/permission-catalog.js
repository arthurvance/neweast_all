const AUTH_SESSION_LOGOUT_PERMISSION_CODE = 'auth.session.logout';
const AUTH_SESSION_CHANGE_PASSWORD_PERMISSION_CODE = 'auth.session.change_password';

const TENANT_CONTEXT_READ_PERMISSION_CODE = 'tenant.context.read';
const TENANT_CONTEXT_SWITCH_PERMISSION_CODE = 'tenant.context.switch';
const TENANT_MEMBER_ADMIN_VIEW_PERMISSION_CODE = 'tenant.member_admin.view';
const TENANT_MEMBER_ADMIN_OPERATE_PERMISSION_CODE = 'tenant.member_admin.operate';
const TENANT_BILLING_VIEW_PERMISSION_CODE = 'tenant.billing.view';
const TENANT_BILLING_OPERATE_PERMISSION_CODE = 'tenant.billing.operate';

const PLATFORM_MEMBER_ADMIN_VIEW_PERMISSION_CODE = 'platform.member_admin.view';
const PLATFORM_MEMBER_ADMIN_OPERATE_PERMISSION_CODE = 'platform.member_admin.operate';
const PLATFORM_BILLING_VIEW_PERMISSION_CODE = 'platform.billing.view';
const PLATFORM_BILLING_OPERATE_PERMISSION_CODE = 'platform.billing.operate';
const PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE = 'platform.system_config.view';
const PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE = 'platform.system_config.operate';

const PERMISSION_SCOPE_SESSION = 'session';
const PERMISSION_SCOPE_PLATFORM = 'platform';
const PERMISSION_SCOPE_TENANT = 'tenant';

const KNOWN_PLATFORM_PERMISSION_CODES = Object.freeze([
  PLATFORM_MEMBER_ADMIN_VIEW_PERMISSION_CODE,
  PLATFORM_MEMBER_ADMIN_OPERATE_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE,
  PLATFORM_BILLING_VIEW_PERMISSION_CODE,
  PLATFORM_BILLING_OPERATE_PERMISSION_CODE
]);

const KNOWN_TENANT_PERMISSION_CODES = Object.freeze([
  TENANT_MEMBER_ADMIN_VIEW_PERMISSION_CODE,
  TENANT_MEMBER_ADMIN_OPERATE_PERMISSION_CODE,
  TENANT_BILLING_VIEW_PERMISSION_CODE,
  TENANT_BILLING_OPERATE_PERMISSION_CODE
]);

const TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT = new Set([
  TENANT_CONTEXT_READ_PERMISSION_CODE,
  TENANT_CONTEXT_SWITCH_PERMISSION_CODE
]);

const toPermissionCodeKey = (permissionCode) =>
  String(permissionCode || '').trim().toLowerCase();

const SYSTEM_CONFIG_PERMISSION_CODE_KEY_SET = new Set([
  PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE
].map((permissionCode) => toPermissionCodeKey(permissionCode)));

const buildContextEvaluator = ({
  contextKey,
  requiredFlags = []
}) => {
  const normalizedContextKey = String(contextKey || '').trim().toLowerCase();
  if (normalizedContextKey === 'always') {
    return () => true;
  }
  const normalizedRequiredFlags = (Array.isArray(requiredFlags) ? requiredFlags : [])
    .map((flagKey) => String(flagKey || '').trim())
    .filter((flagKey) => flagKey.length > 0);

  return ({
    platformPermissionContext = null,
    tenantPermissionContext = null
  } = {}) => {
    const permissionContext = normalizedContextKey === 'platform'
      ? platformPermissionContext
      : tenantPermissionContext;
    return normalizedRequiredFlags.every((flagKey) =>
      Boolean(permissionContext?.[flagKey])
    );
  };
};

const ROUTE_PERMISSION_DEFINITIONS = Object.freeze([
  Object.freeze({
    code: TENANT_CONTEXT_READ_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_TENANT]),
    evaluate: buildContextEvaluator({ contextKey: 'always' })
  }),
  Object.freeze({
    code: TENANT_CONTEXT_SWITCH_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_TENANT]),
    evaluate: buildContextEvaluator({ contextKey: 'always' })
  }),
  Object.freeze({
    code: AUTH_SESSION_LOGOUT_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_SESSION]),
    evaluate: buildContextEvaluator({ contextKey: 'always' })
  }),
  Object.freeze({
    code: AUTH_SESSION_CHANGE_PASSWORD_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_SESSION]),
    evaluate: buildContextEvaluator({ contextKey: 'always' })
  }),
  Object.freeze({
    code: PLATFORM_MEMBER_ADMIN_VIEW_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_PLATFORM]),
    evaluate: buildContextEvaluator({
      contextKey: 'platform',
      requiredFlags: ['can_view_member_admin']
    })
  }),
  Object.freeze({
    code: PLATFORM_MEMBER_ADMIN_OPERATE_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_PLATFORM]),
    evaluate: buildContextEvaluator({
      contextKey: 'platform',
      requiredFlags: ['can_view_member_admin', 'can_operate_member_admin']
    })
  }),
  Object.freeze({
    code: PLATFORM_BILLING_VIEW_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_PLATFORM]),
    evaluate: buildContextEvaluator({
      contextKey: 'platform',
      requiredFlags: ['can_view_billing']
    })
  }),
  Object.freeze({
    code: PLATFORM_BILLING_OPERATE_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_PLATFORM]),
    evaluate: buildContextEvaluator({
      contextKey: 'platform',
      requiredFlags: ['can_view_billing', 'can_operate_billing']
    })
  }),
  Object.freeze({
    code: PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_PLATFORM]),
    evaluate: buildContextEvaluator({
      contextKey: 'platform',
      requiredFlags: ['can_view_system_config']
    })
  }),
  Object.freeze({
    code: PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_PLATFORM]),
    evaluate: buildContextEvaluator({
      contextKey: 'platform',
      requiredFlags: ['can_view_system_config', 'can_operate_system_config']
    })
  }),
  Object.freeze({
    code: TENANT_MEMBER_ADMIN_VIEW_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_TENANT]),
    evaluate: buildContextEvaluator({
      contextKey: 'tenant',
      requiredFlags: ['can_view_member_admin']
    })
  }),
  Object.freeze({
    code: TENANT_MEMBER_ADMIN_OPERATE_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_TENANT]),
    evaluate: buildContextEvaluator({
      contextKey: 'tenant',
      requiredFlags: ['can_view_member_admin', 'can_operate_member_admin']
    })
  }),
  Object.freeze({
    code: TENANT_BILLING_VIEW_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_TENANT]),
    evaluate: buildContextEvaluator({
      contextKey: 'tenant',
      requiredFlags: ['can_view_billing']
    })
  }),
  Object.freeze({
    code: TENANT_BILLING_OPERATE_PERMISSION_CODE,
    scopes: Object.freeze([PERMISSION_SCOPE_TENANT]),
    evaluate: buildContextEvaluator({
      contextKey: 'tenant',
      requiredFlags: ['can_view_billing', 'can_operate_billing']
    })
  })
]);

const ROUTE_PERMISSION_EVALUATORS = Object.freeze(
  Object.fromEntries(
    ROUTE_PERMISSION_DEFINITIONS.map((definition) => [
      definition.code,
      definition.evaluate
    ])
  )
);

const ROUTE_PERMISSION_SCOPE_RULES = Object.freeze(
  Object.fromEntries(
    ROUTE_PERMISSION_DEFINITIONS.map((definition) => [
      definition.code,
      Object.freeze([...(definition.scopes || [])])
    ])
  )
);

const normalizeDistinctPermissionCodeKeys = (permissionCodes = []) =>
  [...new Set(
    (Array.isArray(permissionCodes) ? permissionCodes : [])
      .map((permissionCode) => toPermissionCodeKey(permissionCode))
      .filter((permissionCode) => permissionCode.length > 0)
  )];

const toPlatformPermissionSnapshotFromCodes = (permissionCodes = []) => {
  const snapshot = {
    canViewMemberAdmin: false,
    canOperateMemberAdmin: false,
    canViewBilling: false,
    canOperateBilling: false,
    canViewSystemConfig: false,
    canOperateSystemConfig: false
  };
  for (const permissionCode of normalizeDistinctPermissionCodeKeys(permissionCodes)) {
    switch (permissionCode) {
      case PLATFORM_MEMBER_ADMIN_VIEW_PERMISSION_CODE:
        snapshot.canViewMemberAdmin = true;
        break;
      case PLATFORM_MEMBER_ADMIN_OPERATE_PERMISSION_CODE:
        snapshot.canViewMemberAdmin = true;
        snapshot.canOperateMemberAdmin = true;
        break;
      case PLATFORM_BILLING_VIEW_PERMISSION_CODE:
        snapshot.canViewBilling = true;
        break;
      case PLATFORM_BILLING_OPERATE_PERMISSION_CODE:
        snapshot.canViewBilling = true;
        snapshot.canOperateBilling = true;
        break;
      case PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE:
        snapshot.canViewSystemConfig = true;
        break;
      case PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE:
        snapshot.canViewSystemConfig = true;
        snapshot.canOperateSystemConfig = true;
        break;
      default:
        break;
    }
  }
  return snapshot;
};

const toTenantPermissionSnapshotFromCodes = (permissionCodes = []) => {
  const snapshot = {
    canViewMemberAdmin: false,
    canOperateMemberAdmin: false,
    canViewBilling: false,
    canOperateBilling: false
  };
  for (const permissionCode of normalizeDistinctPermissionCodeKeys(permissionCodes)) {
    switch (permissionCode) {
      case TENANT_MEMBER_ADMIN_VIEW_PERMISSION_CODE:
        snapshot.canViewMemberAdmin = true;
        break;
      case TENANT_MEMBER_ADMIN_OPERATE_PERMISSION_CODE:
        snapshot.canViewMemberAdmin = true;
        snapshot.canOperateMemberAdmin = true;
        break;
      case TENANT_BILLING_VIEW_PERMISSION_CODE:
        snapshot.canViewBilling = true;
        break;
      case TENANT_BILLING_OPERATE_PERMISSION_CODE:
        snapshot.canViewBilling = true;
        snapshot.canOperateBilling = true;
        break;
      default:
        break;
    }
  }
  return snapshot;
};

const listSupportedRoutePermissionCodes = () =>
  ROUTE_PERMISSION_DEFINITIONS.map((definition) => definition.code);

const listSupportedRoutePermissionScopes = () =>
  Object.fromEntries(
    Object.entries(ROUTE_PERMISSION_SCOPE_RULES).map(([permissionCode, scopes]) => [
      permissionCode,
      [...scopes]
    ])
  );

const listSupportedPlatformPermissionCodes = () =>
  listSupportedRoutePermissionCodes()
    .filter((permissionCode) =>
      permissionCode.startsWith('platform.')
      && (ROUTE_PERMISSION_SCOPE_RULES[permissionCode] || []).includes(PERMISSION_SCOPE_PLATFORM)
    )
    .sort((left, right) => left.localeCompare(right));

const listSupportedTenantPermissionCodes = ({
  includeTenantContextCodes = false
} = {}) =>
  listSupportedRoutePermissionCodes()
    .filter((permissionCode) =>
      permissionCode.startsWith('tenant.')
      && (ROUTE_PERMISSION_SCOPE_RULES[permissionCode] || []).includes(PERMISSION_SCOPE_TENANT)
      && (
        includeTenantContextCodes
        || !TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT.has(permissionCode)
      )
    )
    .sort((left, right) => left.localeCompare(right));

module.exports = {
  AUTH_SESSION_LOGOUT_PERMISSION_CODE,
  AUTH_SESSION_CHANGE_PASSWORD_PERMISSION_CODE,
  TENANT_CONTEXT_READ_PERMISSION_CODE,
  TENANT_CONTEXT_SWITCH_PERMISSION_CODE,
  TENANT_MEMBER_ADMIN_VIEW_PERMISSION_CODE,
  TENANT_MEMBER_ADMIN_OPERATE_PERMISSION_CODE,
  TENANT_BILLING_VIEW_PERMISSION_CODE,
  TENANT_BILLING_OPERATE_PERMISSION_CODE,
  PLATFORM_MEMBER_ADMIN_VIEW_PERMISSION_CODE,
  PLATFORM_MEMBER_ADMIN_OPERATE_PERMISSION_CODE,
  PLATFORM_BILLING_VIEW_PERMISSION_CODE,
  PLATFORM_BILLING_OPERATE_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE,
  KNOWN_PLATFORM_PERMISSION_CODES,
  KNOWN_TENANT_PERMISSION_CODES,
  TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT,
  SYSTEM_CONFIG_PERMISSION_CODE_KEY_SET,
  ROUTE_PERMISSION_EVALUATORS,
  ROUTE_PERMISSION_SCOPE_RULES,
  listSupportedRoutePermissionCodes,
  listSupportedRoutePermissionScopes,
  listSupportedPlatformPermissionCodes,
  listSupportedTenantPermissionCodes,
  toPlatformPermissionSnapshotFromCodes,
  toTenantPermissionSnapshotFromCodes
};

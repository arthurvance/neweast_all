const AUTH_SESSION_LOGOUT_PERMISSION_CODE = 'auth.session.logout';
const AUTH_SESSION_CHANGE_PASSWORD_PERMISSION_CODE = 'auth.session.change_password';

const TENANT_CONTEXT_READ_PERMISSION_CODE = 'tenant.context.read';
const TENANT_CONTEXT_SWITCH_PERMISSION_CODE = 'tenant.context.switch';
const TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE = 'tenant.user_management.view';
const TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE = 'tenant.user_management.operate';
const TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE = 'tenant.role_management.view';
const TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE = 'tenant.role_management.operate';

const PLATFORM_USER_MANAGEMENT_VIEW_PERMISSION_CODE = 'platform.user_management.view';
const PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE = 'platform.user_management.operate';
const PLATFORM_TENANT_MANAGEMENT_VIEW_PERMISSION_CODE = 'platform.tenant_management.view';
const PLATFORM_TENANT_MANAGEMENT_OPERATE_PERMISSION_CODE = 'platform.tenant_management.operate';
const PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE = 'platform.role_management.view';
const PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE = 'platform.role_management.operate';

const PERMISSION_SCOPE_SESSION = 'session';
const PERMISSION_SCOPE_PLATFORM = 'platform';
const PERMISSION_SCOPE_TENANT = 'tenant';

const TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT = new Set([
  TENANT_CONTEXT_READ_PERMISSION_CODE,
  TENANT_CONTEXT_SWITCH_PERMISSION_CODE
]);

const toPermissionCodeKey = (permissionCode) =>
  String(permissionCode || '').trim().toLowerCase();

const ROLE_MANAGEMENT_PERMISSION_CODE_KEY_SET = new Set([
  PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
].map((permissionCode) => toPermissionCodeKey(permissionCode)));

const readBooleanPermissionField = (permissionContext, fieldKey) =>
  Boolean(permissionContext?.[fieldKey]);

const readPermissionCodeSet = (permissionContext) => {
  const permissionCodeSet = permissionContext?.permission_code_set
    ?? permissionContext?.permissionCodeSet;
  if (permissionCodeSet instanceof Set) {
    return permissionCodeSet;
  }
  if (Array.isArray(permissionCodeSet)) {
    return new Set(permissionCodeSet.map((permissionCode) => toPermissionCodeKey(permissionCode)));
  }
  return null;
};

const hasPermissionCodeGrant = ({ permissionContext = null, permissionCode }) => {
  const normalizedPermissionCode = toPermissionCodeKey(permissionCode);
  if (!normalizedPermissionCode) {
    return false;
  }

  const permissionCodeSet = readPermissionCodeSet(permissionContext);
  if (permissionCodeSet && permissionCodeSet.has(normalizedPermissionCode)) {
    return true;
  }

  switch (normalizedPermissionCode) {
    case PLATFORM_USER_MANAGEMENT_VIEW_PERMISSION_CODE:
      return readBooleanPermissionField(permissionContext, 'can_view_user_management')
        || readBooleanPermissionField(permissionContext, 'canViewUserManagement')
        || readBooleanPermissionField(permissionContext, 'can_operate_user_management')
        || readBooleanPermissionField(permissionContext, 'canOperateUserManagement');
    case PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE:
      return readBooleanPermissionField(permissionContext, 'can_operate_user_management')
        || readBooleanPermissionField(permissionContext, 'canOperateUserManagement');
    case PLATFORM_TENANT_MANAGEMENT_VIEW_PERMISSION_CODE:
      return readBooleanPermissionField(permissionContext, 'can_view_tenant_management')
        || readBooleanPermissionField(permissionContext, 'canViewTenantManagement')
        || readBooleanPermissionField(permissionContext, 'can_operate_tenant_management')
        || readBooleanPermissionField(permissionContext, 'canOperateTenantManagement');
    case PLATFORM_TENANT_MANAGEMENT_OPERATE_PERMISSION_CODE:
      return readBooleanPermissionField(permissionContext, 'can_operate_tenant_management')
        || readBooleanPermissionField(permissionContext, 'canOperateTenantManagement');
    case PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE:
      return readBooleanPermissionField(permissionContext, 'can_view_role_management')
        || readBooleanPermissionField(permissionContext, 'canViewRoleManagement')
        || readBooleanPermissionField(permissionContext, 'can_operate_role_management')
        || readBooleanPermissionField(permissionContext, 'canOperateRoleManagement');
    case PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE:
      return readBooleanPermissionField(permissionContext, 'can_operate_role_management')
        || readBooleanPermissionField(permissionContext, 'canOperateRoleManagement');
    case TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE:
      return readBooleanPermissionField(permissionContext, 'can_view_user_management')
        || readBooleanPermissionField(permissionContext, 'canViewUserManagement')
        || readBooleanPermissionField(permissionContext, 'can_operate_user_management')
        || readBooleanPermissionField(permissionContext, 'canOperateUserManagement');
    case TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE:
      return readBooleanPermissionField(permissionContext, 'can_operate_user_management')
        || readBooleanPermissionField(permissionContext, 'canOperateUserManagement');
    case TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE:
      return readBooleanPermissionField(permissionContext, 'can_view_role_management')
        || readBooleanPermissionField(permissionContext, 'canViewRoleManagement')
        || readBooleanPermissionField(permissionContext, 'can_operate_role_management')
        || readBooleanPermissionField(permissionContext, 'canOperateRoleManagement');
    case TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE:
      return readBooleanPermissionField(permissionContext, 'can_operate_role_management')
        || readBooleanPermissionField(permissionContext, 'canOperateRoleManagement');
    default:
      return false;
  }
};

const buildContextEvaluator = ({
  contextKey,
  permissionCode = null,
  requiredFlags = []
}) => {
  const normalizedContextKey = String(contextKey || '').trim().toLowerCase();
  if (normalizedContextKey === 'always') {
    return () => true;
  }
  const normalizedPermissionCode = toPermissionCodeKey(permissionCode);
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

    if (
      normalizedPermissionCode
      && hasPermissionCodeGrant({
        permissionContext,
        permissionCode: normalizedPermissionCode
      })
    ) {
      return true;
    }

    if (normalizedRequiredFlags.length === 0) {
      return false;
    }

    return normalizedRequiredFlags.every((flagKey) =>
      Boolean(permissionContext?.[flagKey])
    );
  };
};

const normalizeCatalogScope = (scopes = []) => {
  const normalizedScopes = (Array.isArray(scopes) ? scopes : [])
    .map((scope) => String(scope || '').trim().toLowerCase())
    .filter((scope) => scope.length > 0);
  if (normalizedScopes.includes(PERMISSION_SCOPE_PLATFORM)) {
    return PERMISSION_SCOPE_PLATFORM;
  }
  if (normalizedScopes.includes(PERMISSION_SCOPE_TENANT)) {
    return PERMISSION_SCOPE_TENANT;
  }
  if (normalizedScopes.includes(PERMISSION_SCOPE_SESSION)) {
    return PERMISSION_SCOPE_SESSION;
  }
  return normalizedScopes[0] || '';
};

const createPermissionDefinition = ({
  code,
  scopes,
  contextKey = 'always',
  requiredFlags = [],
  assignable = true,
  groupKey = '',
  actionKey = '',
  labelKey = '',
  order = 0
}) => {
  const normalizedCode = toPermissionCodeKey(code);
  return Object.freeze({
    code: normalizedCode,
    scopes: Object.freeze(
      (Array.isArray(scopes) ? scopes : [])
        .map((scope) => String(scope || '').trim().toLowerCase())
        .filter((scope) => scope.length > 0)
    ),
    scope: normalizeCatalogScope(scopes),
    assignable: Boolean(assignable),
    group_key: String(groupKey || '').trim(),
    action_key: String(actionKey || '').trim(),
    label_key: String(labelKey || '').trim(),
    order: Number.isFinite(order) ? Number(order) : 0,
    evaluate: buildContextEvaluator({
      contextKey,
      permissionCode: normalizedCode,
      requiredFlags
    })
  });
};

const ROUTE_PERMISSION_DEFINITIONS = Object.freeze([
  createPermissionDefinition({
    code: TENANT_CONTEXT_READ_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_TENANT],
    contextKey: 'always',
    assignable: false,
    labelKey: 'permission.tenant.context.read',
    order: 10
  }),
  createPermissionDefinition({
    code: TENANT_CONTEXT_SWITCH_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_TENANT],
    contextKey: 'always',
    assignable: false,
    labelKey: 'permission.tenant.context.switch',
    order: 20
  }),
  createPermissionDefinition({
    code: AUTH_SESSION_LOGOUT_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_SESSION],
    contextKey: 'always',
    assignable: false,
    labelKey: 'permission.auth.session.logout',
    order: 10
  }),
  createPermissionDefinition({
    code: AUTH_SESSION_CHANGE_PASSWORD_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_SESSION],
    contextKey: 'always',
    assignable: false,
    labelKey: 'permission.auth.session.change_password',
    order: 20
  }),
  createPermissionDefinition({
    code: PLATFORM_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_PLATFORM],
    contextKey: 'platform',
    groupKey: 'user_management',
    actionKey: 'view',
    labelKey: 'permission.platform.user_management.view',
    order: 110
  }),
  createPermissionDefinition({
    code: PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_PLATFORM],
    contextKey: 'platform',
    groupKey: 'user_management',
    actionKey: 'operate',
    labelKey: 'permission.platform.user_management.operate',
    order: 120
  }),
  createPermissionDefinition({
    code: PLATFORM_TENANT_MANAGEMENT_VIEW_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_PLATFORM],
    contextKey: 'platform',
    groupKey: 'tenant_management',
    actionKey: 'view',
    labelKey: 'permission.platform.tenant_management.view',
    order: 210
  }),
  createPermissionDefinition({
    code: PLATFORM_TENANT_MANAGEMENT_OPERATE_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_PLATFORM],
    contextKey: 'platform',
    groupKey: 'tenant_management',
    actionKey: 'operate',
    labelKey: 'permission.platform.tenant_management.operate',
    order: 220
  }),
  createPermissionDefinition({
    code: PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_PLATFORM],
    contextKey: 'platform',
    groupKey: 'role_management',
    actionKey: 'view',
    labelKey: 'permission.platform.role_management.view',
    order: 310
  }),
  createPermissionDefinition({
    code: PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_PLATFORM],
    contextKey: 'platform',
    groupKey: 'role_management',
    actionKey: 'operate',
    labelKey: 'permission.platform.role_management.operate',
    order: 320
  }),
  createPermissionDefinition({
    code: TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_TENANT],
    contextKey: 'tenant',
    groupKey: 'user_management',
    actionKey: 'view',
    labelKey: 'permission.tenant.user_management.view',
    order: 110
  }),
  createPermissionDefinition({
    code: TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_TENANT],
    contextKey: 'tenant',
    groupKey: 'user_management',
    actionKey: 'operate',
    labelKey: 'permission.tenant.user_management.operate',
    order: 120
  }),
  createPermissionDefinition({
    code: TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_TENANT],
    contextKey: 'tenant',
    groupKey: 'role_management',
    actionKey: 'view',
    labelKey: 'permission.tenant.role_management.view',
    order: 210
  }),
  createPermissionDefinition({
    code: TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
    scopes: [PERMISSION_SCOPE_TENANT],
    contextKey: 'tenant',
    groupKey: 'role_management',
    actionKey: 'operate',
    labelKey: 'permission.tenant.role_management.operate',
    order: 220
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
    canViewUserManagement: false,
    canOperateUserManagement: false,
    canViewTenantManagement: false,
    canOperateTenantManagement: false,
    canViewRoleManagement: false,
    canOperateRoleManagement: false
  };
  for (const permissionCode of normalizeDistinctPermissionCodeKeys(permissionCodes)) {
    switch (permissionCode) {
      case PLATFORM_USER_MANAGEMENT_VIEW_PERMISSION_CODE:
        snapshot.canViewUserManagement = true;
        break;
      case PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE:
        snapshot.canViewUserManagement = true;
        snapshot.canOperateUserManagement = true;
        break;
      case PLATFORM_TENANT_MANAGEMENT_VIEW_PERMISSION_CODE:
        snapshot.canViewTenantManagement = true;
        break;
      case PLATFORM_TENANT_MANAGEMENT_OPERATE_PERMISSION_CODE:
        snapshot.canViewTenantManagement = true;
        snapshot.canOperateTenantManagement = true;
        break;
      case PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE:
        snapshot.canViewRoleManagement = true;
        break;
      case PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE:
        snapshot.canViewRoleManagement = true;
        snapshot.canOperateRoleManagement = true;
        break;
      default:
        break;
    }
  }
  return snapshot;
};

const toTenantPermissionSnapshotFromCodes = (permissionCodes = []) => {
  const snapshot = {
    canViewUserManagement: false,
    canOperateUserManagement: false,
    canViewRoleManagement: false,
    canOperateRoleManagement: false
  };
  for (const permissionCode of normalizeDistinctPermissionCodeKeys(permissionCodes)) {
    switch (permissionCode) {
      case TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE:
        snapshot.canViewUserManagement = true;
        break;
      case TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE:
        snapshot.canViewUserManagement = true;
        snapshot.canOperateUserManagement = true;
        break;
      case TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE:
        snapshot.canViewRoleManagement = true;
        break;
      case TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE:
        snapshot.canViewRoleManagement = true;
        snapshot.canOperateRoleManagement = true;
        break;
      default:
        break;
    }
  }
  return snapshot;
};

const toCatalogItem = (definition) =>
  Object.freeze({
    code: definition.code,
    scope: definition.scope,
    group_key: definition.group_key,
    action_key: definition.action_key,
    label_key: definition.label_key,
    order: definition.order,
    assignable: Boolean(definition.assignable)
  });

const sortCatalogItems = (items = []) =>
  [...items].sort((left, right) => {
    const leftOrder = Number.isFinite(left?.order) ? Number(left.order) : 0;
    const rightOrder = Number.isFinite(right?.order) ? Number(right.order) : 0;
    if (leftOrder !== rightOrder) {
      return leftOrder - rightOrder;
    }
    return String(left?.code || '').localeCompare(String(right?.code || ''));
  });

const listRoutePermissionCatalogItems = () =>
  sortCatalogItems(ROUTE_PERMISSION_DEFINITIONS.map((definition) => toCatalogItem(definition)));

const listPlatformPermissionCatalogItems = ({
  includeUnassignable = false
} = {}) =>
  sortCatalogItems(
    ROUTE_PERMISSION_DEFINITIONS
      .filter((definition) =>
        definition.scope === PERMISSION_SCOPE_PLATFORM
        && (includeUnassignable || definition.assignable)
      )
      .map((definition) => toCatalogItem(definition))
  );

const listTenantPermissionCatalogItems = ({
  includeTenantContextCodes = false,
  includeUnassignable = false
} = {}) =>
  sortCatalogItems(
    ROUTE_PERMISSION_DEFINITIONS
      .filter((definition) => {
        if (definition.scope !== PERMISSION_SCOPE_TENANT) {
          return false;
        }
        if (!includeUnassignable && !definition.assignable) {
          return false;
        }
        if (
          !includeTenantContextCodes
          && TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT.has(definition.code)
        ) {
          return false;
        }
        return true;
      })
      .map((definition) => toCatalogItem(definition))
  );

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
  listPlatformPermissionCatalogItems()
    .map((item) => item.code)
    .sort((left, right) => left.localeCompare(right));

const listSupportedTenantPermissionCodes = ({
  includeTenantContextCodes = false
} = {}) =>
  listTenantPermissionCatalogItems({ includeTenantContextCodes })
    .map((item) => item.code)
    .sort((left, right) => left.localeCompare(right));

const KNOWN_PLATFORM_PERMISSION_CODES = Object.freeze(
  listSupportedPlatformPermissionCodes()
);

const KNOWN_TENANT_PERMISSION_CODES = Object.freeze(
  listSupportedTenantPermissionCodes()
);

module.exports = {
  AUTH_SESSION_LOGOUT_PERMISSION_CODE,
  AUTH_SESSION_CHANGE_PASSWORD_PERMISSION_CODE,
  TENANT_CONTEXT_READ_PERMISSION_CODE,
  TENANT_CONTEXT_SWITCH_PERMISSION_CODE,
  TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
  TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
  PLATFORM_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
  PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
  PLATFORM_TENANT_MANAGEMENT_VIEW_PERMISSION_CODE,
  PLATFORM_TENANT_MANAGEMENT_OPERATE_PERMISSION_CODE,
  PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
  KNOWN_PLATFORM_PERMISSION_CODES,
  KNOWN_TENANT_PERMISSION_CODES,
  TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT,
  ROLE_MANAGEMENT_PERMISSION_CODE_KEY_SET,
  ROUTE_PERMISSION_EVALUATORS,
  ROUTE_PERMISSION_SCOPE_RULES,
  listRoutePermissionCatalogItems,
  listPlatformPermissionCatalogItems,
  listTenantPermissionCatalogItems,
  listSupportedRoutePermissionCodes,
  listSupportedRoutePermissionScopes,
  listSupportedPlatformPermissionCodes,
  listSupportedTenantPermissionCodes,
  toPlatformPermissionSnapshotFromCodes,
  toTenantPermissionSnapshotFromCodes
};

const { log } = require('../../common/logger');
const { AuthProblemError } = require('../auth/auth.service');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  TENANT_ROLE_VIEW_PERMISSION_CODE,
  TENANT_ROLE_OPERATE_PERMISSION_CODE,
  TENANT_ROLE_SCOPE,
  PROTECTED_TENANT_ROLE_IDS
} = require('./role.constants');

const MYSQL_DUP_ENTRY_ERRNO = 1062;
const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const MAX_ROLE_ID_LENGTH = 64;
const MAX_ROLE_CODE_LENGTH = 64;
const MAX_ROLE_NAME_LENGTH = 128;
const MAX_TENANT_ID_LENGTH = 64;
const ROLE_ID_ADDRESSABLE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const TENANT_ID_WHITESPACE_PATTERN = /\s/;
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const VALID_ROLE_STATUS = new Set(['active', 'disabled']);
const CREATE_ROLE_ALLOWED_FIELDS = new Set([
  'role_id',
  'code',
  'name',
  'status'
]);
const UPDATE_ROLE_ALLOWED_FIELDS = new Set([
  'code',
  'name',
  'status'
]);
const PROTECTED_ROLE_ID_SET = new Set(
  PROTECTED_TENANT_ROLE_IDS.map((roleId) => String(roleId || '').trim().toLowerCase())
);

const isPlainObject = (candidate) =>
  candidate !== null
  && typeof candidate === 'object'
  && !Array.isArray(candidate);

const normalizeRequiredString = (candidate) => {
  if (typeof candidate !== 'string') {
    return '';
  }
  return candidate.trim();
};

const normalizeRoleStatusInput = (status) =>
  String(status || '').trim().toLowerCase();
const normalizeRoleScopeInput = (scope) =>
  String(scope || '').trim().toLowerCase();

const normalizeRoleStatusOutput = (status) => {
  const normalized = normalizeRoleStatusInput(status);
  if (normalized === 'enabled') {
    return 'active';
  }
  return normalized;
};

const isValidActiveTenantId = (tenantId) => {
  const normalizedTenantId = normalizeRequiredString(tenantId);
  return normalizedTenantId.length > 0
    && normalizedTenantId.length <= MAX_TENANT_ID_LENGTH
    && !CONTROL_CHAR_PATTERN.test(normalizedTenantId)
    && !TENANT_ID_WHITESPACE_PATTERN.test(normalizedTenantId);
};

const normalizeRoleId = (roleId) => normalizeRequiredString(roleId).toLowerCase();
const normalizeRoleIdKey = (roleId) => normalizeRoleId(roleId).toLowerCase();
const assertAddressableRoleId = (roleId) => {
  if (!ROLE_ID_ADDRESSABLE_PATTERN.test(roleId)) {
    throw tenantRoleErrors.invalidPayload(
      'role_id 仅允许字母、数字、点、下划线和中划线，且必须以字母或数字开头'
    );
  }
};

const isProtectedRoleId = (roleId) =>
  PROTECTED_ROLE_ID_SET.has(normalizeRoleIdKey(roleId));

const isDuplicateEntryError = (error) =>
  String(error?.code || '').trim().toUpperCase() === 'ER_DUP_ENTRY'
  || Number(error?.errno || 0) === MYSQL_DUP_ENTRY_ERRNO;

const resolveDuplicateRoleConflictTarget = (error) => {
  const explicitTarget = String(
    error?.platformRoleCatalogConflictTarget
    || error?.conflictTarget
    || ''
  ).trim().toLowerCase();
  if (explicitTarget === 'role_id' || explicitTarget === 'code') {
    return explicitTarget;
  }

  const errorMessage = String(
    error?.sqlMessage || error?.message || ''
  ).trim().toLowerCase();
  if (
    errorMessage.includes('uk_platform_role_catalog_scope_tenant_code_normalized')
    || errorMessage.includes('uk_platform_role_catalog_code_normalized')
    || errorMessage.includes('code_normalized')
  ) {
    return 'code';
  }
  if (errorMessage.includes('primary') || errorMessage.includes('role_id')) {
    return 'role_id';
  }
  return 'code';
};

const isResolvedOperatorIdentifier = (value) => {
  const normalized = String(value || '').trim();
  return normalized.length > 0 && normalized.toLowerCase() !== 'unknown';
};

const toIsoTimestamp = (value) => {
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (value === null || value === undefined) {
    return '';
  }
  const asDate = new Date(value);
  if (!Number.isNaN(asDate.getTime())) {
    return asDate.toISOString();
  }
  return '';
};

const tenantRoleProblem = ({ status, title, detail, errorCode, extensions = {} }) =>
  new AuthProblemError({
    status,
    title,
    detail,
    errorCode,
    extensions
  });

const tenantRoleErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    tenantRoleProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'TROLE-400-INVALID-PAYLOAD'
    }),

  forbidden: () =>
    tenantRoleProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  noDomainAccess: () =>
    tenantRoleProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前入口无可用访问域权限',
      errorCode: 'AUTH-403-NO-DOMAIN'
    }),

  protectedRoleMutationDenied: () =>
    tenantRoleProblem({
      status: 403,
      title: 'Forbidden',
      detail: '受保护系统角色定义不允许创建、编辑或删除',
      errorCode: 'TROLE-403-SYSTEM-ROLE-PROTECTED',
      extensions: {
        retryable: false
      }
    }),

  roleNotFound: () =>
    tenantRoleProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标组织角色不存在',
      errorCode: 'TROLE-404-ROLE-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  roleCodeConflict: () =>
    tenantRoleProblem({
      status: 409,
      title: 'Conflict',
      detail: '角色编码冲突，请使用其他 code',
      errorCode: 'TROLE-409-CODE-CONFLICT',
      extensions: {
        retryable: false
      }
    }),

  roleIdConflict: () =>
    tenantRoleProblem({
      status: 409,
      title: 'Conflict',
      detail: '角色标识冲突，请使用其他 role_id',
      errorCode: 'TROLE-409-ROLE-ID-CONFLICT',
      extensions: {
        retryable: false
      }
    }),

  deleteConditionNotMet: (detail = '角色删除条件不满足') =>
    tenantRoleProblem({
      status: 409,
      title: 'Conflict',
      detail,
      errorCode: 'TROLE-409-DELETE-CONDITION-NOT-MET',
      extensions: {
        retryable: false
      }
    }),

  dependencyUnavailable: () =>
    tenantRoleProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '组织角色治理依赖暂不可用，请稍后重试',
      errorCode: 'TROLE-503-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true
      }
    })
};

const mapOperatorContextError = (error) =>
  error instanceof AuthProblemError ? error : tenantRoleErrors.dependencyUnavailable();

const resolveActiveTenantIdFromAuthorizationContext = (authorizationContext = null) =>
  normalizeRequiredString(
    authorizationContext?.active_tenant_id
      || authorizationContext?.activeTenantId
      || authorizationContext?.session_context?.active_tenant_id
      || authorizationContext?.session_context?.activeTenantId
      || authorizationContext?.session?.sessionContext?.active_tenant_id
      || authorizationContext?.session?.sessionContext?.activeTenantId
      || authorizationContext?.session?.session_context?.active_tenant_id
      || authorizationContext?.session?.session_context?.activeTenantId
  );

const resolveAuthorizedOperatorContext = ({
  authorizationContext = null,
  expectedPermissionCode = TENANT_ROLE_OPERATE_PERMISSION_CODE
}) => {
  const preauthorizedContext = resolveRoutePreauthorizedContext({
    authorizationContext,
    expectedPermissionCode,
    expectedScope: TENANT_ROLE_SCOPE,
    expectedEntryDomain: TENANT_ROLE_SCOPE
  });
  if (!preauthorizedContext) {
    return null;
  }
  const activeTenantId = resolveActiveTenantIdFromAuthorizationContext(
    authorizationContext
  );
  if (!isValidActiveTenantId(activeTenantId)) {
    throw tenantRoleErrors.noDomainAccess();
  }
  if (
    !isResolvedOperatorIdentifier(preauthorizedContext.userId)
    || !isResolvedOperatorIdentifier(preauthorizedContext.sessionId)
  ) {
    throw tenantRoleErrors.forbidden();
  }
  return {
    operatorUserId: preauthorizedContext.userId,
    operatorSessionId: preauthorizedContext.sessionId,
    activeTenantId
  };
};

const parseCreateRolePayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw tenantRoleErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !CREATE_ROLE_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw tenantRoleErrors.invalidPayload();
  }
  if (
    !Object.prototype.hasOwnProperty.call(payload, 'role_id')
    || !Object.prototype.hasOwnProperty.call(payload, 'code')
    || !Object.prototype.hasOwnProperty.call(payload, 'name')
  ) {
    throw tenantRoleErrors.invalidPayload();
  }

  const roleId = normalizeRoleId(payload.role_id);
  const code = normalizeRequiredString(payload.code);
  const name = normalizeRequiredString(payload.name);
  const status = normalizeRoleStatusInput(
    Object.prototype.hasOwnProperty.call(payload, 'status')
      ? payload.status
      : 'active'
  );

  if (!roleId) {
    throw tenantRoleErrors.invalidPayload('role_id 不能为空');
  }
  if (roleId.length > MAX_ROLE_ID_LENGTH) {
    throw tenantRoleErrors.invalidPayload(`role_id 长度不能超过 ${MAX_ROLE_ID_LENGTH}`);
  }
  assertAddressableRoleId(roleId);
  if (isProtectedRoleId(roleId)) {
    throw tenantRoleErrors.protectedRoleMutationDenied();
  }
  if (!code || code.length > MAX_ROLE_CODE_LENGTH) {
    throw tenantRoleErrors.invalidPayload(`code 长度不能超过 ${MAX_ROLE_CODE_LENGTH}`);
  }
  if (!name || name.length > MAX_ROLE_NAME_LENGTH) {
    throw tenantRoleErrors.invalidPayload(`name 长度不能超过 ${MAX_ROLE_NAME_LENGTH}`);
  }
  if (CONTROL_CHAR_PATTERN.test(roleId) || CONTROL_CHAR_PATTERN.test(code) || CONTROL_CHAR_PATTERN.test(name)) {
    throw tenantRoleErrors.invalidPayload('role_id/code/name 不能包含控制字符');
  }
  if (!VALID_ROLE_STATUS.has(status)) {
    throw tenantRoleErrors.invalidPayload('status 必须为 active 或 disabled');
  }

  return {
    roleId,
    code,
    name,
    status,
    isSystem: false,
    scope: TENANT_ROLE_SCOPE
  };
};

const parseUpdateRolePayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw tenantRoleErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !UPDATE_ROLE_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw tenantRoleErrors.invalidPayload();
  }

  const hasCode = Object.prototype.hasOwnProperty.call(payload, 'code');
  const hasName = Object.prototype.hasOwnProperty.call(payload, 'name');
  const hasStatus = Object.prototype.hasOwnProperty.call(payload, 'status');
  if (!hasCode && !hasName && !hasStatus) {
    throw tenantRoleErrors.invalidPayload('至少提供一个可更新字段');
  }

  const updates = {};
  if (hasCode) {
    const code = normalizeRequiredString(payload.code);
    if (!code || code.length > MAX_ROLE_CODE_LENGTH) {
      throw tenantRoleErrors.invalidPayload(`code 长度不能超过 ${MAX_ROLE_CODE_LENGTH}`);
    }
    if (CONTROL_CHAR_PATTERN.test(code)) {
      throw tenantRoleErrors.invalidPayload('code 不能包含控制字符');
    }
    updates.code = code;
  }
  if (hasName) {
    const name = normalizeRequiredString(payload.name);
    if (!name || name.length > MAX_ROLE_NAME_LENGTH) {
      throw tenantRoleErrors.invalidPayload(`name 长度不能超过 ${MAX_ROLE_NAME_LENGTH}`);
    }
    if (CONTROL_CHAR_PATTERN.test(name)) {
      throw tenantRoleErrors.invalidPayload('name 不能包含控制字符');
    }
    updates.name = name;
  }
  if (hasStatus) {
    const status = normalizeRoleStatusInput(payload.status);
    if (!VALID_ROLE_STATUS.has(status)) {
      throw tenantRoleErrors.invalidPayload('status 必须为 active 或 disabled');
    }
    updates.status = status;
  }

  return updates;
};

const resolveRawRoleIsSystem = (role = {}) => {
  if (role && role.isSystem !== undefined) {
    return role.isSystem;
  }
  if (role && role.is_system !== undefined) {
    return role.is_system;
  }
  return undefined;
};

const mapRoleCatalogEntry = (role, requestId) => ({
  role_id: String(role?.roleId || role?.role_id || '').trim(),
  tenant_id: String(role?.tenantId || role?.tenant_id || '').trim(),
  code: String(role?.code || '').trim(),
  name: String(role?.name || '').trim(),
  status: normalizeRoleStatusOutput(role?.status),
  is_system: resolveRawRoleIsSystem(role),
  created_at: toIsoTimestamp(role?.createdAt ?? role?.created_at),
  updated_at: toIsoTimestamp(role?.updatedAt ?? role?.updated_at),
  request_id: String(requestId || '').trim() || 'request_id_unset'
});

const isValidRoleCatalogEntry = ({
  role = {},
  activeTenantId = '',
  rawRole = null
} = {}) =>
  (() => {
    const createdAtEpoch = new Date(String(role?.created_at || '').trim()).getTime();
    const updatedAtEpoch = new Date(String(role?.updated_at || '').trim()).getTime();
    return Number.isFinite(createdAtEpoch) && Number.isFinite(updatedAtEpoch);
  })()
  && String(role?.created_at || '').trim().length > 0
  && String(role?.updated_at || '').trim().length > 0
  && String(role?.role_id || '').trim().length > 0
  && ROLE_ID_ADDRESSABLE_PATTERN.test(String(role?.role_id || '').trim())
  && isValidActiveTenantId(role?.tenant_id)
  && String(role?.tenant_id || '').trim() === String(activeTenantId || '').trim()
  && String(role?.code || '').trim().length > 0
  && String(role?.code || '').trim().length <= MAX_ROLE_CODE_LENGTH
  && !CONTROL_CHAR_PATTERN.test(String(role?.code || ''))
  && String(role?.name || '').trim().length > 0
  && String(role?.name || '').trim().length <= MAX_ROLE_NAME_LENGTH
  && !CONTROL_CHAR_PATTERN.test(String(role?.name || ''))
  && VALID_ROLE_STATUS.has(String(role?.status || '').trim())
  && typeof role?.is_system === 'boolean'
  && normalizeRoleScopeInput(rawRole?.scope) === TENANT_ROLE_SCOPE;

const isExpectedMutationTarget = ({
  role = {},
  expectedRoleId = '',
  activeTenantId = ''
} = {}) =>
  normalizeRoleIdKey(role?.role_id) === normalizeRoleIdKey(expectedRoleId)
  && String(role?.tenant_id || '').trim() === String(activeTenantId || '').trim();

const createTenantRoleService = ({ authService } = {}) => {
  const auditTrail = [];

  const addAuditEvent = ({
    type,
    requestId,
    operatorUserId = 'unknown',
    targetRoleId = null,
    detail,
    metadata = {}
  }) => {
    const event = {
      type: String(type || '').trim() || 'tenant.role.unknown',
      at: new Date().toISOString(),
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      target_role_id: targetRoleId ? String(targetRoleId) : null,
      detail: String(detail || '').trim(),
      ...metadata
    };
    auditTrail.push(event);
    if (auditTrail.length > MAX_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Tenant role audit event', event);
  };

  const assertAuthServiceMethod = (methodName) => {
    if (!authService || typeof authService[methodName] !== 'function') {
      throw tenantRoleErrors.dependencyUnavailable();
    }
  };

  const resolveOperatorContext = async ({
    requestId,
    accessToken,
    authorizationContext = null,
    permissionCode = TENANT_ROLE_OPERATE_PERMISSION_CODE
  }) => {
    const preAuthorizedOperatorContext = resolveAuthorizedOperatorContext({
      authorizationContext,
      expectedPermissionCode: permissionCode
    });
    if (preAuthorizedOperatorContext) {
      return preAuthorizedOperatorContext;
    }

    assertAuthServiceMethod('authorizeRoute');
    const authorized = await authService.authorizeRoute({
      requestId,
      accessToken,
      permissionCode,
      scope: TENANT_ROLE_SCOPE,
      authorizationContext
    });
    const operatorUserId = normalizeRequiredString(
      authorized?.user_id
        || authorized?.userId
        || authorized?.user?.id
        || authorized?.user?.user_id
        || authorized?.user?.userId
    );
    const operatorSessionId = normalizeRequiredString(
      authorized?.session_id
        || authorized?.sessionId
        || authorized?.session?.session_id
        || authorized?.session?.sessionId
    );
    const activeTenantId = resolveActiveTenantIdFromAuthorizationContext(authorized);
    if (!isValidActiveTenantId(activeTenantId)) {
      throw tenantRoleErrors.noDomainAccess();
    }
    if (
      !isResolvedOperatorIdentifier(operatorUserId)
      || !isResolvedOperatorIdentifier(operatorSessionId)
    ) {
      throw tenantRoleErrors.forbidden();
    }

    return {
      operatorUserId,
      operatorSessionId,
      activeTenantId
    };
  };

  const listRoles = async ({
    requestId,
    accessToken,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: TENANT_ROLE_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.role.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    const { operatorUserId, activeTenantId } = operatorContext;
    assertAuthServiceMethod('listPlatformRoleCatalogEntries');
    let roles = [];
    try {
      roles = await authService.listPlatformRoleCatalogEntries({
        scope: TENANT_ROLE_SCOPE,
        tenantId: activeTenantId
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'tenant.role.list.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant role listing rejected',
          metadata: {
            tenant_id: activeTenantId,
            error_code: error.errorCode
          }
        });
        throw error;
      }
      addAuditEvent({
        type: 'tenant.role.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant role catalog dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantRoleErrors.dependencyUnavailable();
    }

    if (!Array.isArray(roles)) {
      addAuditEvent({
        type: 'tenant.role.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant role listing returned malformed payload',
        metadata: {
          tenant_id: activeTenantId,
          error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantRoleErrors.dependencyUnavailable();
    }

    const mappedRoles = roles.map((role) =>
      mapRoleCatalogEntry(role, resolvedRequestId)
    );
    const hasMalformedRole = mappedRoles.some((role, index) =>
      !isValidRoleCatalogEntry({
        role,
        activeTenantId,
        rawRole: roles[index]
      })
    );
    if (hasMalformedRole) {
      addAuditEvent({
        type: 'tenant.role.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant role listing returned malformed catalog record',
        metadata: {
          tenant_id: activeTenantId,
          error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantRoleErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.role.list.succeeded',
      requestId: resolvedRequestId,
      operatorUserId,
      detail: 'tenant role catalog listed',
      metadata: {
        tenant_id: activeTenantId,
        total: mappedRoles.length
      }
    });

    return {
      tenant_id: activeTenantId,
      roles: mappedRoles,
      request_id: resolvedRequestId
    };
  };

  const createRole = async ({
    requestId,
    accessToken,
    payload = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: TENANT_ROLE_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.role.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    let parsedPayload;
    try {
      parsedPayload = parseCreateRolePayload(payload);
    } catch (error) {
      addAuditEvent({
        type: 'tenant.role.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: String(payload?.role_id || '').trim() || null,
        detail: 'payload validation failed',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: String(error?.errorCode || 'TROLE-400-INVALID-PAYLOAD')
        }
      });
      throw error;
    }

    assertAuthServiceMethod('createPlatformRoleCatalogEntry');
    let createdRole;
    try {
      createdRole = await authService.createPlatformRoleCatalogEntry({
        roleId: parsedPayload.roleId,
        code: parsedPayload.code,
        name: parsedPayload.name,
        status: parsedPayload.status,
        scope: parsedPayload.scope,
        tenantId: operatorContext.activeTenantId,
        isSystem: parsedPayload.isSystem,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId
      });
    } catch (error) {
      const duplicateConflictTarget = resolveDuplicateRoleConflictTarget(error);
      const mappedError = isDuplicateEntryError(error)
        ? (
          duplicateConflictTarget === 'role_id'
            ? tenantRoleErrors.roleIdConflict()
            : tenantRoleErrors.roleCodeConflict()
        )
        : tenantRoleErrors.dependencyUnavailable();
      addAuditEvent({
        type: 'tenant.role.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: parsedPayload.roleId,
        detail:
          mappedError.errorCode === 'TROLE-409-ROLE-ID-CONFLICT'
            ? 'role id conflict'
            : mappedError.errorCode === 'TROLE-409-CODE-CONFLICT'
              ? 'role code conflict'
            : 'tenant role catalog dependency unavailable',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    const mappedRole = mapRoleCatalogEntry(createdRole, resolvedRequestId);
    if (!isValidRoleCatalogEntry({
      role: mappedRole,
      activeTenantId: operatorContext.activeTenantId,
      rawRole: createdRole
    }) || !isExpectedMutationTarget({
      role: mappedRole,
      expectedRoleId: parsedPayload.roleId,
      activeTenantId: operatorContext.activeTenantId
    }) || mappedRole.is_system !== false) {
      addAuditEvent({
        type: 'tenant.role.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: mappedRole.role_id || parsedPayload.roleId,
        detail: 'tenant role creation returned malformed catalog record',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantRoleErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.role.create.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetRoleId: mappedRole.role_id,
      detail: 'tenant role created',
      metadata: {
        tenant_id: operatorContext.activeTenantId,
        code: mappedRole.code,
        status: mappedRole.status
      }
    });

    return mappedRole;
  };

  const updateRole = async ({
    requestId,
    accessToken,
    roleId,
    payload = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedRoleId = normalizeRoleId(roleId);
    if (!normalizedRoleId) {
      throw tenantRoleErrors.invalidPayload('role_id 不能为空');
    }
    if (normalizedRoleId.length > MAX_ROLE_ID_LENGTH) {
      throw tenantRoleErrors.invalidPayload(`role_id 长度不能超过 ${MAX_ROLE_ID_LENGTH}`);
    }
    assertAddressableRoleId(normalizedRoleId);

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: TENANT_ROLE_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        targetRoleId: normalizedRoleId,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    if (isProtectedRoleId(normalizedRoleId)) {
      const error = tenantRoleErrors.protectedRoleMutationDenied();
      addAuditEvent({
        type: 'tenant.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'protected role mutation denied',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: error.errorCode
        }
      });
      throw error;
    }

    assertAuthServiceMethod('findPlatformRoleCatalogEntryByRoleId');
    let existingRole;
    try {
      existingRole = await authService.findPlatformRoleCatalogEntryByRoleId({
        roleId: normalizedRoleId,
        scope: TENANT_ROLE_SCOPE,
        tenantId: operatorContext.activeTenantId
      });
    } catch (_error) {
      addAuditEvent({
        type: 'tenant.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'tenant role lookup dependency unavailable',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantRoleErrors.dependencyUnavailable();
    }

    if (!existingRole) {
      const error = tenantRoleErrors.roleNotFound();
      addAuditEvent({
        type: 'tenant.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'role not found',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: error.errorCode
        }
      });
      throw error;
    }

    const mappedExistingRole = mapRoleCatalogEntry(existingRole, resolvedRequestId);
    if (!isValidRoleCatalogEntry({
      role: mappedExistingRole,
      activeTenantId: operatorContext.activeTenantId,
      rawRole: existingRole
    }) || !isExpectedMutationTarget({
      role: mappedExistingRole,
      expectedRoleId: normalizedRoleId,
      activeTenantId: operatorContext.activeTenantId
    })) {
      addAuditEvent({
        type: 'tenant.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'tenant role lookup returned malformed catalog record',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantRoleErrors.dependencyUnavailable();
    }
    if (mappedExistingRole.is_system) {
      const error = tenantRoleErrors.protectedRoleMutationDenied();
      addAuditEvent({
        type: 'tenant.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'protected role mutation denied',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: error.errorCode
        }
      });
      throw error;
    }

    let parsedPayload;
    try {
      parsedPayload = parseUpdateRolePayload(payload);
    } catch (error) {
      addAuditEvent({
        type: 'tenant.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'payload validation failed',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: String(error?.errorCode || 'TROLE-400-INVALID-PAYLOAD')
        }
      });
      throw error;
    }

    assertAuthServiceMethod('updatePlatformRoleCatalogEntry');
    let updatedRole;
    try {
      updatedRole = await authService.updatePlatformRoleCatalogEntry({
        roleId: normalizedRoleId,
        scope: TENANT_ROLE_SCOPE,
        tenantId: operatorContext.activeTenantId,
        ...parsedPayload,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId
      });
    } catch (error) {
      const duplicateConflictTarget = resolveDuplicateRoleConflictTarget(error);
      const mappedError = isDuplicateEntryError(error)
        ? (
          duplicateConflictTarget === 'role_id'
            ? tenantRoleErrors.roleIdConflict()
            : tenantRoleErrors.roleCodeConflict()
        )
        : tenantRoleErrors.dependencyUnavailable();
      addAuditEvent({
        type: 'tenant.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail:
          mappedError.errorCode === 'TROLE-409-ROLE-ID-CONFLICT'
            ? 'role id conflict'
            : mappedError.errorCode === 'TROLE-409-CODE-CONFLICT'
              ? 'role code conflict'
            : 'tenant role catalog dependency unavailable',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    if (!updatedRole) {
      const error = tenantRoleErrors.roleNotFound();
      addAuditEvent({
        type: 'tenant.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'role not found',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: error.errorCode
        }
      });
      throw error;
    }

    const mappedRole = mapRoleCatalogEntry(updatedRole, resolvedRequestId);
    if (!isValidRoleCatalogEntry({
      role: mappedRole,
      activeTenantId: operatorContext.activeTenantId,
      rawRole: updatedRole
    }) || !isExpectedMutationTarget({
      role: mappedRole,
      expectedRoleId: normalizedRoleId,
      activeTenantId: operatorContext.activeTenantId
    }) || mappedRole.is_system !== false) {
      addAuditEvent({
        type: 'tenant.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'tenant role update returned malformed catalog record',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantRoleErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.role.update.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetRoleId: mappedRole.role_id,
      detail: 'tenant role updated',
      metadata: {
        tenant_id: operatorContext.activeTenantId,
        code: mappedRole.code,
        status: mappedRole.status
      }
    });

    return mappedRole;
  };

  const deleteRole = async ({
    requestId,
    accessToken,
    roleId,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedRoleId = normalizeRoleId(roleId);
    if (!normalizedRoleId) {
      throw tenantRoleErrors.invalidPayload('role_id 不能为空');
    }
    if (normalizedRoleId.length > MAX_ROLE_ID_LENGTH) {
      throw tenantRoleErrors.invalidPayload(`role_id 长度不能超过 ${MAX_ROLE_ID_LENGTH}`);
    }
    assertAddressableRoleId(normalizedRoleId);

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: TENANT_ROLE_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        targetRoleId: normalizedRoleId,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    if (isProtectedRoleId(normalizedRoleId)) {
      const error = tenantRoleErrors.protectedRoleMutationDenied();
      addAuditEvent({
        type: 'tenant.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'protected role mutation denied',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: error.errorCode
        }
      });
      throw error;
    }

    assertAuthServiceMethod('findPlatformRoleCatalogEntryByRoleId');
    let existingRole;
    try {
      existingRole = await authService.findPlatformRoleCatalogEntryByRoleId({
        roleId: normalizedRoleId,
        scope: TENANT_ROLE_SCOPE,
        tenantId: operatorContext.activeTenantId
      });
    } catch (_error) {
      addAuditEvent({
        type: 'tenant.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'tenant role lookup dependency unavailable',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantRoleErrors.dependencyUnavailable();
    }

    if (!existingRole) {
      const error = tenantRoleErrors.roleNotFound();
      addAuditEvent({
        type: 'tenant.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'role not found',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: error.errorCode
        }
      });
      throw error;
    }
    const mappedExistingRole = mapRoleCatalogEntry(existingRole, resolvedRequestId);
    if (!isValidRoleCatalogEntry({
      role: mappedExistingRole,
      activeTenantId: operatorContext.activeTenantId,
      rawRole: existingRole
    }) || !isExpectedMutationTarget({
      role: mappedExistingRole,
      expectedRoleId: normalizedRoleId,
      activeTenantId: operatorContext.activeTenantId
    })) {
      addAuditEvent({
        type: 'tenant.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'tenant role lookup returned malformed catalog record',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantRoleErrors.dependencyUnavailable();
    }
    if (mappedExistingRole.is_system) {
      const error = tenantRoleErrors.protectedRoleMutationDenied();
      addAuditEvent({
        type: 'tenant.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'protected role mutation denied',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: error.errorCode
        }
      });
      throw error;
    }
    if (mappedExistingRole.status !== 'active') {
      const error = tenantRoleErrors.deleteConditionNotMet('禁用状态角色不允许删除');
      addAuditEvent({
        type: 'tenant.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'delete precondition failed',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: error.errorCode
        }
      });
      throw error;
    }

    assertAuthServiceMethod('deletePlatformRoleCatalogEntry');
    let deletedRole;
    try {
      deletedRole = await authService.deletePlatformRoleCatalogEntry({
        roleId: normalizedRoleId,
        scope: TENANT_ROLE_SCOPE,
        tenantId: operatorContext.activeTenantId,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId
      });
    } catch (_error) {
      addAuditEvent({
        type: 'tenant.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'tenant role catalog dependency unavailable',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantRoleErrors.dependencyUnavailable();
    }

    if (!deletedRole) {
      const error = tenantRoleErrors.roleNotFound();
      addAuditEvent({
        type: 'tenant.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'role not found',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: error.errorCode
        }
      });
      throw error;
    }

    const mappedRole = mapRoleCatalogEntry(deletedRole, resolvedRequestId);
    if (!isValidRoleCatalogEntry({
      role: mappedRole,
      activeTenantId: operatorContext.activeTenantId,
      rawRole: deletedRole
    }) || !isExpectedMutationTarget({
      role: mappedRole,
      expectedRoleId: normalizedRoleId,
      activeTenantId: operatorContext.activeTenantId
    }) || mappedRole.is_system !== false || mappedRole.status !== 'disabled') {
      addAuditEvent({
        type: 'tenant.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'tenant role delete returned malformed catalog record',
        metadata: {
          tenant_id: operatorContext.activeTenantId,
          error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantRoleErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.role.delete.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetRoleId: mappedRole.role_id,
      detail: 'tenant role soft deleted',
      metadata: {
        tenant_id: operatorContext.activeTenantId,
        status: mappedRole.status
      }
    });

    return {
      role_id: mappedRole.role_id,
      tenant_id: mappedRole.tenant_id,
      status: mappedRole.status,
      request_id: resolvedRequestId
    };
  };

  return {
    listRoles,
    createRole,
    updateRole,
    deleteRole,
    _internals: {
      auditTrail,
      authService
    }
  };
};

module.exports = {
  createTenantRoleService
};

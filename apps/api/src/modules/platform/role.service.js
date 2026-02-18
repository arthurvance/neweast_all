const { log } = require('../../common/logger');
const { AuthProblemError } = require('../auth/auth.service');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_ROLE_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_OPERATE_PERMISSION_CODE,
  PLATFORM_ROLE_SCOPE,
  PROTECTED_PLATFORM_ROLE_IDS
} = require('./role.constants');

const MYSQL_DUP_ENTRY_ERRNO = 1062;
const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const MAX_ROLE_ID_LENGTH = 64;
const MAX_ROLE_CODE_LENGTH = 64;
const MAX_ROLE_NAME_LENGTH = 128;
const MAX_PERMISSION_CODES_PAYLOAD_LENGTH = 64;
const ROLE_ID_ADDRESSABLE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const VALID_ROLE_STATUS = new Set(['active', 'disabled']);
const CREATE_ROLE_ALLOWED_FIELDS = new Set([
  'role_id',
  'code',
  'name',
  'status',
  'is_system'
]);
const UPDATE_ROLE_ALLOWED_FIELDS = new Set([
  'code',
  'name',
  'status'
]);
const UPDATE_ROLE_PERMISSION_ALLOWED_FIELDS = new Set([
  'permission_codes'
]);
const PROTECTED_ROLE_ID_SET = new Set(
  PROTECTED_PLATFORM_ROLE_IDS.map((roleId) => String(roleId || '').trim().toLowerCase())
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

const normalizeRoleStatusOutput = (status) => {
  const normalized = normalizeRoleStatusInput(status);
  if (normalized === 'enabled') {
    return 'active';
  }
  return normalized;
};

const normalizeRoleId = (roleId) => normalizeRequiredString(roleId).toLowerCase();
const normalizeRoleIdKey = (roleId) => normalizeRoleId(roleId).toLowerCase();
const assertAddressableRoleId = (roleId) => {
  if (!ROLE_ID_ADDRESSABLE_PATTERN.test(roleId)) {
    throw roleErrors.invalidPayload(
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
    errorMessage.includes('uk_platform_role_catalog_code_normalized')
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
    return new Date().toISOString();
  }
  const asDate = new Date(value);
  if (!Number.isNaN(asDate.getTime())) {
    return asDate.toISOString();
  }
  return String(value);
};

const roleProblem = ({ status, title, detail, errorCode, extensions = {} }) =>
  new AuthProblemError({
    status,
    title,
    detail,
    errorCode,
    extensions
  });

const roleErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    roleProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'ROLE-400-INVALID-PAYLOAD'
    }),

  forbidden: () =>
    roleProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  protectedRoleMutationDenied: () =>
    roleProblem({
      status: 403,
      title: 'Forbidden',
      detail: '受保护系统角色不允许编辑或删除',
      errorCode: 'ROLE-403-SYSTEM-ROLE-PROTECTED',
      extensions: {
        retryable: false
      }
    }),

  roleNotFound: () =>
    roleProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标平台角色不存在',
      errorCode: 'ROLE-404-ROLE-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  roleCodeConflict: () =>
    roleProblem({
      status: 409,
      title: 'Conflict',
      detail: '角色编码冲突，请使用其他 code',
      errorCode: 'ROLE-409-CODE-CONFLICT',
      extensions: {
        retryable: false
      }
    }),

  roleIdConflict: () =>
    roleProblem({
      status: 409,
      title: 'Conflict',
      detail: '角色标识冲突，请使用其他 role_id',
      errorCode: 'ROLE-409-ROLE-ID-CONFLICT',
      extensions: {
        retryable: false
      }
    }),

  dependencyUnavailable: () =>
    roleProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '平台角色治理依赖暂不可用，请稍后重试',
      errorCode: 'ROLE-503-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true
      }
    })
};

const resolveAuthorizedOperatorContext = ({
  authorizationContext = null,
  expectedPermissionCode = PLATFORM_ROLE_OPERATE_PERMISSION_CODE
}) => {
  const preauthorizedContext = resolveRoutePreauthorizedContext({
    authorizationContext,
    expectedPermissionCode,
    expectedScope: PLATFORM_ROLE_SCOPE,
    expectedEntryDomain: PLATFORM_ROLE_SCOPE
  });
  if (!preauthorizedContext) {
    return null;
  }
  return {
    operatorUserId: preauthorizedContext.userId,
    operatorSessionId: preauthorizedContext.sessionId
  };
};

const parseCreateRolePayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw roleErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !CREATE_ROLE_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw roleErrors.invalidPayload('请求参数不完整或格式错误');
  }
  if (
    !Object.prototype.hasOwnProperty.call(payload, 'role_id')
    || !Object.prototype.hasOwnProperty.call(payload, 'code')
    || !Object.prototype.hasOwnProperty.call(payload, 'name')
  ) {
    throw roleErrors.invalidPayload();
  }

  const roleId = normalizeRoleId(payload.role_id);
  const code = normalizeRequiredString(payload.code);
  const name = normalizeRequiredString(payload.name);
  const status = normalizeRoleStatusInput(
    Object.prototype.hasOwnProperty.call(payload, 'status')
      ? payload.status
      : 'active'
  );
  const isSystem = Boolean(payload.is_system);

  if (!roleId) {
    throw roleErrors.invalidPayload('role_id 不能为空');
  }
  if (roleId.length > MAX_ROLE_ID_LENGTH) {
    throw roleErrors.invalidPayload(`role_id 长度不能超过 ${MAX_ROLE_ID_LENGTH}`);
  }
  assertAddressableRoleId(roleId);
  if (!code || code.length > MAX_ROLE_CODE_LENGTH) {
    throw roleErrors.invalidPayload(`code 长度不能超过 ${MAX_ROLE_CODE_LENGTH}`);
  }
  if (!name || name.length > MAX_ROLE_NAME_LENGTH) {
    throw roleErrors.invalidPayload(`name 长度不能超过 ${MAX_ROLE_NAME_LENGTH}`);
  }
  if (CONTROL_CHAR_PATTERN.test(roleId) || CONTROL_CHAR_PATTERN.test(code) || CONTROL_CHAR_PATTERN.test(name)) {
    throw roleErrors.invalidPayload('role_id/code/name 不能包含控制字符');
  }
  if (!VALID_ROLE_STATUS.has(status)) {
    throw roleErrors.invalidPayload('status 必须为 active 或 disabled');
  }
  if (isSystem) {
    throw roleErrors.invalidPayload('is_system 仅允许由系统维护');
  }

  return {
    roleId,
    code,
    name,
    status,
    isSystem: false,
    scope: PLATFORM_ROLE_SCOPE
  };
};

const parseUpdateRolePayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw roleErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !UPDATE_ROLE_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw roleErrors.invalidPayload('请求参数不完整或格式错误');
  }

  const hasCode = Object.prototype.hasOwnProperty.call(payload, 'code');
  const hasName = Object.prototype.hasOwnProperty.call(payload, 'name');
  const hasStatus = Object.prototype.hasOwnProperty.call(payload, 'status');
  if (!hasCode && !hasName && !hasStatus) {
    throw roleErrors.invalidPayload('至少提供一个可更新字段');
  }

  const updates = {};
  if (hasCode) {
    const code = normalizeRequiredString(payload.code);
    if (!code || code.length > MAX_ROLE_CODE_LENGTH) {
      throw roleErrors.invalidPayload(`code 长度不能超过 ${MAX_ROLE_CODE_LENGTH}`);
    }
    if (CONTROL_CHAR_PATTERN.test(code)) {
      throw roleErrors.invalidPayload('code 不能包含控制字符');
    }
    updates.code = code;
  }
  if (hasName) {
    const name = normalizeRequiredString(payload.name);
    if (!name || name.length > MAX_ROLE_NAME_LENGTH) {
      throw roleErrors.invalidPayload(`name 长度不能超过 ${MAX_ROLE_NAME_LENGTH}`);
    }
    if (CONTROL_CHAR_PATTERN.test(name)) {
      throw roleErrors.invalidPayload('name 不能包含控制字符');
    }
    updates.name = name;
  }
  if (hasStatus) {
    const status = normalizeRoleStatusInput(payload.status);
    if (!VALID_ROLE_STATUS.has(status)) {
      throw roleErrors.invalidPayload('status 必须为 active 或 disabled');
    }
    updates.status = status;
  }

  return updates;
};

const parseReplaceRolePermissionsPayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw roleErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !UPDATE_ROLE_PERMISSION_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw roleErrors.invalidPayload('请求参数不完整或格式错误');
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'permission_codes')) {
    throw roleErrors.invalidPayload('permission_codes 必填');
  }
  if (!Array.isArray(payload.permission_codes)) {
    throw roleErrors.invalidPayload('permission_codes 必须为数组');
  }
  if (payload.permission_codes.length > MAX_PERMISSION_CODES_PAYLOAD_LENGTH) {
    throw roleErrors.invalidPayload(
      `permission_codes 数量不能超过 ${MAX_PERMISSION_CODES_PAYLOAD_LENGTH}`
    );
  }
  const dedupedPermissionCodes = new Map();
  for (const permissionCode of payload.permission_codes) {
    if (typeof permissionCode !== 'string') {
      throw roleErrors.invalidPayload('permission_codes 仅允许字符串权限码');
    }
    const normalizedPermissionCode = permissionCode.trim();
    if (!normalizedPermissionCode) {
      throw roleErrors.invalidPayload('permission_codes 不能为空字符串');
    }
    const normalizedPermissionCodeKey = normalizedPermissionCode.toLowerCase();
    if (dedupedPermissionCodes.has(normalizedPermissionCodeKey)) {
      throw roleErrors.invalidPayload('permission_codes 不允许重复');
    }
    dedupedPermissionCodes.set(
      normalizedPermissionCodeKey,
      normalizedPermissionCode
    );
  }
  return {
    permissionCodes: [...dedupedPermissionCodes.values()]
  };
};

const mapRoleCatalogEntry = (role, requestId) => ({
  role_id: String(role?.roleId || role?.role_id || '').trim(),
  code: String(role?.code || '').trim(),
  name: String(role?.name || '').trim(),
  status: normalizeRoleStatusOutput(role?.status) || 'active',
  is_system: Boolean(role?.isSystem ?? role?.is_system),
  created_at: toIsoTimestamp(role?.createdAt ?? role?.created_at),
  updated_at: toIsoTimestamp(role?.updatedAt ?? role?.updated_at),
  request_id: String(requestId || '').trim() || 'request_id_unset'
});

const createPlatformRoleService = ({ authService } = {}) => {
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
      type: String(type || '').trim() || 'platform.role.unknown',
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
    log('info', 'Platform role audit event', event);
  };

  const assertAuthServiceMethod = (methodName) => {
    if (!authService || typeof authService[methodName] !== 'function') {
      throw roleErrors.dependencyUnavailable();
    }
  };

  const resolveOperatorContext = async ({
    requestId,
    accessToken,
    authorizationContext = null,
    permissionCode = PLATFORM_ROLE_OPERATE_PERMISSION_CODE
  }) => {
    const preAuthorizedOperatorContext = resolveAuthorizedOperatorContext({
      authorizationContext,
      expectedPermissionCode: permissionCode
    });
    let operatorUserId = preAuthorizedOperatorContext?.operatorUserId || 'unknown';
    let operatorSessionId = preAuthorizedOperatorContext?.operatorSessionId || 'unknown';

    if (!preAuthorizedOperatorContext) {
      assertAuthServiceMethod('authorizeRoute');
      const authorized = await authService.authorizeRoute({
        requestId,
        accessToken,
        permissionCode,
        scope: PLATFORM_ROLE_SCOPE,
        authorizationContext
      });
      operatorUserId = String(authorized?.user_id || '').trim() || 'unknown';
      operatorSessionId = String(authorized?.session_id || '').trim() || 'unknown';
    }

    if (
      !isResolvedOperatorIdentifier(operatorUserId)
      || !isResolvedOperatorIdentifier(operatorSessionId)
    ) {
      throw roleErrors.forbidden();
    }
    return {
      operatorUserId,
      operatorSessionId
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
        permissionCode: PLATFORM_ROLE_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      addAuditEvent({
        type: 'platform.role.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: String(error?.errorCode || 'AUTH-403-FORBIDDEN')
        }
      });
      throw error;
    }

    assertAuthServiceMethod('listPlatformRoleCatalogEntries');
    let roles;
    try {
      roles = await authService.listPlatformRoleCatalogEntries({
        scope: PLATFORM_ROLE_SCOPE
      });
    } catch (_error) {
      addAuditEvent({
        type: 'platform.role.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        detail: 'platform role catalog dependency unavailable',
        metadata: {
          error_code: 'ROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw roleErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'platform.role.list.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      detail: 'platform role catalog listed',
      metadata: {
        total: Array.isArray(roles) ? roles.length : 0
      }
    });

    const mappedRoles = (Array.isArray(roles) ? roles : [])
      .map((role) => mapRoleCatalogEntry(role, resolvedRequestId));
    return {
      roles: mappedRoles,
      request_id: resolvedRequestId
    };
  };

  const getRolePermissions = async ({
    requestId,
    accessToken,
    roleId,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedRoleId = normalizeRoleId(roleId);
    if (!normalizedRoleId) {
      throw roleErrors.invalidPayload('role_id 不能为空');
    }
    if (normalizedRoleId.length > MAX_ROLE_ID_LENGTH) {
      throw roleErrors.invalidPayload(`role_id 长度不能超过 ${MAX_ROLE_ID_LENGTH}`);
    }
    assertAddressableRoleId(normalizedRoleId);

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: PLATFORM_ROLE_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      addAuditEvent({
        type: 'platform.role.permissions.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        targetRoleId: normalizedRoleId,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: String(error?.errorCode || 'AUTH-403-FORBIDDEN')
        }
      });
      throw error;
    }

    assertAuthServiceMethod('listPlatformRolePermissionGrants');
    let grants;
    try {
      grants = await authService.listPlatformRolePermissionGrants({
        roleId: normalizedRoleId
      });
    } catch (error) {
      const mappedError = (
        error?.errorCode === 'AUTH-400-INVALID-PAYLOAD'
        || error?.errorCode === 'AUTH-404-ROLE-NOT-FOUND'
      )
        ? roleErrors.roleNotFound()
        : roleErrors.dependencyUnavailable();
      addAuditEvent({
        type: 'platform.role.permissions.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail:
          mappedError.errorCode === 'ROLE-404-ROLE-NOT-FOUND'
            ? 'role not found'
            : 'platform role permission grants dependency unavailable',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    addAuditEvent({
      type: 'platform.role.permissions.read.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetRoleId: normalizedRoleId,
      detail: 'platform role permission grants listed',
      metadata: {
        permission_codes_count: Array.isArray(grants?.permission_codes)
          ? grants.permission_codes.length
          : 0
      }
    });

    return {
      role_id: normalizedRoleId,
      permission_codes: Array.isArray(grants?.permission_codes)
        ? [...grants.permission_codes]
        : [],
      available_permission_codes: Array.isArray(grants?.available_permission_codes)
        ? [...grants.available_permission_codes]
        : [],
      request_id: resolvedRequestId
    };
  };

  const replaceRolePermissions = async ({
    requestId,
    accessToken,
    roleId,
    payload = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedRoleId = normalizeRoleId(roleId);
    if (!normalizedRoleId) {
      throw roleErrors.invalidPayload('role_id 不能为空');
    }
    if (normalizedRoleId.length > MAX_ROLE_ID_LENGTH) {
      throw roleErrors.invalidPayload(`role_id 长度不能超过 ${MAX_ROLE_ID_LENGTH}`);
    }
    assertAddressableRoleId(normalizedRoleId);

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: PLATFORM_ROLE_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      addAuditEvent({
        type: 'platform.role.permissions.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        targetRoleId: normalizedRoleId,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: String(error?.errorCode || 'AUTH-403-FORBIDDEN')
        }
      });
      throw error;
    }

    let parsedPayload;
    try {
      parsedPayload = parseReplaceRolePermissionsPayload(payload);
    } catch (error) {
      addAuditEvent({
        type: 'platform.role.permissions.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'payload validation failed',
        metadata: {
          error_code: String(error?.errorCode || 'ROLE-400-INVALID-PAYLOAD')
        }
      });
      throw error;
    }

    assertAuthServiceMethod('replacePlatformRolePermissionGrants');
    assertAuthServiceMethod('listPlatformRolePermissionGrants');
    assertAuthServiceMethod('listPlatformPermissionCatalog');

    try {
      await authService.listPlatformRolePermissionGrants({
        roleId: normalizedRoleId
      });
    } catch (error) {
      const mappedError = (
        error?.errorCode === 'AUTH-400-INVALID-PAYLOAD'
        || error?.errorCode === 'AUTH-404-ROLE-NOT-FOUND'
      )
        ? roleErrors.roleNotFound()
        : roleErrors.dependencyUnavailable();
      addAuditEvent({
        type: 'platform.role.permissions.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail:
          mappedError.errorCode === 'ROLE-404-ROLE-NOT-FOUND'
            ? 'role not found'
            : 'platform role permission grants dependency unavailable',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    let updated;
    try {
      updated = await authService.replacePlatformRolePermissionGrants({
        requestId: resolvedRequestId,
        roleId: normalizedRoleId,
        permissionCodes: parsedPayload.permissionCodes,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId
      });
    } catch (error) {
      const mappedError = error?.errorCode === 'AUTH-404-ROLE-NOT-FOUND'
        ? roleErrors.roleNotFound()
        : error?.errorCode === 'AUTH-400-INVALID-PAYLOAD'
          ? roleErrors.invalidPayload('请求参数不完整或格式错误')
          : roleErrors.dependencyUnavailable();
      addAuditEvent({
        type: 'platform.role.permissions.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail:
          mappedError.errorCode === 'ROLE-404-ROLE-NOT-FOUND'
            ? 'role not found'
            : mappedError.errorCode === 'ROLE-400-INVALID-PAYLOAD'
            ? 'payload validation failed'
            : 'platform role permission grants update failed',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    const availablePermissionCodes = authService.listPlatformPermissionCatalog();
    addAuditEvent({
      type: 'platform.role.permissions.update.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetRoleId: normalizedRoleId,
      detail: 'platform role permission grants replaced',
      metadata: {
        permission_codes_count: Array.isArray(updated?.permission_codes)
          ? updated.permission_codes.length
          : 0,
        affected_user_count: Number(updated?.affected_user_count || 0)
      }
    });

    return {
      role_id: normalizedRoleId,
      permission_codes: Array.isArray(updated?.permission_codes)
        ? [...updated.permission_codes]
        : [],
      available_permission_codes: Array.isArray(availablePermissionCodes)
        ? [...availablePermissionCodes]
        : [],
      affected_user_count: Number(updated?.affected_user_count || 0),
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
        permissionCode: PLATFORM_ROLE_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      addAuditEvent({
        type: 'platform.role.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: String(error?.errorCode || 'AUTH-403-FORBIDDEN')
        }
      });
      throw error;
    }

    let parsedPayload;
    try {
      parsedPayload = parseCreateRolePayload(payload);
    } catch (error) {
      addAuditEvent({
        type: 'platform.role.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: String(payload?.role_id || '').trim() || null,
        detail: 'payload validation failed',
        metadata: {
          error_code: String(error?.errorCode || 'ROLE-400-INVALID-PAYLOAD')
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
        isSystem: parsedPayload.isSystem,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId
      });
    } catch (error) {
      const duplicateConflictTarget = resolveDuplicateRoleConflictTarget(error);
      const mappedError = isDuplicateEntryError(error)
        ? (
          duplicateConflictTarget === 'role_id'
            ? roleErrors.roleIdConflict()
            : roleErrors.roleCodeConflict()
        )
        : roleErrors.dependencyUnavailable();
      addAuditEvent({
        type: 'platform.role.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: parsedPayload.roleId,
        detail:
          mappedError.errorCode === 'ROLE-409-ROLE-ID-CONFLICT'
            ? 'role id conflict'
            : mappedError.errorCode === 'ROLE-409-CODE-CONFLICT'
              ? 'role code conflict'
            : 'platform role catalog dependency unavailable',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    const mappedRole = mapRoleCatalogEntry(createdRole, resolvedRequestId);
    addAuditEvent({
      type: 'platform.role.create.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetRoleId: mappedRole.role_id,
      detail: 'platform role created',
      metadata: {
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
      throw roleErrors.invalidPayload('role_id 不能为空');
    }
    if (normalizedRoleId.length > MAX_ROLE_ID_LENGTH) {
      throw roleErrors.invalidPayload(`role_id 长度不能超过 ${MAX_ROLE_ID_LENGTH}`);
    }
    assertAddressableRoleId(normalizedRoleId);

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: PLATFORM_ROLE_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      addAuditEvent({
        type: 'platform.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        targetRoleId: normalizedRoleId,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: String(error?.errorCode || 'AUTH-403-FORBIDDEN')
        }
      });
      throw error;
    }

    if (isProtectedRoleId(normalizedRoleId)) {
      const error = roleErrors.protectedRoleMutationDenied();
      addAuditEvent({
        type: 'platform.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'protected role mutation denied',
        metadata: {
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
        type: 'platform.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'payload validation failed',
        metadata: {
          error_code: String(error?.errorCode || 'ROLE-400-INVALID-PAYLOAD')
        }
      });
      throw error;
    }

    assertAuthServiceMethod('updatePlatformRoleCatalogEntry');
    let updatedRole;
    try {
      updatedRole = await authService.updatePlatformRoleCatalogEntry({
        roleId: normalizedRoleId,
        ...parsedPayload,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId
      });
    } catch (error) {
      const duplicateConflictTarget = resolveDuplicateRoleConflictTarget(error);
      const mappedError = isDuplicateEntryError(error)
        ? (
          duplicateConflictTarget === 'role_id'
            ? roleErrors.roleIdConflict()
            : roleErrors.roleCodeConflict()
        )
        : roleErrors.dependencyUnavailable();
      addAuditEvent({
        type: 'platform.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail:
          mappedError.errorCode === 'ROLE-409-ROLE-ID-CONFLICT'
            ? 'role id conflict'
            : mappedError.errorCode === 'ROLE-409-CODE-CONFLICT'
              ? 'role code conflict'
            : 'platform role catalog dependency unavailable',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    if (!updatedRole) {
      const error = roleErrors.roleNotFound();
      addAuditEvent({
        type: 'platform.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'role not found',
        metadata: {
          error_code: error.errorCode
        }
      });
      throw error;
    }

    const mappedRole = mapRoleCatalogEntry(updatedRole, resolvedRequestId);
    addAuditEvent({
      type: 'platform.role.update.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetRoleId: mappedRole.role_id,
      detail: 'platform role updated',
      metadata: {
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
      throw roleErrors.invalidPayload('role_id 不能为空');
    }
    if (normalizedRoleId.length > MAX_ROLE_ID_LENGTH) {
      throw roleErrors.invalidPayload(`role_id 长度不能超过 ${MAX_ROLE_ID_LENGTH}`);
    }
    assertAddressableRoleId(normalizedRoleId);

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: PLATFORM_ROLE_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      addAuditEvent({
        type: 'platform.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        targetRoleId: normalizedRoleId,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: String(error?.errorCode || 'AUTH-403-FORBIDDEN')
        }
      });
      throw error;
    }

    if (isProtectedRoleId(normalizedRoleId)) {
      const error = roleErrors.protectedRoleMutationDenied();
      addAuditEvent({
        type: 'platform.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'protected role mutation denied',
        metadata: {
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
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId
      });
    } catch (_error) {
      addAuditEvent({
        type: 'platform.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'platform role catalog dependency unavailable',
        metadata: {
          error_code: 'ROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw roleErrors.dependencyUnavailable();
    }

    if (!deletedRole) {
      const error = roleErrors.roleNotFound();
      addAuditEvent({
        type: 'platform.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'role not found',
        metadata: {
          error_code: error.errorCode
        }
      });
      throw error;
    }

    const mappedRole = mapRoleCatalogEntry(deletedRole, resolvedRequestId);
    addAuditEvent({
      type: 'platform.role.delete.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetRoleId: mappedRole.role_id,
      detail: 'platform role soft deleted',
      metadata: {
        status: mappedRole.status
      }
    });

    return {
      role_id: mappedRole.role_id,
      status: mappedRole.status,
      request_id: resolvedRequestId
    };
  };

  return {
    listRoles,
    getRolePermissions,
    replaceRolePermissions,
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
  createPlatformRoleService
};

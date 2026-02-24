const { randomBytes } = require('node:crypto');
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
const PLATFORM_PERMISSION_CODE_PATTERN = /^platform\.[A-Za-z0-9._-]+$/;
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
const createSystemGeneratedRoleId = () =>
  `role_${Date.now().toString(36)}_${randomBytes(6).toString('hex')}`;
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
    errorMessage.includes('uk_platform_roles_code_normalized')
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
    !Object.prototype.hasOwnProperty.call(payload, 'code')
    || !Object.prototype.hasOwnProperty.call(payload, 'name')
  ) {
    throw roleErrors.invalidPayload();
  }

  const hasRoleId = Object.prototype.hasOwnProperty.call(payload, 'role_id');
  const roleId = hasRoleId
    ? normalizeRoleId(payload.role_id)
    : createSystemGeneratedRoleId();
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
    roleIdAutoGenerated: !hasRoleId,
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
    if (permissionCode !== normalizedPermissionCode) {
      throw roleErrors.invalidPayload('permission_codes 不能包含前后空白字符');
    }
    if (CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)) {
      throw roleErrors.invalidPayload('permission_codes 不允许包含控制字符');
    }
    const normalizedPermissionCodeKey = normalizedPermissionCode.toLowerCase();
    if (!PLATFORM_PERMISSION_CODE_PATTERN.test(normalizedPermissionCodeKey)) {
      throw roleErrors.invalidPayload('permission_codes 仅允许 platform.* 权限码');
    }
    if (!dedupedPermissionCodes.has(normalizedPermissionCodeKey)) {
      dedupedPermissionCodes.set(
        normalizedPermissionCodeKey,
        normalizedPermissionCodeKey
      );
    }
  }
  const permissionCodes = [...dedupedPermissionCodes.values()]
    .sort((left, right) => left.localeCompare(right));
  return {
    permissionCodes
  };
};

const normalizeStrictRequiredString = (candidate) => {
  if (typeof candidate !== 'string') {
    return '';
  }
  return candidate.trim();
};

const resolveRawRoleCatalogField = (
  role,
  camelCaseKey,
  snakeCaseKey
) => {
  if (!isPlainObject(role)) {
    return undefined;
  }
  const hasCamelCaseKey = Object.prototype.hasOwnProperty.call(
    role,
    camelCaseKey
  );
  const hasSnakeCaseKey = Object.prototype.hasOwnProperty.call(
    role,
    snakeCaseKey
  );
  if (hasCamelCaseKey) {
    const camelCaseValue = role[camelCaseKey];
    if (camelCaseValue !== undefined && camelCaseValue !== null) {
      return camelCaseValue;
    }
  }
  if (hasSnakeCaseKey) {
    const snakeCaseValue = role[snakeCaseKey];
    if (snakeCaseValue !== undefined && snakeCaseValue !== null) {
      return snakeCaseValue;
    }
  }
  if (hasCamelCaseKey) {
    return role[camelCaseKey];
  }
  if (hasSnakeCaseKey) {
    return role[snakeCaseKey];
  }
  return undefined;
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

const isValidRoleCatalogEntry = ({
  role = {},
  rawRole = null
} = {}) =>
  (() => {
    const createdAtEpoch = new Date(String(role?.created_at || '').trim()).getTime();
    const updatedAtEpoch = new Date(String(role?.updated_at || '').trim()).getTime();
    return Number.isFinite(createdAtEpoch) && Number.isFinite(updatedAtEpoch);
  })()
  && (() => {
    const rawRoleId = normalizeStrictRequiredString(
      resolveRawRoleCatalogField(rawRole, 'roleId', 'role_id')
    );
    const rawCode = normalizeStrictRequiredString(rawRole?.code);
    const rawName = normalizeStrictRequiredString(rawRole?.name);
    const rawStatus = normalizeRoleStatusOutput(
      normalizeStrictRequiredString(rawRole?.status).toLowerCase()
    );
    const rawScope = normalizeStrictRequiredString(rawRole?.scope).toLowerCase();
    const rawCreatedAt = normalizeStrictRequiredString(
      resolveRawRoleCatalogField(rawRole, 'createdAt', 'created_at')
    );
    const rawUpdatedAt = normalizeStrictRequiredString(
      resolveRawRoleCatalogField(rawRole, 'updatedAt', 'updated_at')
    );
    const rawIsSystem = resolveRawRoleCatalogField(rawRole, 'isSystem', 'is_system');

    return (
      !!rawRoleId
      && !!rawCode
      && !!rawName
      && !!rawStatus
      && !!rawScope
      && !!rawCreatedAt
      && !!rawUpdatedAt
      && normalizeRoleIdKey(rawRoleId) === normalizeRoleIdKey(role?.role_id)
      && rawCode === String(role?.code || '')
      && rawName === String(role?.name || '')
      && rawStatus === String(role?.status || '')
      && rawScope === PLATFORM_ROLE_SCOPE
      && typeof rawIsSystem === 'boolean'
      && rawIsSystem === role?.is_system
      && !CONTROL_CHAR_PATTERN.test(rawCode)
      && !CONTROL_CHAR_PATTERN.test(rawName)
    );
  })()
  && String(role?.created_at || '').trim().length > 0
  && String(role?.updated_at || '').trim().length > 0
  && String(role?.role_id || '').trim().length > 0
  && ROLE_ID_ADDRESSABLE_PATTERN.test(String(role?.role_id || '').trim())
  && String(role?.code || '').trim().length > 0
  && String(role?.code || '').trim().length <= MAX_ROLE_CODE_LENGTH
  && !CONTROL_CHAR_PATTERN.test(String(role?.code || ''))
  && String(role?.name || '').trim().length > 0
  && String(role?.name || '').trim().length <= MAX_ROLE_NAME_LENGTH
  && !CONTROL_CHAR_PATTERN.test(String(role?.name || ''))
  && VALID_ROLE_STATUS.has(String(role?.status || '').trim())
  && typeof role?.is_system === 'boolean'
  && normalizeRoleStatusOutput(rawRole?.status) === String(role?.status || '')
  && normalizeRequiredString(rawRole?.scope) === PLATFORM_ROLE_SCOPE;

const isExpectedMutationTarget = ({
  role = {},
  expectedRoleId = ''
} = {}) =>
  normalizeRoleIdKey(role?.role_id) === normalizeRoleIdKey(expectedRoleId);

const normalizeStrictPlatformPermissionCodes = ({
  permissionCodes,
  minCount = 0,
  maxCount = Number.POSITIVE_INFINITY
} = {}) => {
  if (!Array.isArray(permissionCodes)) {
    return null;
  }
  if (
    permissionCodes.length < minCount
    || permissionCodes.length > maxCount
  ) {
    return null;
  }
  const normalizedPermissionCodes = [];
  const seenPermissionCodes = new Set();
  for (const permissionCode of permissionCodes) {
    if (typeof permissionCode !== 'string') {
      return null;
    }
    const trimmedPermissionCode = permissionCode.trim();
    if (permissionCode !== trimmedPermissionCode) {
      return null;
    }
    const normalizedPermissionCode = trimmedPermissionCode.toLowerCase();
    if (
      !normalizedPermissionCode
      || CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)
      || !PLATFORM_PERMISSION_CODE_PATTERN.test(normalizedPermissionCode)
      || seenPermissionCodes.has(normalizedPermissionCode)
    ) {
      return null;
    }
    seenPermissionCodes.add(normalizedPermissionCode);
    normalizedPermissionCodes.push(normalizedPermissionCode);
  }
  return normalizedPermissionCodes;
};

const normalizeStrictPlatformPermissionCatalogItems = ({
  permissionCatalogItems,
  minCount = 0,
  maxCount = Number.POSITIVE_INFINITY
} = {}) => {
  if (!Array.isArray(permissionCatalogItems)) {
    return null;
  }
  if (
    permissionCatalogItems.length < minCount
    || permissionCatalogItems.length > maxCount
  ) {
    return null;
  }
  const normalizedItems = [];
  const seenPermissionCodes = new Set();
  for (const item of permissionCatalogItems) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      return null;
    }
    const rawCode = String(item.code || '').trim();
    if (!rawCode || rawCode !== String(item.code || '')) {
      return null;
    }
    const normalizedCode = rawCode.toLowerCase();
    if (
      !PLATFORM_PERMISSION_CODE_PATTERN.test(normalizedCode)
      || CONTROL_CHAR_PATTERN.test(normalizedCode)
      || seenPermissionCodes.has(normalizedCode)
    ) {
      return null;
    }
    const rawScope = String(item.scope || PLATFORM_ROLE_SCOPE).trim().toLowerCase();
    if (rawScope !== PLATFORM_ROLE_SCOPE) {
      return null;
    }
    const groupKey = String(item.group_key || '').trim();
    const actionKey = String(item.action_key || '').trim();
    const labelKey = String(item.label_key || '').trim();
    if (
      CONTROL_CHAR_PATTERN.test(groupKey)
      || CONTROL_CHAR_PATTERN.test(actionKey)
      || CONTROL_CHAR_PATTERN.test(labelKey)
    ) {
      return null;
    }
    const hasOrderField = Object.prototype.hasOwnProperty.call(item, 'order');
    const order = hasOrderField ? item.order : 0;
    if (
      (hasOrderField && (typeof order !== 'number' || !Number.isFinite(order)))
      || !Number.isInteger(Number(order))
    ) {
      return null;
    }
    seenPermissionCodes.add(normalizedCode);
    normalizedItems.push({
      code: normalizedCode,
      scope: PLATFORM_ROLE_SCOPE,
      group_key: groupKey,
      action_key: actionKey,
      label_key: labelKey,
      order: Number(order)
    });
  }
  return normalizedItems;
};

const sortPermissionCatalogItems = (items = []) =>
  [...items].sort((left, right) => {
    const leftOrder = Number(left?.order || 0);
    const rightOrder = Number(right?.order || 0);
    if (leftOrder !== rightOrder) {
      return leftOrder - rightOrder;
    }
    return String(left?.code || '').localeCompare(String(right?.code || ''));
  });

const normalizeNonNegativeInteger = (value) => {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    return null;
  }
  return value;
};

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

    if (!Array.isArray(roles)) {
      addAuditEvent({
        type: 'platform.role.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        detail: 'platform role catalog returned non-array payload',
        metadata: {
          error_code: 'ROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw roleErrors.dependencyUnavailable();
    }
    const rawRoles = roles;
    const mappedRoles = rawRoles
      .map((role) => mapRoleCatalogEntry(role, resolvedRequestId));
    const malformedRoleIndex = mappedRoles.findIndex(
      (role, index) =>
        !isValidRoleCatalogEntry({
          role,
          rawRole: rawRoles[index]
        })
    );
    if (malformedRoleIndex !== -1) {
      addAuditEvent({
        type: 'platform.role.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: mappedRoles[malformedRoleIndex]?.role_id || null,
        detail: 'platform role catalog returned malformed record',
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
        total: mappedRoles.length
      }
    });
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
    assertAuthServiceMethod('listPlatformPermissionCatalogEntries');
    let availablePermissionCatalogItems;
    let availablePermissionCodes;
    try {
      availablePermissionCatalogItems = normalizeStrictPlatformPermissionCatalogItems({
        permissionCatalogItems: authService.listPlatformPermissionCatalogEntries(),
        minCount: 0,
        maxCount: Number.POSITIVE_INFINITY
      });
      availablePermissionCodes = normalizeStrictPlatformPermissionCodes({
        permissionCodes: Array.isArray(availablePermissionCatalogItems)
          ? availablePermissionCatalogItems.map((item) => item.code)
          : null,
        minCount: 0,
        maxCount: Number.POSITIVE_INFINITY
      });
      if (!availablePermissionCatalogItems || !availablePermissionCodes) {
        throw roleErrors.dependencyUnavailable();
      }
    } catch (_error) {
      addAuditEvent({
        type: 'platform.role.permissions.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'platform permission catalog dependency unavailable',
        metadata: {
          error_code: 'ROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw roleErrors.dependencyUnavailable();
    }
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

    const rawResultRoleId =
      Object.prototype.hasOwnProperty.call(grants || {}, 'role_id')
        ? grants?.role_id
        : grants?.roleId;
    const normalizedResultRoleId = normalizeRoleId(
      normalizeStrictRequiredString(rawResultRoleId)
    );
    const normalizedPermissionCodes = normalizeStrictPlatformPermissionCodes({
      permissionCodes: Array.isArray(grants?.permission_codes)
        ? grants.permission_codes
        : grants?.permissionCodes,
      minCount: 0,
      maxCount: Number.POSITIVE_INFINITY
    });
    const normalizedAvailablePermissionCodes = normalizeStrictPlatformPermissionCodes({
      permissionCodes: Array.isArray(grants?.available_permission_codes)
        ? grants.available_permission_codes
        : grants?.availablePermissionCodes,
      minCount: 0,
      maxCount: Number.POSITIVE_INFINITY
    });
    const normalizedAvailablePermissions = normalizeStrictPlatformPermissionCatalogItems({
      permissionCatalogItems: Array.isArray(grants?.available_permissions)
        ? grants.available_permissions
        : grants?.availablePermissions,
      minCount: 0,
      maxCount: Number.POSITIVE_INFINITY
    });
    const normalizedAvailablePermissionCodesFromMetadata =
      normalizeStrictPlatformPermissionCodes({
        permissionCodes: Array.isArray(normalizedAvailablePermissions)
          ? normalizedAvailablePermissions.map((item) => item.code)
          : null,
        minCount: 0,
        maxCount: Number.POSITIVE_INFINITY
      });
    const catalogPermissionSet = new Set(availablePermissionCodes || []);
    const hasUnknownAvailablePermission = Array.isArray(normalizedAvailablePermissionCodes)
      && normalizedAvailablePermissionCodes.some((permissionCode) =>
        !catalogPermissionSet.has(permissionCode)
      );
    const availablePermissionSet = new Set(normalizedAvailablePermissionCodes || []);
    const hasUnsupportedGrantedPermission = Array.isArray(normalizedPermissionCodes)
      && normalizedPermissionCodes.some((permissionCode) =>
        !availablePermissionSet.has(permissionCode)
      );
    const sortedAvailablePermissionCodes = [...(normalizedAvailablePermissionCodes || [])]
      .sort((left, right) => left.localeCompare(right));
    const sortedAvailablePermissionCodesFromMetadata =
      [...(normalizedAvailablePermissionCodesFromMetadata || [])]
        .sort((left, right) => left.localeCompare(right));
    const hasAvailablePermissionMetadataMismatch = (
      sortedAvailablePermissionCodes.length !== sortedAvailablePermissionCodesFromMetadata.length
      || sortedAvailablePermissionCodes.some(
        (permissionCode, index) =>
          permissionCode !== sortedAvailablePermissionCodesFromMetadata[index]
      )
    );
    if (
      !availablePermissionCodes
      || !availablePermissionCatalogItems
      || normalizedResultRoleId !== normalizedRoleId
      || !normalizedPermissionCodes
      || !normalizedAvailablePermissionCodes
      || !normalizedAvailablePermissions
      || !normalizedAvailablePermissionCodesFromMetadata
      || hasUnknownAvailablePermission
      || hasUnsupportedGrantedPermission
      || hasAvailablePermissionMetadataMismatch
    ) {
      addAuditEvent({
        type: 'platform.role.permissions.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'platform role permission grants read returned malformed payload',
        metadata: {
          error_code: 'ROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw roleErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'platform.role.permissions.read.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetRoleId: normalizedRoleId,
      detail: 'platform role permission grants listed',
      metadata: {
        permission_codes_count: normalizedPermissionCodes.length
      }
    });

    const resolvedSortedPermissionCodes = [...normalizedPermissionCodes]
      .sort((left, right) => left.localeCompare(right));
    const resolvedSortedAvailablePermissionCodes = [...normalizedAvailablePermissionCodes]
      .sort((left, right) => left.localeCompare(right));
    const resolvedSortedAvailablePermissions = sortPermissionCatalogItems(
      normalizedAvailablePermissions
    );

    return {
      role_id: normalizedRoleId,
      permission_codes: resolvedSortedPermissionCodes,
      available_permission_codes: resolvedSortedAvailablePermissionCodes,
      available_permissions: resolvedSortedAvailablePermissions,
      request_id: resolvedRequestId
    };
  };

  const replaceRolePermissions = async ({
    requestId,
    accessToken,
    roleId,
    payload = {},
    traceparent = null,
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
    assertAuthServiceMethod('listPlatformPermissionCatalogEntries');

    let availablePermissionCatalogItems;
    let availablePermissionCodes;
    try {
      availablePermissionCatalogItems = normalizeStrictPlatformPermissionCatalogItems({
        permissionCatalogItems: authService.listPlatformPermissionCatalogEntries(),
        minCount: 0,
        maxCount: Number.POSITIVE_INFINITY
      });
      availablePermissionCodes = normalizeStrictPlatformPermissionCodes({
        permissionCodes: Array.isArray(availablePermissionCatalogItems)
          ? availablePermissionCatalogItems.map((item) => item.code)
          : null,
        minCount: 0,
        maxCount: Number.POSITIVE_INFINITY
      });
      if (!availablePermissionCatalogItems || !availablePermissionCodes) {
        throw roleErrors.dependencyUnavailable();
      }
    } catch (_error) {
      addAuditEvent({
        type: 'platform.role.permissions.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'platform permission catalog dependency unavailable',
        metadata: {
          error_code: 'ROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw roleErrors.dependencyUnavailable();
    }
    if (!Array.isArray(availablePermissionCodes)) {
      addAuditEvent({
        type: 'platform.role.permissions.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'platform permission catalog dependency unavailable',
        metadata: {
          error_code: 'ROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw roleErrors.dependencyUnavailable();
    }
    const availablePermissionSet = new Set(availablePermissionCodes);
    const hasUnsupportedRequestedPermission = parsedPayload.permissionCodes.some(
      (permissionCode) => !availablePermissionSet.has(permissionCode)
    );
    if (hasUnsupportedRequestedPermission) {
      addAuditEvent({
        type: 'platform.role.permissions.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'payload validation failed',
        metadata: {
          error_code: 'ROLE-400-INVALID-PAYLOAD'
        }
      });
      throw roleErrors.invalidPayload('permission_codes 包含未注册权限码');
    }

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
        traceparent,
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

    const rawResultRoleId =
      Object.prototype.hasOwnProperty.call(updated || {}, 'role_id')
        ? updated?.role_id
        : updated?.roleId;
    const normalizedResultRoleId = normalizeRoleId(
      normalizeStrictRequiredString(rawResultRoleId)
    );
    const normalizedPermissionCodes = normalizeStrictPlatformPermissionCodes({
      permissionCodes: Array.isArray(updated?.permission_codes)
        ? updated.permission_codes
        : updated?.permissionCodes,
      minCount: 0,
      maxCount: MAX_PERMISSION_CODES_PAYLOAD_LENGTH
    });
    const normalizedAffectedUserCount = normalizeNonNegativeInteger(
      updated?.affected_user_count ?? updated?.affectedUserCount
    );
    const expectedPermissionCodes = [...parsedPayload.permissionCodes]
      .map((permissionCode) => permissionCode.toLowerCase())
      .sort((left, right) => left.localeCompare(right));
    const resolvedPermissionCodes = [...(normalizedPermissionCodes || [])]
      .sort((left, right) => left.localeCompare(right));
    const hasUnsupportedGrantedPermission = Array.isArray(normalizedPermissionCodes)
      && normalizedPermissionCodes.some((permissionCode) =>
        !availablePermissionSet.has(permissionCode)
      );
    const hasPermissionCodeMismatch = (
      expectedPermissionCodes.length !== resolvedPermissionCodes.length
      || expectedPermissionCodes.some(
        (permissionCode, index) => permissionCode !== resolvedPermissionCodes[index]
      )
    );
    if (
      !availablePermissionCodes
      || !availablePermissionCatalogItems
      || normalizedResultRoleId !== normalizedRoleId
      || !normalizedPermissionCodes
      || normalizedAffectedUserCount === null
      || hasUnsupportedGrantedPermission
      || hasPermissionCodeMismatch
    ) {
      addAuditEvent({
        type: 'platform.role.permissions.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'platform role permission grants update returned malformed payload',
        metadata: {
          error_code: 'ROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw roleErrors.dependencyUnavailable();
    }
    addAuditEvent({
      type: 'platform.role.permissions.update.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetRoleId: normalizedRoleId,
      detail: 'platform role permission grants replaced',
      metadata: {
        permission_codes_count: normalizedPermissionCodes.length,
        affected_user_count: normalizedAffectedUserCount
      }
    });

    const resolvedSortedPermissionCodes = [...normalizedPermissionCodes]
      .sort((left, right) => left.localeCompare(right));
    const resolvedSortedAvailablePermissionCodes = [...availablePermissionCodes]
      .sort((left, right) => left.localeCompare(right));
    const resolvedSortedAvailablePermissions = sortPermissionCatalogItems(
      availablePermissionCatalogItems
    );

    return {
      role_id: normalizedRoleId,
      permission_codes: resolvedSortedPermissionCodes,
      available_permission_codes: resolvedSortedAvailablePermissionCodes,
      available_permissions: resolvedSortedAvailablePermissions,
      affected_user_count: normalizedAffectedUserCount,
      request_id: resolvedRequestId
    };
  };

  const createRole = async ({
    requestId,
    accessToken,
    payload = {},
    traceparent = null,
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
    let createPayload = {
      ...parsedPayload
    };
    try {
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          createdRole = await authService.createPlatformRoleCatalogEntry({
            requestId: resolvedRequestId,
            traceparent,
            roleId: createPayload.roleId,
            code: createPayload.code,
            name: createPayload.name,
            status: createPayload.status,
            scope: createPayload.scope,
            isSystem: createPayload.isSystem,
            operatorUserId: operatorContext.operatorUserId,
            operatorSessionId: operatorContext.operatorSessionId
          });
          break;
        } catch (error) {
          const duplicateConflictTarget = resolveDuplicateRoleConflictTarget(error);
          const shouldRetryGeneratedRoleId = (
            isDuplicateEntryError(error)
            && duplicateConflictTarget === 'role_id'
            && createPayload.roleIdAutoGenerated === true
            && attempt < 2
          );
          if (!shouldRetryGeneratedRoleId) {
            throw error;
          }
          createPayload = {
            ...createPayload,
            roleId: createSystemGeneratedRoleId(),
            roleIdAutoGenerated: true
          };
        }
      }
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
        targetRoleId: createPayload.roleId,
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
    if (!isValidRoleCatalogEntry({
      role: mappedRole,
      rawRole: createdRole
    }) || !isExpectedMutationTarget({
      role: mappedRole,
      expectedRoleId: createPayload.roleId
    }) || mappedRole.is_system !== false) {
      addAuditEvent({
        type: 'platform.role.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: mappedRole.role_id || createPayload.roleId,
        detail: 'platform role creation returned malformed catalog record',
        metadata: {
          error_code: 'ROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw roleErrors.dependencyUnavailable();
    }
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
    traceparent = null,
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
        requestId: resolvedRequestId,
        traceparent,
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
    if (!isValidRoleCatalogEntry({
      role: mappedRole,
      rawRole: updatedRole
    }) || !isExpectedMutationTarget({
      role: mappedRole,
      expectedRoleId: normalizedRoleId
    }) || mappedRole.is_system !== false) {
      addAuditEvent({
        type: 'platform.role.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'platform role update returned malformed catalog record',
        metadata: {
          error_code: 'ROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw roleErrors.dependencyUnavailable();
    }
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
    traceparent = null,
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
        requestId: resolvedRequestId,
        traceparent,
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
    if (!isValidRoleCatalogEntry({
      role: mappedRole,
      rawRole: deletedRole
    }) || !isExpectedMutationTarget({
      role: mappedRole,
      expectedRoleId: normalizedRoleId
    }) || mappedRole.is_system !== false || mappedRole.status !== 'disabled') {
      addAuditEvent({
        type: 'platform.role.delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetRoleId: normalizedRoleId,
        detail: 'platform role delete returned malformed catalog record',
        metadata: {
          error_code: 'ROLE-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw roleErrors.dependencyUnavailable();
    }
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

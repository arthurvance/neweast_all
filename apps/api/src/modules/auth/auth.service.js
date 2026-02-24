const { AsyncLocalStorage } = require('node:async_hooks');
const { createHash, createDecipheriv, generateKeyPairSync, pbkdf2Sync, randomBytes, randomUUID, randomInt, timingSafeEqual, createSign, createVerify } = require('node:crypto');
const { log } = require('../../common/logger');
const { normalizeTraceparent } = require('../../common/trace-context');
const { createInMemoryAuthStore } = require('./auth.store.memory');
const {
  TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
  TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
  PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
  PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
  ROLE_MANAGEMENT_PERMISSION_CODE_KEY_SET,
  TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT,
  ROUTE_PERMISSION_EVALUATORS,
  ROUTE_PERMISSION_SCOPE_RULES,
  listSupportedRoutePermissionCodes,
  listSupportedRoutePermissionScopes,
  listSupportedPlatformPermissionCodes,
  listSupportedTenantPermissionCodes,
  listPlatformPermissionCatalogItems,
  listTenantPermissionCatalogItems,
  toPlatformPermissionSnapshotFromCodes,
  toTenantPermissionSnapshotFromCodes
} = require('./permission-catalog');
const { createAuthSessionService } = require('./session-service');
const { createTenantContextService } = require('./tenant-context-service');
const { createPermissionContextBuilder } = require('./permission-context-builder');
const { createEntryPolicyService } = require('./entry-policy-service');
const { createLoginService } = require('./login-service');
const { createAuthRepositories } = require('./repositories');

const ACCESS_TTL_SECONDS = 15 * 60;
const REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60;
const OTP_TTL_SECONDS = 15 * 60;
const OTP_CODE_LENGTH = 6;
const RATE_LIMIT_WINDOW_SECONDS = 60;
const RATE_LIMIT_MAX_ATTEMPTS = 10;
const OTP_RESEND_COOLDOWN_SECONDS = 60;
const PASSWORD_MIN_LENGTH = 6;
const PBKDF2_ITERATIONS = 150000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';
const ACCESS_SESSION_CACHE_TTL_MS = 800;
const VALID_PLATFORM_ROLE_FACT_STATUS = new Set(['active', 'enabled', 'disabled']);
const VALID_PLATFORM_ROLE_CATALOG_STATUS = new Set(['active', 'enabled', 'disabled']);
const VALID_PLATFORM_ROLE_CATALOG_SCOPE = new Set(['platform', 'tenant']);
const VALID_ORG_STATUS = new Set(['active', 'disabled']);
const VALID_PLATFORM_USER_STATUS = new Set(['active', 'disabled']);
const MAX_PLATFORM_ROLE_FACTS_PER_USER = 5;
const MAX_PLATFORM_ROLE_ID_LENGTH = 64;
const MAX_PLATFORM_USER_ID_LENGTH = 64;
const MAX_ROLE_PERMISSION_CODES_PER_REQUEST = 64;
const MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS = 100;
const MAX_TENANT_NAME_LENGTH = 128;
const MAX_OWNER_TRANSFER_ORG_ID_LENGTH = 64;
const MAX_OWNER_TRANSFER_REASON_LENGTH = 256;
const MAX_ORG_STATUS_CASCADE_COUNT = 100000;
const OWNER_TRANSFER_TAKEOVER_ROLE_ID_PREFIX = 'sys_admin__';
const OWNER_TRANSFER_TAKEOVER_ROLE_ID_DIGEST_LENGTH = 24;
const OWNER_TRANSFER_TAKEOVER_ROLE_CODE = 'sys_admin';
const OWNER_TRANSFER_TAKEOVER_ROLE_NAME = '管理员';
const OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES = Object.freeze([
  TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
  TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
]);
const MAX_AUTH_AUDIT_TRAIL_ENTRIES = 2000;
const AUDIT_EVENT_ALLOWED_DOMAINS = new Set(['platform', 'tenant']);
const AUDIT_EVENT_ALLOWED_RESULTS = new Set(['success', 'rejected', 'failed']);
const AUDIT_EVENT_REDACTION_KEY_PATTERN =
  /(password|token|secret|credential|private[_-]?key|access[_-]?key|api[_-]?key|signing[_-]?key)/i;
const MAX_AUDIT_QUERY_PAGE_SIZE = 200;
const MAX_TENANT_MEMBERSHIP_ID_LENGTH = 64;
const MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS = 5;
const MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH = 64;
const MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH = 128;
const MYSQL_DUP_ENTRY_ERRNO = 1062;
const MYSQL_DATA_TOO_LONG_ERRNO = 1406;
const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const WHITESPACE_PATTERN = /\s/;
const TENANT_MEMBERSHIP_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const ROLE_ID_ADDRESSABLE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const DEFAULT_PASSWORD_CONFIG_KEY = 'auth.default_password';
const SENSITIVE_CONFIG_ENVELOPE_VERSION = 'enc:v1';
const SENSITIVE_CONFIG_KEY_DERIVATION_ITERATIONS = 210000;
const SENSITIVE_CONFIG_KEY_DERIVATION_SALT = DEFAULT_PASSWORD_CONFIG_KEY;
const SUPPORTED_SYSTEM_SENSITIVE_CONFIG_KEYS = new Set([DEFAULT_PASSWORD_CONFIG_KEY]);
const VALID_SYSTEM_SENSITIVE_CONFIG_STATUS = new Set(['active', 'disabled']);
const REJECTED_SYSTEM_CONFIG_AUDIT_EVENT_TYPES = new Set([
  'auth.system_config.read.rejected',
  'auth.system_config.update.rejected'
]);
const PLATFORM_ROLE_FACTS_REPLACE_PERMISSION_CODE = PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE;
const PLATFORM_ROLE_CATALOG_SCOPE = 'platform';
const TENANT_ROLE_SCOPE = 'tenant';
const PLATFORM_ROLE_PERMISSION_FIELD_KEYS = Object.freeze([
  'canViewUserManagement',
  'can_view_user_management',
  'canOperateUserManagement',
  'can_operate_user_management',
  'canViewTenantManagement',
  'can_view_tenant_management',
  'canOperateTenantManagement',
  'can_operate_tenant_management',
  'canViewRoleManagement',
  'can_view_role_management',
  'canOperateRoleManagement',
  'can_operate_role_management'
]);
const PLATFORM_ROLE_ASSIGNMENT_ALLOWED_FIELDS = new Set([
  'role_id',
  'roleId',
  'status'
]);
const UNSET_EXPECTED_TENANT_MEMBER_PROFILE_FIELD = Symbol(
  'unsetExpectedTenantMemberProfileField'
);

const DEFAULT_SEED_USERS = [];
const hasOwnProperty = (target, key) =>
  target !== null
  && typeof target === 'object'
  && Object.prototype.hasOwnProperty.call(target, key);
const isPlainObject = (value) =>
  value !== null
  && typeof value === 'object'
  && !Array.isArray(value);
const normalizePlatformRoleIdKey = (roleId) =>
  String(roleId || '').trim().toLowerCase();
const normalizePlatformRoleCatalogStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  return normalizedStatus;
};
const normalizePlatformRoleCatalogScope = (scope) =>
  String(scope || '').trim().toLowerCase();
const normalizeRequiredStringField = (candidate, errorFactory) => {
  if (typeof candidate !== 'string') {
    throw errorFactory();
  }
  const normalized = candidate.trim();
  if (!normalized) {
    throw errorFactory();
  }
  return normalized;
};
const normalizeStrictRequiredStringField = (candidate) => {
  if (typeof candidate !== 'string') {
    return '';
  }
  const normalized = candidate.trim();
  if (!normalized || candidate !== normalized) {
    return '';
  }
  return normalized;
};
const normalizeAuditDomain = (domain) => {
  const normalized = String(domain || '').trim().toLowerCase();
  return AUDIT_EVENT_ALLOWED_DOMAINS.has(normalized) ? normalized : '';
};
const normalizeAuditResult = (result) => {
  const normalized = String(result || '').trim().toLowerCase();
  return AUDIT_EVENT_ALLOWED_RESULTS.has(normalized) ? normalized : '';
};
const normalizeAuditStringOrNull = (value, maxLength = 256) => {
  if (value === null || value === undefined) {
    return null;
  }
  const normalized = String(value).trim();
  if (!normalized || normalized.length > maxLength) {
    return null;
  }
  return normalized;
};
const normalizeAuditTraceparentOrNull = (value) => {
  const normalized = normalizeAuditStringOrNull(value, 128);
  if (!normalized) {
    return null;
  }
  return normalizeTraceparent(normalized);
};
const normalizeAuditOccurredAt = (value) => {
  if (value === null || value === undefined) {
    return new Date().toISOString();
  }
  const asDate = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(asDate.getTime())) {
    return new Date().toISOString();
  }
  return asDate.toISOString();
};
const parseAuditQueryTimestamp = (value) => {
  if (value === null || value === undefined) {
    return {
      valid: true,
      value: null
    };
  }
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      return {
        valid: false,
        value: null
      };
    }
    return {
      valid: true,
      value: value.toISOString()
    };
  }
  if (typeof value !== 'string') {
    return {
      valid: false,
      value: null
    };
  }
  const normalizedValue = value.trim();
  if (
    !normalizedValue
    || normalizedValue !== value
    || CONTROL_CHAR_PATTERN.test(normalizedValue)
  ) {
    return {
      valid: false,
      value: null
    };
  }
  const parsedDate = new Date(normalizedValue);
  if (Number.isNaN(parsedDate.getTime())) {
    return {
      valid: false,
      value: null
    };
  }
  return {
    valid: true,
    value: parsedDate.toISOString()
  };
};
const sanitizeAuditState = (value, depth = 0) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (depth > 8) {
    return null;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeAuditState(item, depth + 1));
  }
  if (typeof value === 'object') {
    const sanitized = {};
    for (const [key, itemValue] of Object.entries(value)) {
      if (AUDIT_EVENT_REDACTION_KEY_PATTERN.test(String(key))) {
        sanitized[key] = '[REDACTED]';
        continue;
      }
      sanitized[key] = sanitizeAuditState(itemValue, depth + 1);
    }
    return sanitized;
  }
  return value;
};
const resolveRawCamelSnakeField = (
  source,
  camelCaseKey,
  snakeCaseKey
) => {
  if (!source || typeof source !== 'object') {
    return undefined;
  }
  const hasCamelCaseKey = hasOwnProperty(source, camelCaseKey);
  const hasSnakeCaseKey = hasOwnProperty(source, snakeCaseKey);

  if (hasCamelCaseKey) {
    const camelCaseValue = source[camelCaseKey];
    if (camelCaseValue !== undefined && camelCaseValue !== null) {
      return camelCaseValue;
    }
  }
  if (hasSnakeCaseKey) {
    const snakeCaseValue = source[snakeCaseKey];
    if (snakeCaseValue !== undefined && snakeCaseValue !== null) {
      return snakeCaseValue;
    }
  }
  if (hasCamelCaseKey) {
    return source[camelCaseKey];
  }
  if (hasSnakeCaseKey) {
    return source[snakeCaseKey];
  }
  return undefined;
};
const resolveRawRoleIdCandidate = (role) =>
  resolveRawCamelSnakeField(role, 'roleId', 'role_id');
const isDuplicateRoleFactEntryError = (error) =>
  String(error?.code || '').trim().toUpperCase() === 'ER_DUP_ENTRY'
  || Number(error?.errno || 0) === MYSQL_DUP_ENTRY_ERRNO;
const isDataTooLongRoleFactError = (error) =>
  String(error?.code || '').trim().toUpperCase() === 'ER_DATA_TOO_LONG'
  || Number(error?.errno || 0) === MYSQL_DATA_TOO_LONG_ERRNO;
const isMissingTableError = (error) =>
  String(error?.code || '').trim().toUpperCase() === 'ER_NO_SUCH_TABLE'
  || Number(error?.errno || 0) === 1146;
const isMissingPlatformRoleCatalogTableError = (error) =>
  isMissingTableError(error)
  && /platform_roles/i.test(String(error?.message || ''));
const assertOptionalBooleanRolePermission = (candidate, errorFactory) => {
  if (candidate === undefined) {
    return;
  }
  if (typeof candidate !== 'boolean') {
    throw errorFactory();
  }
};
const hasTopLevelPlatformRolePermissionField = (role) =>
  PLATFORM_ROLE_PERMISSION_FIELD_KEYS.some((field) =>
    hasOwnProperty(role, field)
  );
const normalizePlatformPermissionCode = (permissionCode) =>
  String(permissionCode || '').trim();
const toPlatformPermissionCodeKey = (permissionCode) =>
  normalizePlatformPermissionCode(permissionCode).toLowerCase();
const isPlatformPermissionCode = (permissionCode) =>
  String(permissionCode || '').trim().startsWith('platform.');
const isTenantPermissionCode = (permissionCode) =>
  String(permissionCode || '').trim().startsWith('tenant.');
const SUPPORTED_PLATFORM_PERMISSION_CODE_SET = new Set(
  listSupportedPlatformPermissionCodes().map((permissionCode) =>
    toPlatformPermissionCodeKey(permissionCode)
  )
);
const normalizeTenantPermissionCode = (permissionCode) =>
  String(permissionCode || '').trim();
const toTenantPermissionCodeKey = (permissionCode) =>
  normalizeTenantPermissionCode(permissionCode).toLowerCase();
const SUPPORTED_TENANT_PERMISSION_CODE_SET = new Set(
  listSupportedTenantPermissionCodes().map((permissionCode) =>
    toTenantPermissionCodeKey(permissionCode)
  )
);
const normalizeSystemSensitiveConfigKey = (configKey) =>
  String(configKey || '').trim().toLowerCase();
const normalizeSystemSensitiveConfigStatus = (status) => {
  const normalizedStatus = String(status || 'active').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  return VALID_SYSTEM_SENSITIVE_CONFIG_STATUS.has(normalizedStatus)
    ? normalizedStatus
    : '';
};
const toSystemSensitiveConfigRecord = (record = null) => {
  if (!record || typeof record !== 'object') {
    return null;
  }
  const normalizedConfigKey = normalizeSystemSensitiveConfigKey(
    record.configKey ?? record.config_key
  );
  if (
    !normalizedConfigKey
    || !SUPPORTED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(normalizedConfigKey)
  ) {
    return null;
  }
  const normalizedStatus = normalizeSystemSensitiveConfigStatus(record.status || 'active');
  if (!normalizedStatus) {
    return null;
  }
  const normalizedVersion = Number(record.version || 0);
  if (!Number.isInteger(normalizedVersion) || normalizedVersion < 0) {
    return null;
  }
  const normalizedPreviousVersion = Number(
    record.previousVersion
    ?? record.previous_version
    ?? 0
  );
  if (
    !Number.isInteger(normalizedPreviousVersion)
    || normalizedPreviousVersion < 0
  ) {
    return null;
  }
  const normalizedEncryptedValue = String(
    record.encryptedValue ?? record.encrypted_value ?? ''
  ).trim();
  if (!normalizedEncryptedValue) {
    return null;
  }
  const normalizedUpdatedByUserId = normalizeStrictRequiredStringField(
    record.updatedByUserId ?? record.updated_by_user_id
  );
  if (!normalizedUpdatedByUserId) {
    return null;
  }
  const updatedAtRaw = record.updatedAt ?? record.updated_at;
  const createdAtRaw = record.createdAt ?? record.created_at;
  const normalizedUpdatedAt = normalizeStrictRequiredStringField(
    updatedAtRaw instanceof Date ? updatedAtRaw.toISOString() : updatedAtRaw
  );
  if (!normalizedUpdatedAt) {
    return null;
  }
  const normalizedCreatedAt = normalizeStrictRequiredStringField(
    createdAtRaw instanceof Date ? createdAtRaw.toISOString() : createdAtRaw
  );
  return {
    configKey: normalizedConfigKey,
    encryptedValue: normalizedEncryptedValue,
    version: normalizedVersion,
    previousVersion: normalizedPreviousVersion,
    status: normalizedStatus,
    updatedByUserId: normalizedUpdatedByUserId,
    updatedAt: normalizedUpdatedAt,
    createdByUserId: normalizeStrictRequiredStringField(
      record.createdByUserId ?? record.created_by_user_id
    ) || null,
    createdAt: normalizedCreatedAt || null
  };
};

class AuthProblemError extends Error {
  constructor({ status, title, detail, errorCode, extensions = {} }) {
    super(detail);
    this.name = 'AuthProblemError';
    this.status = status;
    this.title = title;
    this.detail = detail;
    this.errorCode = errorCode;
    this.extensions = extensions;
  }
}

const authError = ({ status, title, detail, errorCode, extensions = {} }) => new AuthProblemError({
  status,
  title,
  detail,
  errorCode,
  extensions
});

const errors = {
  invalidPayload: () =>
    authError({
      status: 400,
      title: 'Bad Request',
      detail: '请求参数不完整或格式错误',
      errorCode: 'AUTH-400-INVALID-PAYLOAD'
    }),

  loginFailed: () =>
    authError({
      status: 401,
      title: 'Unauthorized',
      detail: '手机号或密码错误',
      errorCode: 'AUTH-401-LOGIN-FAILED'
    }),

  invalidAccess: () =>
    authError({
      status: 401,
      title: 'Unauthorized',
      detail: '当前会话无效，请重新登录',
      errorCode: 'AUTH-401-INVALID-ACCESS'
    }),

  invalidRefresh: () =>
    authError({
      status: 401,
      title: 'Unauthorized',
      detail: '会话已失效，请重新登录',
      errorCode: 'AUTH-401-INVALID-REFRESH'
    }),

  otpFailed: () =>
    authError({
      status: 401,
      title: 'Unauthorized',
      detail: '验证码错误或已失效',
      errorCode: 'AUTH-401-OTP-FAILED'
    }),

  rateLimited: ({
    action,
    remainingSeconds,
    limit = RATE_LIMIT_MAX_ATTEMPTS,
    windowSeconds = RATE_LIMIT_WINDOW_SECONDS
  }) =>
    authError({
      status: 429,
      title: 'Too Many Requests',
      detail: '请求过于频繁，请稍后重试',
      errorCode: 'AUTH-429-RATE-LIMITED',
      extensions: {
        retryable: true,
        retry_after_seconds: remainingSeconds,
        rate_limit_action: action,
        rate_limit_limit: limit,
        rate_limit_window_seconds: windowSeconds
      }
    }),

  weakPassword: () =>
    authError({
      status: 400,
      title: 'Bad Request',
      detail: `新密码不满足策略，最小长度 ${PASSWORD_MIN_LENGTH}`,
      errorCode: 'AUTH-400-WEAK-PASSWORD'
    }),

  noDomainAccess: () =>
    authError({
      status: 403,
      title: 'Forbidden',
      detail: '当前入口无可用访问域权限',
      errorCode: 'AUTH-403-NO-DOMAIN'
    }),

  forbidden: () =>
    authError({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  orgNotFound: () =>
    authError({
      status: 404,
      title: 'Not Found',
      detail: '目标组织不存在',
      errorCode: 'AUTH-404-ORG-NOT-FOUND'
    }),

  userNotFound: ({ extensions = null } = {}) =>
    authError({
      status: 404,
      title: 'Not Found',
      detail: '目标用户不存在',
      errorCode: 'AUTH-404-USER-NOT-FOUND',
      extensions: isPlainObject(extensions) ? extensions : {}
    }),

  ownerTransferOrgNotActive: ({
    orgId = null,
    oldOwnerUserId = null
  } = {}) =>
    authError({
      status: 409,
      title: 'Conflict',
      detail: '目标组织当前不可发起负责人变更，请先启用后重试',
      errorCode: 'AUTH-409-ORG-NOT-ACTIVE',
      extensions: {
        org_id: orgId ? String(orgId).trim() : null,
        old_owner_user_id: oldOwnerUserId ? String(oldOwnerUserId).trim() : null
      }
    }),

  ownerTransferTargetUserInactive: ({
    orgId = null,
    oldOwnerUserId = null,
    newOwnerUserId = null
  } = {}) =>
    authError({
      status: 409,
      title: 'Conflict',
      detail: '候选新负责人状态不可用',
      errorCode: 'AUTH-409-OWNER-TRANSFER-TARGET-USER-INACTIVE',
      extensions: {
        org_id: orgId ? String(orgId).trim() : null,
        old_owner_user_id: oldOwnerUserId ? String(oldOwnerUserId).trim() : null,
        new_owner_user_id: newOwnerUserId ? String(newOwnerUserId).trim() : null
      }
    }),

  ownerTransferSameOwner: ({
    orgId = null,
    oldOwnerUserId = null
  } = {}) =>
    authError({
      status: 409,
      title: 'Conflict',
      detail: '新负责人不能与当前负责人相同',
      errorCode: 'AUTH-409-OWNER-TRANSFER-SAME-OWNER',
      extensions: {
        org_id: orgId ? String(orgId).trim() : null,
        old_owner_user_id: oldOwnerUserId ? String(oldOwnerUserId).trim() : null,
        new_owner_user_id: oldOwnerUserId ? String(oldOwnerUserId).trim() : null
      }
    }),

  ownerTransferConflict: ({
    orgId = null,
    oldOwnerUserId = null,
    newOwnerUserId = null
  } = {}) =>
    authError({
      status: 409,
      title: 'Conflict',
      detail: 'sys_admin 变更请求处理中，请稍后重试',
      errorCode: 'AUTH-409-OWNER-TRANSFER-CONFLICT',
      extensions: {
        org_id: orgId ? String(orgId).trim() : null,
        old_owner_user_id: oldOwnerUserId ? String(oldOwnerUserId).trim() : null,
        new_owner_user_id: newOwnerUserId ? String(newOwnerUserId).trim() : null
      }
    }),

  roleNotFound: () =>
    authError({
      status: 404,
      title: 'Not Found',
      detail: '目标平台角色不存在',
      errorCode: 'AUTH-404-ROLE-NOT-FOUND'
    }),

  platformSnapshotDegraded: ({ reason = 'db-deadlock' } = {}) =>
    authError({
      status: 503,
      title: 'Service Unavailable',
      detail: '平台权限同步暂时不可用，请稍后重试',
      errorCode: 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED',
      extensions: {
        retryable: true,
        degradation_reason: String(reason || 'unknown')
      }
    }),

  provisioningConfigUnavailable: () =>
    authError({
      status: 503,
      title: 'Service Unavailable',
      detail: '默认密码配置不可用，请稍后重试',
      errorCode: 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: 'default-password-config-unavailable'
      }
    }),

  ownerTransferLockUnavailable: () =>
    authError({
      status: 503,
      title: 'Service Unavailable',
      detail: '负责人变更锁服务暂不可用，请稍后重试',
      errorCode: 'AUTH-503-OWNER-TRANSFER-LOCK-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: 'owner-transfer-lock-unavailable'
      }
    }),

  provisionConflict: () =>
    authError({
      status: 409,
      title: 'Conflict',
      detail: '用户关系已存在，请勿重复提交',
      errorCode: 'AUTH-409-PROVISION-CONFLICT'
    }),

  tenantMembershipNotFound: () =>
    authError({
      status: 404,
      title: 'Not Found',
      detail: '目标成员关系不存在',
      errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  tenantMemberDependencyUnavailable: ({ reason = 'dependency-unavailable' } = {}) =>
    authError({
      status: 503,
      title: 'Service Unavailable',
      detail: '组织成员治理依赖暂不可用，请稍后重试',
      errorCode: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: String(reason || 'dependency-unavailable').trim()
      }
    }),

  auditDependencyUnavailable: ({ reason = 'audit-dependency-unavailable' } = {}) =>
    authError({
      status: 503,
      title: 'Service Unavailable',
      detail: '审计依赖暂不可用，请稍后重试',
      errorCode: 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: String(reason || 'audit-dependency-unavailable').trim()
      }
    })
};

const toBase64Url = (input) => {
  const raw = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return raw.toString('base64url');
};

const fromBase64Url = (input) => Buffer.from(input, 'base64url');
const deriveLegacySensitiveConfigKey = (rawKey) => {
  const normalizedRawKey = typeof rawKey === 'string' ? rawKey.trim() : '';
  if (!normalizedRawKey) {
    return null;
  }
  if (/^[0-9a-f]{64}$/i.test(normalizedRawKey)) {
    return Buffer.from(normalizedRawKey, 'hex');
  }
  return createHash('sha256').update(normalizedRawKey).digest();
};
const derivePrimarySensitiveConfigKey = (rawKey) => {
  const normalizedRawKey = typeof rawKey === 'string' ? rawKey.trim() : '';
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
const deriveSensitiveConfigKeys = (rawKey) => {
  const derivedKeys = [];
  const primaryKey = derivePrimarySensitiveConfigKey(rawKey);
  const legacyKey = deriveLegacySensitiveConfigKey(rawKey);
  if (primaryKey) {
    derivedKeys.push(primaryKey);
  }
  if (
    legacyKey
    && !derivedKeys.some((candidate) => Buffer.compare(candidate, legacyKey) === 0)
  ) {
    derivedKeys.push(legacyKey);
  }
  return derivedKeys;
};
const decryptSensitiveConfigValue = ({
  encryptedValue,
  decryptionKey,
  decryptionKeys = null
}) => {
  const envelope = String(encryptedValue || '').trim();
  const keys = Array.isArray(decryptionKeys)
    ? decryptionKeys.filter((key) => Buffer.isBuffer(key))
    : deriveSensitiveConfigKeys(decryptionKey);
  if (!envelope || keys.length === 0) {
    throw new Error('sensitive-config-unavailable');
  }
  const envelopeSections = envelope.split(':');
  if (
    envelopeSections.length !== 5
    || `${envelopeSections[0]}:${envelopeSections[1]}` !== SENSITIVE_CONFIG_ENVELOPE_VERSION
  ) {
    throw new Error('sensitive-config-format-invalid');
  }
  const iv = Buffer.from(envelopeSections[2], 'base64url');
  const authTag = Buffer.from(envelopeSections[3], 'base64url');
  const ciphertext = Buffer.from(envelopeSections[4], 'base64url');
  if (iv.length !== 12 || authTag.length !== 16 || ciphertext.length === 0) {
    throw new Error('sensitive-config-envelope-invalid');
  }
  let decryptError = null;
  for (const key of keys) {
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);
      const plainText = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
      ]).toString('utf8');
      if (!plainText) {
        throw new Error('sensitive-config-plaintext-empty');
      }
      return plainText;
    } catch (error) {
      decryptError = error;
    }
  }
  if (decryptError?.message === 'sensitive-config-plaintext-empty') {
    throw decryptError;
  }
  throw new Error('sensitive-config-decrypt-failed');
};
const resolveProvisioningConfigFailureReason = (error) => {
  if (error instanceof AuthProblemError && error.errorCode === 'AUTH-400-WEAK-PASSWORD') {
    return 'decrypted-password-policy-violation';
  }
  const message = String(error?.message || '').trim();
  if (message === 'sensitive-config-unavailable') {
    return 'encrypted-config-missing-or-key-missing';
  }
  if (message === 'sensitive-config-format-invalid' || message === 'sensitive-config-envelope-invalid') {
    return 'encrypted-config-format-invalid';
  }
  if (message === 'sensitive-config-plaintext-empty') {
    return 'decrypted-password-empty';
  }
  return 'encrypted-config-decrypt-failed';
};

const signJwt = ({ payload, privateKeyPem, ttlSeconds }) => {
  const header = {
    alg: 'RS256',
    typ: 'JWT'
  };

  const nowSeconds = Math.floor(Date.now() / 1000);
  const normalizedPayload = {
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds,
    ...payload
  };

  const encodedHeader = toBase64Url(JSON.stringify(header));
  const encodedPayload = toBase64Url(JSON.stringify(normalizedPayload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();

  const signature = signer.sign(privateKeyPem);
  const encodedSignature = signature.toString('base64url');
  return `${signingInput}.${encodedSignature}`;
};

const createJwtError = (message, code, extra = {}) => {
  const error = new Error(message);
  error.code = code;
  Object.assign(error, extra);
  return error;
};

const verifyJwt = ({ token, publicKeyPem, expectedTyp, allowExpired = false }) => {
  if (typeof token !== 'string' || token.trim().length === 0) {
    throw createJwtError('jwt missing', 'JWT_MISSING');
  }

  const sections = token.split('.');
  if (sections.length !== 3) {
    throw createJwtError('jwt malformed', 'JWT_MALFORMED');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = sections;
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const verifier = createVerify('RSA-SHA256');
  verifier.update(signingInput);
  verifier.end();

  const signature = fromBase64Url(encodedSignature);
  const validSignature = verifier.verify(publicKeyPem, signature);
  if (!validSignature) {
    throw createJwtError('jwt signature mismatch', 'JWT_SIGNATURE_MISMATCH');
  }

  const header = JSON.parse(fromBase64Url(encodedHeader).toString('utf8'));
  const payload = JSON.parse(fromBase64Url(encodedPayload).toString('utf8'));

  if (header.alg !== 'RS256') {
    throw createJwtError('jwt alg mismatch', 'JWT_ALG_MISMATCH');
  }

  if (expectedTyp && payload.typ !== expectedTyp) {
    throw createJwtError('jwt typ mismatch', 'JWT_TYP_MISMATCH');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (!allowExpired && (typeof payload.exp !== 'number' || payload.exp <= nowSeconds)) {
    throw createJwtError('jwt expired', 'JWT_EXPIRED', { payload });
  }

  return payload;
};

const hashPassword = (plainTextPassword) => {
  const salt = randomBytes(16).toString('hex');
  const derived = pbkdf2Sync(
    plainTextPassword,
    salt,
    PBKDF2_ITERATIONS,
    PBKDF2_KEYLEN,
    PBKDF2_DIGEST
  ).toString('hex');

  return `pbkdf2$${PBKDF2_DIGEST}$${PBKDF2_ITERATIONS}$${salt}$${derived}`;
};

const verifyPassword = (plainTextPassword, encodedHash) => {
  if (!encodedHash || typeof encodedHash !== 'string') {
    return false;
  }

  const sections = encodedHash.split('$');
  if (sections.length !== 5 || sections[0] !== 'pbkdf2') {
    return false;
  }

  const [, digest, iterationText, salt, expectedHex] = sections;
  const iterations = Number(iterationText);
  if (Number.isNaN(iterations) || iterations < 1) {
    return false;
  }

  let actualHex;
  try {
    actualHex = pbkdf2Sync(
      plainTextPassword,
      salt,
      iterations,
      Buffer.from(expectedHex, 'hex').length,
      digest
    ).toString('hex');
  } catch (_error) {
    return false;
  }

  const expected = Buffer.from(expectedHex, 'hex');
  const actual = Buffer.from(actualHex, 'hex');

  if (expected.length !== actual.length) {
    return false;
  }

  return timingSafeEqual(expected, actual);
};

const tokenHash = (rawToken) => createHash('sha256').update(rawToken).digest('hex');
const normalizePhone = (phone) => {
  if (typeof phone !== 'string') {
    return null;
  }
  const trimmed = phone.trim();
  if (!/^1\d{10}$/.test(trimmed)) {
    return null;
  }
  return trimmed;
};

const maskPhone = (phone) => {
  if (typeof phone !== 'string' || phone.trim().length === 0) {
    return 'unknown';
  }

  const cleaned = phone.trim().replace(/\s/g, '');

  if (/^1\d{10}$/.test(cleaned)) {
    return `${cleaned.slice(0, 3)}****${cleaned.slice(-4)}`;
  }

  if (cleaned.length <= 4) {
    return cleaned.replace(/./g, '*');
  }

  return `${cleaned.slice(0, 2)}${'*'.repeat(cleaned.length - 4)}${cleaned.slice(-2)}`;
};
const toOwnerTransferTakeoverRoleId = ({ orgId } = {}) => {
  const normalizedOrgId = String(orgId || '').trim();
  if (!normalizedOrgId) {
    return '';
  }
  const digest = createHash('sha256')
    .update(normalizedOrgId)
    .digest('hex')
    .slice(0, OWNER_TRANSFER_TAKEOVER_ROLE_ID_DIGEST_LENGTH);
  return `${OWNER_TRANSFER_TAKEOVER_ROLE_ID_PREFIX}${digest}`;
};

const isUserActive = (user) => {
  if (!user || typeof user.status !== 'string') {
    return false;
  }

  const normalizedStatus = user.status.trim().toLowerCase();
  return normalizedStatus === 'active' || normalizedStatus === 'enabled';
};

const normalizeEntryDomain = (entryDomain) => {
  const normalized = String(entryDomain || 'platform').trim().toLowerCase();
  if (normalized !== 'platform' && normalized !== 'tenant') {
    return null;
  }
  return normalized;
};

const normalizeTenantId = (tenantId) => {
  if (tenantId === null || tenantId === undefined) {
    return null;
  }
  const normalized = String(tenantId).trim();
  return normalized.length > 0 ? normalized : null;
};
const normalizePlatformRoleCatalogTenantIdForScope = ({
  scope = PLATFORM_ROLE_CATALOG_SCOPE,
  tenantId,
  allowEmptyForPlatform = true
} = {}) => {
  const normalizedScope = normalizePlatformRoleCatalogScope(scope);
  const normalizedTenantId = normalizeTenantId(tenantId);
  if (normalizedScope === 'tenant') {
    if (!normalizedTenantId) {
      throw errors.invalidPayload();
    }
    return normalizedTenantId;
  }
  if (allowEmptyForPlatform) {
    return null;
  }
  return normalizedTenantId;
};
const normalizeOrgStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  if (normalizedStatus === 'active' || normalizedStatus === 'disabled') {
    return normalizedStatus;
  }
  return '';
};
const normalizeTenantMembershipStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  if (
    normalizedStatus === 'active'
    || normalizedStatus === 'disabled'
    || normalizedStatus === 'left'
  ) {
    return normalizedStatus;
  }
  return '';
};
const isValidTenantMembershipId = (membershipId) =>
  TENANT_MEMBERSHIP_ID_PATTERN.test(String(membershipId || ''))
  && String(membershipId || '').length <= MAX_TENANT_MEMBERSHIP_ID_LENGTH;
const normalizeStrictTenantMembershipIdFromInput = (membershipId) => {
  const normalizedMembershipId = normalizeStrictRequiredStringField(membershipId)
    .toLowerCase();
  if (
    !normalizedMembershipId
    || CONTROL_CHAR_PATTERN.test(normalizedMembershipId)
    || !isValidTenantMembershipId(normalizedMembershipId)
  ) {
    throw errors.invalidPayload();
  }
  return normalizedMembershipId;
};
const normalizeStrictAddressableTenantRoleIdFromInput = (roleId) => {
  const normalizedRoleId = normalizeStrictRequiredStringField(roleId)
    .toLowerCase();
  if (
    !normalizedRoleId
    || normalizedRoleId.length > MAX_PLATFORM_ROLE_ID_LENGTH
    || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
    || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
  ) {
    throw errors.invalidPayload();
  }
  return normalizedRoleId;
};
const normalizeMemberListInteger = ({
  value,
  fallback,
  min = 1,
  max = Number.MAX_SAFE_INTEGER
}) => {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }
  const normalized = String(value).trim();
  if (!/^\d+$/.test(normalized)) {
    return fallback;
  }
  const parsed = Number.parseInt(normalized, 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  if (parsed < min) {
    return min;
  }
  if (parsed > max) {
    return max;
  }
  return parsed;
};
const parseOptionalTenantName = (tenantName) => {
  if (tenantName === null || tenantName === undefined) {
    return { valid: true, value: null };
  }
  if (typeof tenantName !== 'string') {
    return { valid: false, value: null };
  }
  if (tenantName.length > MAX_TENANT_NAME_LENGTH) {
    return { valid: false, value: null };
  }
  const normalized = tenantName.trim();
  if (!normalized) {
    return { valid: false, value: null };
  }
  if (normalized.length > MAX_TENANT_NAME_LENGTH) {
    return { valid: false, value: null };
  }
  return { valid: true, value: normalized };
};
const parseOptionalTenantMemberProfileField = ({
  value,
  maxLength
} = {}) => {
  if (value === null || value === undefined) {
    return { valid: true, value: null };
  }
  if (typeof value !== 'string') {
    return { valid: false, value: null };
  }
  const normalized = value.trim();
  if (
    !normalized
    || value !== normalized
    || normalized.length > maxLength
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    return { valid: false, value: null };
  }
  return { valid: true, value: normalized };
};
const normalizeTenantMembershipRecordFromStore = ({
  membership = null,
  expectedMembershipId = '',
  expectedUserId = '',
  expectedTenantId = '',
  expectedDisplayName = UNSET_EXPECTED_TENANT_MEMBER_PROFILE_FIELD,
  expectedDepartmentName = UNSET_EXPECTED_TENANT_MEMBER_PROFILE_FIELD
} = {}) => {
  if (!membership || typeof membership !== 'object') {
    return null;
  }
  const normalizedMembershipId = normalizeStrictRequiredStringField(
    resolveRawCamelSnakeField(membership, 'membershipId', 'membership_id')
  ).toLowerCase();
  const normalizedUserId = normalizeStrictRequiredStringField(
    resolveRawCamelSnakeField(membership, 'userId', 'user_id')
  );
  const normalizedTenantId = normalizeStrictRequiredStringField(
    resolveRawCamelSnakeField(membership, 'tenantId', 'tenant_id')
  );
  const normalizedPhone = normalizeStrictRequiredStringField(
    resolveRawCamelSnakeField(membership, 'phone', 'phone')
  );
  const normalizedStatus = normalizeTenantMembershipStatus(
    normalizeStrictRequiredStringField(
      resolveRawCamelSnakeField(membership, 'status', 'status')
    )
  );
  const normalizedExpectedMembershipId = normalizeStrictRequiredStringField(
    expectedMembershipId
  ).toLowerCase();
  const normalizedExpectedUserId = normalizeStrictRequiredStringField(
    expectedUserId
  );
  const normalizedExpectedTenantId = normalizeStrictRequiredStringField(
    expectedTenantId
  );
  const parsedTenantName = parseOptionalTenantName(
    resolveRawCamelSnakeField(membership, 'tenantName', 'tenant_name')
  );
  const parsedDisplayName = parseOptionalTenantMemberProfileField({
    value: resolveRawCamelSnakeField(membership, 'displayName', 'display_name'),
    maxLength: MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH
  });
  const parsedDepartmentName = parseOptionalTenantMemberProfileField({
    value: resolveRawCamelSnakeField(membership, 'departmentName', 'department_name'),
    maxLength: MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH
  });
  if (
    !isValidTenantMembershipId(normalizedMembershipId)
    || !normalizedUserId
    || !normalizedTenantId
    || !normalizePhone(normalizedPhone)
    || !normalizedStatus
    || !parsedTenantName.valid
    || !parsedDisplayName.valid
    || !parsedDepartmentName.valid
    || (
      normalizedExpectedMembershipId
      && normalizedMembershipId !== normalizedExpectedMembershipId
    )
    || (
      normalizedExpectedUserId
      && normalizedUserId !== normalizedExpectedUserId
    )
    || (
      normalizedExpectedTenantId
      && normalizedTenantId !== normalizedExpectedTenantId
    )
  ) {
    return null;
  }
  if (expectedDisplayName !== UNSET_EXPECTED_TENANT_MEMBER_PROFILE_FIELD) {
    const normalizedExpectedDisplayName = normalizeStrictRequiredStringField(
      expectedDisplayName
    );
    if (
      !normalizedExpectedDisplayName
      || normalizedExpectedDisplayName.length > MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalizedExpectedDisplayName)
      || parsedDisplayName.value !== normalizedExpectedDisplayName
    ) {
      return null;
    }
  }
  if (expectedDepartmentName !== UNSET_EXPECTED_TENANT_MEMBER_PROFILE_FIELD) {
    const parsedExpectedDepartmentName = parseOptionalTenantMemberProfileField({
      value: expectedDepartmentName,
      maxLength: MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH
    });
    if (
      !parsedExpectedDepartmentName.valid
      || parsedDepartmentName.value !== parsedExpectedDepartmentName.value
    ) {
      return null;
    }
  }
  const joinedAt = resolveRawCamelSnakeField(membership, 'joinedAt', 'joined_at');
  const leftAt = resolveRawCamelSnakeField(membership, 'leftAt', 'left_at');
  return {
    membership_id: normalizedMembershipId,
    user_id: normalizedUserId,
    tenant_id: normalizedTenantId,
    tenant_name: parsedTenantName.value,
    phone: normalizedPhone,
    status: normalizedStatus,
    display_name: parsedDisplayName.value,
    department_name: parsedDepartmentName.value,
    joined_at: joinedAt || null,
    left_at: leftAt || null
  };
};

const parseProvisionPayload = ({ payload, scope }) => {
  if (!isPlainObject(payload)) {
    return { valid: false, phone: undefined, tenantName: undefined, tenantNameProvided: false };
  }
  const normalizedScope = String(scope || '').trim().toLowerCase();
  const allowedKeys = normalizedScope === 'tenant'
    ? new Set(['phone', 'tenant_name'])
    : new Set(['phone']);
  for (const key of Object.keys(payload)) {
    if (!allowedKeys.has(key)) {
      return { valid: false, phone: undefined, tenantName: undefined, tenantNameProvided: false };
    }
  }
  const tenantNameProvided = hasOwnProperty(payload, 'tenant_name');
  return {
    valid: true,
    phone: payload.phone,
    tenantName: tenantNameProvided ? payload.tenant_name : undefined,
    tenantNameProvided
  };
};

const createInMemoryOtpStore = ({ nowProvider }) => {
  const otpByPhone = new Map();

  return {
    upsertOtp: async ({ phone, code, expiresAt }) => {
      const sentAtMs = nowProvider();
      otpByPhone.set(String(phone), {
        codeHash: tokenHash(String(code)),
        expiresAt: Number(expiresAt),
        consumed: false,
        sentAtMs
      });
      return { sent_at_ms: sentAtMs };
    },

    getSentAt: async ({ phone }) => {
      const record = otpByPhone.get(String(phone));
      return record ? record.sentAtMs : null;
    },

    verifyAndConsumeOtp: async ({ phone, code, nowMs }) => {
      const record = otpByPhone.get(String(phone));
      if (!record) {
        return { ok: false, reason: 'missing' };
      }
      if (record.consumed) {
        return { ok: false, reason: 'used' };
      }
      if (record.expiresAt <= Number(nowMs)) {
        return { ok: false, reason: 'expired' };
      }
      if (record.codeHash !== tokenHash(String(code))) {
        return { ok: false, reason: 'mismatch' };
      }

      record.consumed = true;
      record.consumedAt = nowProvider();
      otpByPhone.set(String(phone), record);
      return { ok: true, reason: 'ok' };
    }
  };
};

const createInMemoryRateLimitStore = () => {
  const eventsByKey = new Map();

  return {
    consume: async ({ phone, action, limit, windowSeconds, nowMs }) => {
      const key = `${String(phone)}:${String(action)}`;
      const windowMs = Number(windowSeconds) * 1000;
      const floor = Number(nowMs) - windowMs;
      const existing = eventsByKey.get(key) || [];
      const pruned = existing.filter((eventTs) => eventTs > floor);
      pruned.push(Number(nowMs));
      eventsByKey.set(key, pruned);

      const count = pruned.length;
      const oldest = pruned[0] || Number(nowMs);
      const remainingMs = Math.max(0, oldest + windowMs - Number(nowMs));
      return {
        allowed: count <= Number(limit),
        count,
        remainingSeconds: Math.max(1, Math.ceil(remainingMs / 1000))
      };
    }
  };
};

const assertStoreMethod = (store, methodName, storeName) => {
  if (!store || typeof store[methodName] !== 'function') {
    throw new Error(`${storeName}.${methodName} is required`);
  }
};

const assertOtpStoreContract = (store) => {
  assertStoreMethod(store, 'upsertOtp', 'otpStore');
  assertStoreMethod(store, 'getSentAt', 'otpStore');
  assertStoreMethod(store, 'verifyAndConsumeOtp', 'otpStore');
};

const createAuthService = (options = {}) => {
  const now = options.now || (() => Date.now());
  const seedUsers = options.seedUsers || DEFAULT_SEED_USERS;
  const authStore = options.authStore || createInMemoryAuthStore({ seedUsers, hashPassword });
  const {
    userRepository,
    sessionRepository,
    domainAccessRepository,
    tenantMembershipRepository,
    permissionRepository
  } = createAuthRepositories({ authStore });
  const hasExternalAuthStore = Boolean(options.authStore);

  const isSecureMode = options.requireSecureOtpStores === true;
  if (isSecureMode && (!options.otpStore || !options.rateLimitStore)) {
    throw new Error('OTP and rate-limit stores are REQUIRED in secure mode. Fallback to memory is forbidden.');
  }

  const allowInMemoryOtpStores = options.allowInMemoryOtpStores === true;
  if (
    hasExternalAuthStore &&
    !allowInMemoryOtpStores &&
    (!options.otpStore || !options.rateLimitStore)
  ) {
    throw new Error('OTP and rate-limit stores must be configured explicitly');
  }

  const otpStore = options.otpStore || createInMemoryOtpStore({ nowProvider: now });
  const rateLimitStore = options.rateLimitStore || createInMemoryRateLimitStore();
  assertOtpStoreContract(otpStore);

  const isMultiInstance = Boolean(options.multiInstance || options.enforceExternalJwtKeys);
  const configuredAccessSessionCacheTtlMs = Math.max(
    0,
    Number(options.accessSessionCacheTtlMs || ACCESS_SESSION_CACHE_TTL_MS)
  );
  const accessSessionCacheTtlMs = isMultiInstance ? 0 : configuredAccessSessionCacheTtlMs;
  const accessSessionCache = new Map();
  const sensitiveConfigProvider = options.sensitiveConfigProvider || null;
  const sensitiveConfigDecryptionKey = options.sensitiveConfigDecryptionKey || '';
  const sensitiveConfigDecryptionKeys = deriveSensitiveConfigKeys(sensitiveConfigDecryptionKey);

  const jwtKeyPair = (() => {
    if (options.jwtKeyPair?.privateKey && options.jwtKeyPair?.publicKey) {
      return options.jwtKeyPair;
    }

    if (options.enforceExternalJwtKeys) {
      throw new Error('External JWT key pair is required when enforceExternalJwtKeys is enabled');
    }

    return generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
  })();

  const auditTrail = [];
  const requestTraceContextStorage = new AsyncLocalStorage();
  const ownerTransferLocksByOrgId = new Map();

  const normalizeAuditRequestIdOrNull = (value) =>
    normalizeAuditStringOrNull(value, 128);

  const bindRequestTraceparent = ({ requestId, traceparent } = {}) => {
    const normalizedRequestId = normalizeAuditRequestIdOrNull(requestId);
    const normalizedTraceparent = normalizeAuditTraceparentOrNull(traceparent);
    requestTraceContextStorage.enterWith({
      requestId: normalizedRequestId || 'request_id_unset',
      traceparent: normalizedTraceparent
    });
    return normalizedTraceparent;
  };

  const addAuditEvent = ({
    type,
    requestId,
    traceparent = undefined,
    userId = 'unknown',
    sessionId = 'unknown',
    detail = '',
    metadata = {}
  }) => {
    const normalizedRequestId =
      normalizeAuditRequestIdOrNull(requestId) || 'request_id_unset';
    const traceContext = requestTraceContextStorage.getStore();
    const inheritedTraceparent =
      traceContext && traceContext.requestId === normalizedRequestId
        ? traceContext.traceparent
        : null;
    const resolvedTraceparent =
      traceparent === undefined
        ? inheritedTraceparent
        : normalizeAuditTraceparentOrNull(traceparent);
    const event = {
      type,
      at: new Date(now()).toISOString(),
      request_id: normalizedRequestId,
      traceparent: resolvedTraceparent,
      user_id: userId,
      session_id: sessionId,
      detail,
      ...metadata
    };

    auditTrail.push(event);
    if (auditTrail.length > MAX_AUTH_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUTH_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Auth audit event', event);
  };

  const recordPersistentAuditEvent = async ({
    domain,
    tenantId = null,
    requestId = 'request_id_unset',
    traceparent = null,
    eventType,
    actorUserId = null,
    actorSessionId = null,
    targetType,
    targetId = null,
    result = 'success',
    beforeState = null,
    afterState = null,
    metadata = null,
    occurredAt = null
  } = {}) => {
    const normalizedDomain = normalizeAuditDomain(domain);
    const normalizedResult = normalizeAuditResult(result);
    const normalizedEventType = normalizeAuditStringOrNull(eventType, 128);
    const normalizedTargetType = normalizeAuditStringOrNull(targetType, 64);
    if (
      !normalizedDomain
      || !normalizedResult
      || !normalizedEventType
      || !normalizedTargetType
    ) {
      throw errors.auditDependencyUnavailable({
        reason: 'audit-payload-invalid'
      });
    }
    const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
    if (normalizedDomain === 'tenant' && !normalizedTenantId) {
      throw errors.auditDependencyUnavailable({
        reason: 'audit-tenant-id-missing'
      });
    }
    if (!authStore || typeof authStore.recordAuditEvent !== 'function') {
      throw errors.auditDependencyUnavailable({
        reason: 'audit-store-unsupported'
      });
    }
    try {
      const normalizedTraceparent = normalizeAuditTraceparentOrNull(traceparent);
      return await authStore.recordAuditEvent({
        domain: normalizedDomain,
        tenantId: normalizedTenantId,
        requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
        traceparent: normalizedTraceparent,
        eventType: normalizedEventType,
        actorUserId: normalizeAuditStringOrNull(actorUserId, 64),
        actorSessionId: normalizeAuditStringOrNull(actorSessionId, 128),
        targetType: normalizedTargetType,
        targetId: normalizeAuditStringOrNull(targetId, 128),
        result: normalizedResult,
        beforeState: sanitizeAuditState(beforeState),
        afterState: sanitizeAuditState(afterState),
        metadata: sanitizeAuditState(metadata),
        occurredAt: normalizeAuditOccurredAt(occurredAt)
      });
    } catch (error) {
      throw errors.auditDependencyUnavailable({
        reason: String(error?.code || error?.message || 'audit-write-failed').trim().toLowerCase()
      });
    }
  };

  const listAuditEvents = async ({
    domain,
    tenantId = null,
    page = 1,
    pageSize = 50,
    from = null,
    to = null,
    eventType = null,
    result = null,
    requestId = null,
    traceparent = null,
    actorUserId = null,
    targetType = null,
    targetId = null
  } = {}) => {
    const normalizedDomain = normalizeAuditDomain(domain);
    if (!normalizedDomain) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
    if (normalizedDomain === 'tenant' && !normalizedTenantId) {
      throw errors.invalidPayload();
    }
    const resolvedPage = Math.max(1, Math.floor(Number(page || 1)));
    const resolvedPageSize = Math.min(
      MAX_AUDIT_QUERY_PAGE_SIZE,
      Math.max(1, Math.floor(Number(pageSize || 50)))
    );
    const parsedFrom = parseAuditQueryTimestamp(from);
    const parsedTo = parseAuditQueryTimestamp(to);
    if (!parsedFrom.valid || !parsedTo.valid) {
      throw errors.invalidPayload();
    }
    if (
      parsedFrom.value
      && parsedTo.value
      && new Date(parsedFrom.value).getTime() > new Date(parsedTo.value).getTime()
    ) {
      throw errors.invalidPayload();
    }
    if (!authStore || typeof authStore.listAuditEvents !== 'function') {
      throw errors.auditDependencyUnavailable({
        reason: 'audit-store-query-unsupported'
      });
    }
    let normalizedTraceparentFilter = null;
    if (traceparent !== null && traceparent !== undefined) {
      normalizedTraceparentFilter = normalizeAuditTraceparentOrNull(traceparent);
      if (!normalizedTraceparentFilter) {
        throw errors.invalidPayload();
      }
    }
    try {
      return await authStore.listAuditEvents({
        domain: normalizedDomain,
        tenantId: normalizedTenantId,
        page: resolvedPage,
        pageSize: resolvedPageSize,
        from: parsedFrom.value,
        to: parsedTo.value,
        eventType: normalizeAuditStringOrNull(eventType, 128),
        result: normalizeAuditResult(result) || null,
        requestId: normalizeAuditStringOrNull(requestId, 128),
        traceparent: normalizedTraceparentFilter,
        actorUserId: normalizeAuditStringOrNull(actorUserId, 64),
        targetType: normalizeAuditStringOrNull(targetType, 64),
        targetId: normalizeAuditStringOrNull(targetId, 128)
      });
    } catch (error) {
      throw errors.auditDependencyUnavailable({
        reason: String(error?.code || error?.message || 'audit-query-failed').trim().toLowerCase()
      });
    }
  };

  const recordIdempotencyEvent = async ({
    requestId,
    traceparent = null,
    outcome = 'hit',
    routeKey = '',
    idempotencyKey = '',
    authorizationContext = null,
    metadata = {}
  } = {}) => {
    const requestedOutcome = String(outcome || 'hit').trim().toLowerCase();
    const outcomeDescriptorByCode = {
      hit: {
        eventType: 'auth.idempotency.hit',
        detail: 'idempotency replay served from prior result'
      },
      conflict: {
        eventType: 'auth.idempotency.conflict',
        detail: 'idempotency key reused with different request payload'
      },
      store_unavailable: {
        eventType: 'auth.idempotency.degraded',
        detail: 'idempotency store unavailable for this request'
      },
      pending_timeout: {
        eventType: 'auth.idempotency.degraded',
        detail: 'idempotency pending wait timeout'
      },
      unknown: {
        eventType: 'auth.idempotency.unknown',
        detail: 'idempotency outcome is unrecognized'
      }
    };
    const normalizedOutcome = Object.prototype.hasOwnProperty.call(
      outcomeDescriptorByCode,
      requestedOutcome
    )
      ? requestedOutcome
      : 'unknown';
    const selectedOutcomeDescriptor = outcomeDescriptorByCode[normalizedOutcome];
    const resolvedUserId = String(
      authorizationContext?.user_id
      || authorizationContext?.user?.id
      || 'unknown'
    ).trim() || 'unknown';
    const resolvedSessionId = String(
      authorizationContext?.session_id
      || authorizationContext?.session?.sessionId
      || authorizationContext?.session?.session_id
      || 'unknown'
    ).trim() || 'unknown';
    const idempotencyKeyFingerprint = createHash('sha256')
      .update(String(idempotencyKey || '').trim())
      .digest('hex');

    addAuditEvent({
      type: selectedOutcomeDescriptor.eventType,
      requestId,
      traceparent,
      userId: resolvedUserId,
      sessionId: resolvedSessionId,
      detail: selectedOutcomeDescriptor.detail,
      metadata: {
        route_key: String(routeKey || ''),
        idempotency_key_fingerprint: idempotencyKeyFingerprint,
        idempotency_outcome: normalizedOutcome,
        ...metadata
      }
    });
  };

  const addAccessInvalidAuditEvent = ({
    requestId,
    payload = null,
    userId = 'unknown',
    sessionId = 'unknown',
    dispositionReason = 'access-token-invalid'
  }) =>
    addAuditEvent({
      type: 'auth.access.invalid',
      requestId,
      userId,
      sessionId,
      detail: 'access token rejected',
      metadata: {
        session_id_hint: String(payload?.sid || sessionId || 'unknown'),
        disposition_reason: dispositionReason,
        disposition_action: 'reject-only'
      }
    });

  const validatePasswordPolicy = (candidatePassword) => {
    if (typeof candidatePassword !== 'string' || candidatePassword.length < PASSWORD_MIN_LENGTH) {
      throw errors.weakPassword();
    }
  };

  const {
    invalidateSessionCacheBySessionId,
    invalidateSessionCacheByUserId,
    invalidateAllAccessSessionCache,
    buildSessionContext,
    issueAccessToken,
    issueRefreshToken,
    issueLoginTokenPair,
    createSessionAndIssueLoginTokens,
    assertValidAccessSession,
    resolveAuthorizedSession
  } = createAuthSessionService({
    userRepository,
    sessionRepository,
    jwtKeyPair,
    signJwt,
    verifyJwt,
    tokenHash,
    randomUUID,
    now,
    normalizeEntryDomain,
    normalizeTenantId,
    normalizeOrgStatus,
    accessSessionCache,
    accessSessionCacheTtlMs,
    addAccessInvalidAuditEvent,
    errors,
    accessTtlSeconds: ACCESS_TTL_SECONDS,
    refreshTtlSeconds: REFRESH_TTL_SECONDS
  });

  const tenantContextService = createTenantContextService({
    sessionRepository,
    tenantMembershipRepository,
    normalizeTenantId,
    addAuditEvent,
    invalidateSessionCacheBySessionId
  });
  const getTenantOptionsForUser = tenantContextService.getTenantOptionsForUser;
  const {
    getDomainAccessForUser,
    ensureDefaultDomainAccessForUser,
    ensureTenantDomainAccessForUser,
    shouldProvisionDefaultPlatformDomainAccess,
    rejectNoDomainAccess,
    assertDomainAccess
  } = createEntryPolicyService({
    domainAccessRepository,
    addAuditEvent,
    errors,
    normalizeTenantId,
    getTenantOptionsForUser
  });

  const {
    getTenantPermissionContext,
    getPlatformPermissionContext,
    resolveSystemConfigPermissionGrant
  } = createPermissionContextBuilder({
    permissionRepository,
    errors,
    addAuditEvent,
    rejectNoDomainAccess,
    getDomainAccessForUser,
    normalizeTenantId,
    toPlatformPermissionCodeKey,
    platformRoleManagementOperatePermissionCode: PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
    AuthProblemError
  });

  const resolveLoginUserName = async ({
    userId,
    entryDomain,
    activeTenantId = null
  } = {}) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return null;
    }

    if (entryDomain === 'platform') {
      if (typeof userRepository.getPlatformUserById !== 'function') {
        return null;
      }
      try {
        const userProfile = await userRepository.getPlatformUserById({
          userId: normalizedUserId
        });
        return normalizeAuditStringOrNull(userProfile?.name, 64);
      } catch (_error) {
        return null;
      }
    }

    if (entryDomain === 'tenant') {
      const normalizedTenantId = normalizeTenantId(activeTenantId);
      if (!normalizedTenantId) {
        return null;
      }
      if (typeof authStore.findTenantMembershipByUserAndTenantId !== 'function') {
        return null;
      }
      try {
        const membership = await authStore.findTenantMembershipByUserAndTenantId({
          userId: normalizedUserId,
          tenantId: normalizedTenantId
        });
        const normalizedMembership = normalizeTenantMembershipRecordFromStore({
          membership,
          expectedUserId: normalizedUserId,
          expectedTenantId: normalizedTenantId
        });
        if (!normalizedMembership || normalizedMembership.status !== 'active') {
          return null;
        }
        return normalizeAuditStringOrNull(normalizedMembership.display_name, 64);
      } catch (_error) {
        return null;
      }
    }

    return null;
  };

  const reconcileTenantSessionContext = (params = {}) =>
    tenantContextService.reconcileTenantSessionContext({
      ...params,
      rejectNoDomainAccess
    });

  const assertRateLimit = async ({ requestId, phone, action }) => {
    const result = await rateLimitStore.consume({
      phone,
      action,
      limit: RATE_LIMIT_MAX_ATTEMPTS,
      windowSeconds: RATE_LIMIT_WINDOW_SECONDS,
      nowMs: now()
    });

    if (result.allowed) {
      return result;
    }

    addAuditEvent({
      type: 'auth.rate_limited',
      requestId,
      detail: `rate limit exceeded for ${action}`,
      metadata: {
        phone_masked: maskPhone(phone),
        rate_limit_action: action,
        retry_after_seconds: result.remainingSeconds
      }
    });

    throw errors.rateLimited({
      action,
      remainingSeconds: result.remainingSeconds,
      limit: RATE_LIMIT_MAX_ATTEMPTS,
      windowSeconds: RATE_LIMIT_WINDOW_SECONDS
    });
  };

  const { login, loginWithOtp } = createLoginService({
    userRepository,
    otpStore,
    errors,
    addAuditEvent,
    bindRequestTraceparent,
    now,
    normalizePhone,
    normalizeEntryDomain,
    maskPhone,
    isUserActive,
    verifyPassword,
    assertRateLimit,
    shouldProvisionDefaultPlatformDomainAccess,
    ensureDefaultDomainAccessForUser,
    ensureTenantDomainAccessForUser,
    assertDomainAccess,
    getTenantOptionsForUser,
    createSessionAndIssueLoginTokens,
    getTenantPermissionContext,
    getPlatformPermissionContext,
    resolveLoginUserName,
    accessTtlSeconds: ACCESS_TTL_SECONDS,
    refreshTtlSeconds: REFRESH_TTL_SECONDS
  });

  const sendOtp = async ({ requestId, phone, traceparent = null }) => {
    bindRequestTraceparent({
      requestId,
      traceparent
    });
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) {
      throw errors.invalidPayload();
    }

    const currentTime = now();
    let lastSentAt = null;
    try {
      lastSentAt = await otpStore.getSentAt({ phone: normalizedPhone });
    } catch (error) {
      addAuditEvent({
        type: 'auth.otp.send.cooldown_check_failed',
        requestId,
        detail: `getSentAt failed: ${error.message}`,
        metadata: { phone_masked: maskPhone(normalizedPhone) }
      });
      throw errors.rateLimited({
        action: 'otp_send',
        remainingSeconds: OTP_RESEND_COOLDOWN_SECONDS,
        limit: 1,
        windowSeconds: OTP_RESEND_COOLDOWN_SECONDS
      });
    }

    if (lastSentAt !== null && lastSentAt !== undefined) {
      const lastSentAtMs = Number(lastSentAt);
      if (!Number.isFinite(lastSentAtMs) || lastSentAtMs <= 0) {
        addAuditEvent({
          type: 'auth.otp.send.cooldown_check_failed',
          requestId,
          detail: `getSentAt returned invalid value: ${String(lastSentAt)}`,
          metadata: { phone_masked: maskPhone(normalizedPhone) }
        });
        throw errors.rateLimited({
          action: 'otp_send',
          remainingSeconds: OTP_RESEND_COOLDOWN_SECONDS,
          limit: 1,
          windowSeconds: OTP_RESEND_COOLDOWN_SECONDS
        });
      }

      const cooldownEndsAt = lastSentAtMs + OTP_RESEND_COOLDOWN_SECONDS * 1000;
      if (cooldownEndsAt > currentTime) {
        const remainingSeconds = Math.ceil((cooldownEndsAt - currentTime) / 1000);
        addAuditEvent({
          type: 'auth.otp.send.cooldown',
          requestId,
          detail: 'otp resend within cooldown period',
          metadata: {
            phone_masked: maskPhone(normalizedPhone),
            resend_after_seconds: remainingSeconds
          }
        });
        throw errors.rateLimited({
          action: 'otp_send',
          remainingSeconds,
          limit: 1,
          windowSeconds: OTP_RESEND_COOLDOWN_SECONDS
        });
      }
    }

    await assertRateLimit({
      requestId,
      phone: normalizedPhone,
      action: 'otp_send'
    });

    const otpCode = String(randomInt(0, 10 ** OTP_CODE_LENGTH)).padStart(OTP_CODE_LENGTH, '0');
    const expiresAt = currentTime + OTP_TTL_SECONDS * 1000;

    try {
      await otpStore.upsertOtp({
        phone: normalizedPhone,
        code: otpCode,
        expiresAt
      });
    } catch (error) {
      addAuditEvent({
        type: 'auth.otp.send.failed',
        requestId,
        detail: `otp store failure: ${error.message}`,
        metadata: { phone_masked: maskPhone(normalizedPhone) }
      });
      throw error;
    }

    addAuditEvent({
      type: 'auth.otp.send.succeeded',
      requestId,
      detail: 'otp code issued',
      metadata: {
        phone_masked: maskPhone(normalizedPhone),
        resend_after_seconds: OTP_RESEND_COOLDOWN_SECONDS
      }
    });

    return {
      sent: true,
      resend_after_seconds: OTP_RESEND_COOLDOWN_SECONDS,
      request_id: requestId || 'request_id_unset'
    };
  };

  const refresh = async ({ requestId, refreshToken, traceparent = null }) => {
    bindRequestTraceparent({
      requestId,
      traceparent
    });
    if (typeof refreshToken !== 'string' || refreshToken.trim() === '') {
      addAuditEvent({
        type: 'auth.refresh.replay_or_invalid',
        requestId,
        detail: 'refresh payload missing',
        metadata: {
          session_id_hint: 'unknown',
          disposition_reason: 'refresh-payload-missing',
          disposition_action: 'reject-only'
        }
      });
      throw errors.invalidPayload();
    }

    let payload;
    try {
      payload = verifyJwt({
        token: refreshToken,
        publicKeyPem: jwtKeyPair.publicKey,
        expectedTyp: 'refresh'
      });
    } catch (error) {
      const isExpiredRefreshToken = String(error?.code || '').trim().toUpperCase() === 'JWT_EXPIRED';
      const expiredPayload = isExpiredRefreshToken && error?.payload && typeof error.payload === 'object'
        ? error.payload
        : null;
      const expiredUserId = expiredPayload?.sub ? String(expiredPayload.sub) : 'unknown';
      const expiredSessionId = expiredPayload?.sid ? String(expiredPayload.sid) : 'unknown';
      addAuditEvent({
        type: 'auth.refresh.replay_or_invalid',
        requestId,
        userId: isExpiredRefreshToken ? expiredUserId : 'unknown',
        sessionId: isExpiredRefreshToken ? expiredSessionId : 'unknown',
        detail: isExpiredRefreshToken ? 'refresh token expired' : 'refresh token malformed',
        metadata: {
          session_id_hint: isExpiredRefreshToken ? expiredSessionId : 'unknown',
          disposition_reason: isExpiredRefreshToken
            ? 'refresh-token-expired'
            : 'refresh-token-malformed',
          disposition_action: 'reject-only'
        }
      });
      throw errors.invalidRefresh();
    }

    const refreshHash = tokenHash(String(payload.jti || ''));
    const [refreshRecord, session, user] = await Promise.all([
      authStore.findRefreshTokenByHash(refreshHash),
      authStore.findSessionById(payload.sid),
      authStore.findUserById(payload.sub)
    ]);

    const refreshStatus = refreshRecord ? String(refreshRecord.status).toLowerCase() : 'missing';
    const refreshExpired = Boolean(refreshRecord) && refreshRecord.expiresAt <= now();
    const refreshBelongsToClaim = Boolean(
      refreshRecord
      && String(refreshRecord.sessionId || '') === String(payload.sid || '')
      && String(refreshRecord.userId || '') === String(payload.sub || '')
    );
    const normalizedUserStatus = user ? normalizeOrgStatus(user.status) : '';
    const hasInvalidUserStatus = Boolean(user) && normalizedUserStatus !== 'active';

    const sessionVersionMismatch = Boolean(session && user)
      && (
        Number(session.sessionVersion) !== Number(payload.sv)
        || Number(user.sessionVersion) !== Number(payload.sv)
      );
    const invalidState = (
      !refreshRecord ||
      !refreshBelongsToClaim ||
      refreshStatus !== 'active' ||
      refreshExpired ||
      !session ||
      String(session.status).toLowerCase() !== 'active' ||
      !user ||
      hasInvalidUserStatus ||
      String(session.userId) !== String(user.id) ||
      sessionVersionMismatch
    );

    if (invalidState) {
      const replayDetected = refreshBelongsToClaim
        && (refreshStatus === 'rotated' || refreshStatus === 'revoked');
      const dispositionReason = !refreshRecord
          ? 'refresh-token-missing'
          : !refreshBelongsToClaim
            ? 'refresh-token-binding-mismatch'
          : refreshExpired
            ? 'refresh-token-expired'
            : hasInvalidUserStatus
              ? `user-status-${normalizedUserStatus || 'invalid'}`
            : sessionVersionMismatch
              ? 'session-version-mismatch'
            : replayDetected
              ? 'refresh-replay-detected'
            : refreshStatus === 'active'
              ? 'refresh-token-state-mismatch'
              : `refresh-token-${refreshStatus}`;

      if (refreshRecord && refreshStatus === 'active' && refreshBelongsToClaim) {
        await authStore.markRefreshTokenStatus({
          tokenHash: refreshHash,
          status: 'revoked'
        });
      }

      if (replayDetected) {
        await authStore.revokeSession({
          sessionId: refreshRecord.sessionId || payload.sid,
          reason: 'refresh-replay-detected'
        });
        invalidateSessionCacheBySessionId(refreshRecord.sessionId || payload.sid);
      }

      addAuditEvent({
        type: 'auth.refresh.replay_or_invalid',
        requestId,
        userId: payload.sub,
        sessionId: payload.sid,
        detail: 'refresh token rejected',
        metadata: {
          session_id_hint: String(payload.sid || 'unknown'),
          refresh_status: refreshStatus,
          disposition_reason: dispositionReason,
          disposition_action: replayDetected
            ? 'revoke-session-chain'
            : refreshStatus === 'active' && refreshBelongsToClaim
              ? 'revoke-current-token'
              : 'reject-only'
        }
      });
      throw errors.invalidRefresh();
    }

    const sessionId = session.sessionId || session.session_id || payload.sid;
    const nextRefreshTokenId = randomUUID();
    const nextRefreshHash = tokenHash(nextRefreshTokenId);
    const nextRefreshExpiresAt = now() + REFRESH_TTL_SECONDS * 1000;

    if (typeof authStore.rotateRefreshToken === 'function') {
      const rotated = await authStore.rotateRefreshToken({
        previousTokenHash: refreshHash,
        nextTokenHash: nextRefreshHash,
        sessionId,
        userId: user.id,
        expiresAt: nextRefreshExpiresAt
      });

      if (!rotated || rotated.ok !== true) {
        await authStore.revokeSession({
          sessionId,
          reason: 'refresh-rotation-conflict'
        });
        invalidateSessionCacheBySessionId(sessionId);
        addAuditEvent({
          type: 'auth.refresh.replay_or_invalid',
          requestId,
          userId: user.id,
          sessionId,
          detail: 'refresh token rejected by rotation conflict',
          metadata: {
            session_id_hint: String(sessionId || 'unknown'),
            disposition_reason: 'refresh-rotation-conflict',
            disposition_action: 'revoke-session-chain'
          }
        });
        throw errors.invalidRefresh();
      }
    } else {
      await authStore.markRefreshTokenStatus({
        tokenHash: refreshHash,
        status: 'rotated'
      });

      await authStore.createRefreshToken({
        tokenHash: nextRefreshHash,
        sessionId,
        userId: user.id,
        expiresAt: nextRefreshExpiresAt
      });

      await authStore.linkRefreshRotation({
        previousTokenHash: refreshHash,
        nextTokenHash: nextRefreshHash
      });
    }

    const accessToken = issueAccessToken({
      userId: user.id,
      sessionId,
      sessionVersion: Number(user.sessionVersion)
    });
    const nextRefreshToken = issueRefreshToken({
      userId: user.id,
      sessionId,
      sessionVersion: Number(user.sessionVersion),
      refreshTokenId: nextRefreshTokenId
    });
    let sessionContext = buildSessionContext(session);
    const refreshedTenantOptions = sessionContext.entry_domain === 'tenant'
      ? await getTenantOptionsForUser(user.id)
      : [];
    sessionContext = await reconcileTenantSessionContext({
      requestId,
      userId: user.id,
      sessionId,
      sessionContext,
      options: refreshedTenantOptions
    });
    const tenantSelectionRequired = sessionContext.entry_domain === 'tenant'
      && refreshedTenantOptions.length > 1
      && !sessionContext.active_tenant_id;
    const tenantPermissionContext = await getTenantPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: sessionContext.active_tenant_id
    });
    const platformPermissionContext = await getPlatformPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: sessionContext.entry_domain
    });
    const userName = await resolveLoginUserName({
      userId: user.id,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: sessionContext.active_tenant_id
    });

    addAuditEvent({
      type: 'auth.refresh.succeeded',
      requestId,
      userId: user.id,
      sessionId
    });

    return {
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: nextRefreshToken,
      expires_in: ACCESS_TTL_SECONDS,
      refresh_expires_in: REFRESH_TTL_SECONDS,
      session_id: sessionId,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: sessionContext.active_tenant_id,
      tenant_selection_required: tenantSelectionRequired,
      tenant_options: refreshedTenantOptions,
      user_name: userName,
      platform_permission_context: platformPermissionContext,
      tenant_permission_context: tenantPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  const logout = async ({
    requestId,
    accessToken,
    authorizationContext = null,
    traceparent = null
  }) => {
    bindRequestTraceparent({
      requestId,
      traceparent
    });
    const { session, user } = await resolveAuthorizedSession({
      requestId,
      accessToken,
      authorizationContext
    });
    const sessionId = session.sessionId || session.session_id;
    await authStore.revokeSession({
      sessionId,
      reason: 'logout-current-session'
    });
    invalidateSessionCacheBySessionId(sessionId);

    addAuditEvent({
      type: 'auth.logout.current_session',
      requestId,
      userId: user.id,
      sessionId
    });

    return {
      ok: true,
      session_id: sessionId,
      request_id: requestId || 'request_id_unset'
    };
  };

  const changePassword = async ({
    requestId,
    accessToken,
    currentPassword,
    newPassword,
    authorizationContext = null,
    traceparent = null
  }) => {
    bindRequestTraceparent({
      requestId,
      traceparent
    });
    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
      addAuditEvent({
        type: 'auth.password_change.rejected',
        requestId,
        detail: 'password payload invalid',
        metadata: {
          session_id_hint: 'unknown'
        }
      });
      throw errors.invalidPayload();
    }

    try {
      validatePasswordPolicy(newPassword);
    } catch (error) {
      addAuditEvent({
        type: 'auth.password_change.rejected',
        requestId,
        detail: 'new password policy violation',
        metadata: {
          session_id_hint: 'unknown'
        }
      });
      throw error;
    }

    const { session, user } = await resolveAuthorizedSession({
      requestId,
      accessToken,
      authorizationContext
    });
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);
    const normalizedSessionEntryDomain = normalizeAuditDomain(
      session.entryDomain || session.entry_domain || 'platform'
    );
    const normalizedSessionActiveTenantId = normalizeAuditStringOrNull(
      session.activeTenantId || session.active_tenant_id,
      64
    );
    const resolvedPasswordAuditDomain =
      normalizedSessionEntryDomain === 'tenant' && normalizedSessionActiveTenantId
        ? 'tenant'
        : 'platform';
    const resolvedPasswordAuditTenantId =
      resolvedPasswordAuditDomain === 'tenant'
        ? normalizedSessionActiveTenantId
        : null;
    const currentPasswordValid = verifyPassword(currentPassword, user.passwordHash);

    if (!currentPasswordValid) {
      addAuditEvent({
        type: 'auth.password_change.rejected',
        requestId,
        userId: user.id,
        sessionId: session.sessionId || session.session_id,
        detail: 'current password mismatch',
        metadata: {
          phone_masked: maskPhone(user.phone)
        }
      });
      await recordPersistentAuditEvent({
        domain: resolvedPasswordAuditDomain,
        tenantId: resolvedPasswordAuditTenantId,
        requestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.password_change.rejected',
        actorUserId: user.id,
        actorSessionId: session.sessionId || session.session_id || null,
        targetType: 'user',
        targetId: user.id,
        result: 'rejected',
        beforeState: {
          session_version: Number(user.sessionVersion || 0)
        },
        afterState: {
          session_version: Number(user.sessionVersion || 0)
        },
        metadata: {
          reason: 'current-password-mismatch',
          phone_masked: maskPhone(user.phone)
        }
      });
      throw errors.loginFailed();
    }

    const previousSessionVersion = Number(user.sessionVersion || 0);
    const updatedUser = typeof authStore.updateUserPasswordAndRevokeSessions === 'function'
      ? await authStore.updateUserPasswordAndRevokeSessions({
        userId: user.id,
        passwordHash: hashPassword(newPassword),
        reason: 'password-changed'
      })
      : await authStore.updateUserPasswordAndBumpSessionVersion({
        userId: user.id,
        passwordHash: hashPassword(newPassword)
      });
    if (!updatedUser) {
      throw errors.invalidAccess();
    }
    if (typeof authStore.updateUserPasswordAndRevokeSessions !== 'function') {
      await authStore.revokeAllUserSessions({
        userId: user.id,
        reason: 'password-changed'
      });
    }
    invalidateSessionCacheByUserId(user.id);

    addAuditEvent({
      type: 'auth.password_change.succeeded',
      requestId,
      userId: user.id,
      sessionId: session.sessionId || session.session_id
    });
    await recordPersistentAuditEvent({
      domain: resolvedPasswordAuditDomain,
      tenantId: resolvedPasswordAuditTenantId,
      requestId,
      traceparent: normalizedTraceparent,
      eventType: 'auth.password_change.succeeded',
      actorUserId: user.id,
      actorSessionId: session.sessionId || session.session_id || null,
      targetType: 'user',
      targetId: user.id,
      result: 'success',
      beforeState: {
        session_version: previousSessionVersion
      },
      afterState: {
        session_version: Number(updatedUser.sessionVersion || previousSessionVersion)
      },
      metadata: {
        relogin_required: true
      }
    });

    return {
      password_changed: true,
      relogin_required: true,
      request_id: requestId || 'request_id_unset'
    };
  };

  const mapPlatformRoleCatalogLookupErrorToProblem = (error) => {
    if (isMissingPlatformRoleCatalogTableError(error)) {
      return errors.platformSnapshotDegraded({
        reason: 'platform-role-catalog-unavailable'
      });
    }
    return errors.platformSnapshotDegraded({
      reason: 'platform-role-catalog-query-failed'
    });
  };

  const assertPlatformRoleCatalogLookupCapability = () => {
    if (typeof authStore.findPlatformRoleCatalogEntriesByRoleIds !== 'function') {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-catalog-lookup-unsupported'
      });
    }
  };

  const assertPlatformRoleCatalogDependencyAvailable = async () => {
    assertPlatformRoleCatalogLookupCapability();
    if (typeof authStore.countPlatformRoleCatalogEntries === 'function') {
      try {
        await authStore.countPlatformRoleCatalogEntries();
        return;
      } catch (error) {
        throw mapPlatformRoleCatalogLookupErrorToProblem(error);
      }
    }
    try {
      await authStore.findPlatformRoleCatalogEntriesByRoleIds({
        roleIds: ['__platform_roles_health_probe__']
      });
    } catch (error) {
      throw mapPlatformRoleCatalogLookupErrorToProblem(error);
    }
  };

  const loadValidatedPlatformRoleCatalogEntriesForRoleFacts = async ({
    roles = [],
    allowDisabledRoles = false
  }) => {
    if (!Array.isArray(roles) || roles.length === 0) {
      await assertPlatformRoleCatalogDependencyAvailable();
      return {
        requestedRoleIds: [],
        catalogEntriesByRoleIdKey: new Map()
      };
    }
    assertPlatformRoleCatalogLookupCapability();

    const requestedRoleIds = [];
    const requestedRoleIdKeys = new Set();
    for (const role of roles) {
      const roleId = normalizeRequiredStringField(
        resolveRawRoleIdCandidate(role),
        errors.invalidPayload
      );
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      if (requestedRoleIdKeys.has(roleIdKey)) {
        continue;
      }
      requestedRoleIds.push(roleId);
      requestedRoleIdKeys.add(roleIdKey);
    }

    let catalogEntries = [];
    try {
      catalogEntries = await authStore.findPlatformRoleCatalogEntriesByRoleIds({
        roleIds: requestedRoleIds
      });
    } catch (error) {
      throw mapPlatformRoleCatalogLookupErrorToProblem(error);
    }
    const catalogEntriesByRoleIdKey = new Map();
    for (const catalogEntry of Array.isArray(catalogEntries) ? catalogEntries : []) {
      const roleId = String(
        catalogEntry?.roleId
        || catalogEntry?.role_id
        || ''
      ).trim();
      if (!roleId) {
        continue;
      }
      catalogEntriesByRoleIdKey.set(
        normalizePlatformRoleIdKey(roleId),
        catalogEntry
      );
    }

    for (const roleId of requestedRoleIds) {
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      const catalogEntry = catalogEntriesByRoleIdKey.get(roleIdKey);
      if (!catalogEntry) {
        throw errors.invalidPayload();
      }

      const normalizedStatus = normalizePlatformRoleCatalogStatus(
        catalogEntry?.status
      );
      const normalizedScope = normalizePlatformRoleCatalogScope(
        catalogEntry?.scope
      );
      if (
        !VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)
        || (!allowDisabledRoles && normalizedStatus === 'disabled')
        || normalizedScope !== PLATFORM_ROLE_CATALOG_SCOPE
      ) {
        throw errors.invalidPayload();
      }
    }

    return {
      requestedRoleIds,
      catalogEntriesByRoleIdKey
    };
  };

  const loadPlatformRolePermissionGrantsByRoleIds = async ({
    roleIds = []
  }) => {
    const normalizedRoleIds = [...new Set(
      (Array.isArray(roleIds) ? roleIds : [])
        .map((roleId) => normalizeRequiredStringField(roleId, errors.invalidPayload))
    )];
    if (normalizedRoleIds.length === 0) {
      return new Map();
    }

    if (typeof authStore.listPlatformRolePermissionGrantsByRoleIds !== 'function') {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-grants-unsupported'
      });
    }

    let grantEntries = [];
    try {
      grantEntries = await authStore.listPlatformRolePermissionGrantsByRoleIds({
        roleIds: normalizedRoleIds
      });
    } catch (_error) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-grants-query-failed'
      });
    }

    const grantsByRoleIdKey = new Map();
    for (const roleId of normalizedRoleIds) {
      grantsByRoleIdKey.set(normalizePlatformRoleIdKey(roleId), []);
    }

    for (const grantEntry of Array.isArray(grantEntries) ? grantEntries : []) {
      const rawRoleId = resolveRawCamelSnakeField(
        grantEntry,
        'roleId',
        'role_id'
      );
      const strictRoleId = normalizeStrictRequiredStringField(rawRoleId);
      const roleId = strictRoleId.toLowerCase();
      if (
        !strictRoleId
        || strictRoleId !== roleId
        || CONTROL_CHAR_PATTERN.test(strictRoleId)
        || !ROLE_ID_ADDRESSABLE_PATTERN.test(roleId)
      ) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-invalid'
        });
      }
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      if (!grantsByRoleIdKey.has(roleIdKey)) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-invalid'
        });
      }
      const hasPermissionCodes = (
        Array.isArray(grantEntry?.permissionCodes)
        || Array.isArray(grantEntry?.permission_codes)
      );
      if (!hasPermissionCodes) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-invalid'
        });
      }
      const permissionCodes = Array.isArray(grantEntry?.permissionCodes)
        ? grantEntry.permissionCodes
        : grantEntry.permission_codes;
      const dedupedCodes = new Map();
      for (const permissionCode of permissionCodes) {
        const normalizedPermissionCode = normalizeStrictRequiredStringField(permissionCode);
        const permissionCodeKey = toPlatformPermissionCodeKey(normalizedPermissionCode);
        if (
          !normalizedPermissionCode
          || normalizedPermissionCode !== permissionCodeKey
        ) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-grants-invalid'
          });
        }
        if (CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-grants-invalid'
          });
        }
        if (
          !isPlatformPermissionCode(normalizedPermissionCode)
          || !SUPPORTED_PLATFORM_PERMISSION_CODE_SET.has(permissionCodeKey)
        ) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-grants-invalid'
          });
        }
        if (dedupedCodes.has(permissionCodeKey)) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-grants-invalid'
          });
        }
        dedupedCodes.set(permissionCodeKey, permissionCodeKey);
      }
      grantsByRoleIdKey.set(roleIdKey, [...dedupedCodes.values()]);
    }

    return grantsByRoleIdKey;
  };

  const loadValidatedTenantRoleCatalogEntries = async ({
    tenantId,
    roleIds = [],
    allowDisabledRoles = false
  }) => {
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: 'tenant',
      tenantId,
      allowEmptyForPlatform: false
    });
    const normalizedRoleIds = [...new Set(
      (Array.isArray(roleIds) ? roleIds : [])
        .map((roleId) => normalizeRequiredStringField(roleId, errors.invalidPayload).toLowerCase())
    )];
    const requestedRoleIdKeySet = new Set(
      normalizedRoleIds.map((roleId) => normalizePlatformRoleIdKey(roleId))
    );

    assertPlatformRoleCatalogLookupCapability();
    let catalogEntries = [];
    try {
      catalogEntries = await authStore.findPlatformRoleCatalogEntriesByRoleIds({
        roleIds: normalizedRoleIds
      });
    } catch (error) {
      throw mapPlatformRoleCatalogLookupErrorToProblem(error);
    }
    const catalogEntriesByRoleIdKey = new Map();
    const seenRequestedRoleIdKeys = new Set();
    for (const catalogEntry of Array.isArray(catalogEntries) ? catalogEntries : []) {
      const rawRoleId = resolveRawCamelSnakeField(
        catalogEntry,
        'roleId',
        'role_id'
      );
      const roleId = normalizeStrictRequiredStringField(rawRoleId).toLowerCase();
      if (!roleId) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-role-catalog-invalid'
        });
      }
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      if (!requestedRoleIdKeySet.has(roleIdKey)) {
        continue;
      }
      if (seenRequestedRoleIdKeys.has(roleIdKey)) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-role-catalog-duplicate'
        });
      }
      seenRequestedRoleIdKeys.add(roleIdKey);
      catalogEntriesByRoleIdKey.set(roleIdKey, catalogEntry);
    }

    for (const roleId of normalizedRoleIds) {
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      const catalogEntry = catalogEntriesByRoleIdKey.get(roleIdKey);
      if (!catalogEntry) {
        throw errors.roleNotFound();
      }
      const normalizedStatusCandidate = normalizeStrictRequiredStringField(
        catalogEntry?.status
      ).toLowerCase();
      if (!VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatusCandidate)) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-role-catalog-invalid'
        });
      }
      const normalizedStatus = normalizedStatusCandidate === 'enabled'
        ? 'active'
        : normalizedStatusCandidate;
      const normalizedScope = normalizeStrictRequiredStringField(
        catalogEntry?.scope
      ).toLowerCase();
      if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-role-catalog-invalid'
        });
      }
      const rawCatalogTenantId = resolveRawCamelSnakeField(
        catalogEntry,
        'tenantId',
        'tenant_id'
      );
      const normalizedCatalogTenantId =
        normalizeStrictRequiredStringField(rawCatalogTenantId);
      if (
        !normalizedCatalogTenantId
        || CONTROL_CHAR_PATTERN.test(normalizedCatalogTenantId)
      ) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-role-catalog-invalid'
        });
      }
      if (
        (!allowDisabledRoles && normalizedStatus !== 'active')
        || normalizedScope !== 'tenant'
        || normalizedCatalogTenantId !== normalizedTenantId
      ) {
        throw errors.roleNotFound();
      }
    }

    return {
      normalizedTenantId,
      requestedRoleIds: normalizedRoleIds,
      catalogEntriesByRoleIdKey
    };
  };

  const loadTenantRolePermissionGrantsByRoleIds = async ({
    roleIds = []
  }) => {
    const normalizedRoleIds = [...new Set(
      (Array.isArray(roleIds) ? roleIds : [])
        .map((roleId) => normalizeRequiredStringField(roleId, errors.invalidPayload).toLowerCase())
    )];
    if (normalizedRoleIds.length === 0) {
      return new Map();
    }

    let grantEntries = [];
    try {
      if (typeof authStore.listTenantRolePermissionGrantsByRoleIds === 'function') {
        grantEntries = await authStore.listTenantRolePermissionGrantsByRoleIds({
          roleIds: normalizedRoleIds
        });
      } else if (typeof authStore.listTenantRolePermissionGrants === 'function') {
        grantEntries = await Promise.all(
          normalizedRoleIds.map(async (roleId) => ({
            roleId,
            permissionCodes: await authStore.listTenantRolePermissionGrants({
              roleId
            })
          }))
        );
      } else {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-role-permission-grants-unsupported'
        });
      }
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-role-permission-grants-query-failed'
      });
    }

    const grantsByRoleIdKey = new Map();
    for (const roleId of normalizedRoleIds) {
      grantsByRoleIdKey.set(normalizePlatformRoleIdKey(roleId), []);
    }
    const seenGrantEntriesByRoleIdKey = new Set();
    for (const grantEntry of Array.isArray(grantEntries) ? grantEntries : []) {
      const rawRoleId = resolveRawCamelSnakeField(
        grantEntry,
        'roleId',
        'role_id'
      );
      const strictRoleId = normalizeStrictRequiredStringField(rawRoleId);
      const roleId = strictRoleId.toLowerCase();
      if (
        !strictRoleId
        || strictRoleId !== roleId
        || CONTROL_CHAR_PATTERN.test(strictRoleId)
        || !ROLE_ID_ADDRESSABLE_PATTERN.test(roleId)
      ) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-role-permission-grants-invalid'
        });
      }
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      if (!grantsByRoleIdKey.has(roleIdKey)) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-role-permission-grants-invalid'
        });
      }
      if (seenGrantEntriesByRoleIdKey.has(roleIdKey)) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-role-permission-grants-duplicate-role'
        });
      }
      seenGrantEntriesByRoleIdKey.add(roleIdKey);
      const hasPermissionCodes = (
        Array.isArray(grantEntry?.permissionCodes)
        || Array.isArray(grantEntry?.permission_codes)
      );
      if (!hasPermissionCodes) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-role-permission-grants-invalid'
        });
      }
      const permissionCodes = Array.isArray(grantEntry?.permissionCodes)
        ? grantEntry.permissionCodes
        : grantEntry.permission_codes;
      const dedupedCodes = new Map();
      for (const permissionCode of permissionCodes) {
        const normalizedPermissionCode =
          normalizeStrictRequiredStringField(permissionCode);
        const permissionCodeKey = toTenantPermissionCodeKey(normalizedPermissionCode);
        if (!normalizedPermissionCode) {
          throw errors.tenantMemberDependencyUnavailable({
            reason: 'tenant-role-permission-grants-invalid'
          });
        }
        if (normalizedPermissionCode !== permissionCodeKey) {
          throw errors.tenantMemberDependencyUnavailable({
            reason: 'tenant-role-permission-grants-invalid'
          });
        }
        if (CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)) {
          throw errors.tenantMemberDependencyUnavailable({
            reason: 'tenant-role-permission-grants-invalid'
          });
        }
        if (
          !isTenantPermissionCode(normalizedPermissionCode)
          || !SUPPORTED_TENANT_PERMISSION_CODE_SET.has(permissionCodeKey)
        ) {
          throw errors.tenantMemberDependencyUnavailable({
            reason: 'tenant-role-permission-grants-invalid'
          });
        }
        if (dedupedCodes.has(permissionCodeKey)) {
          throw errors.tenantMemberDependencyUnavailable({
            reason: 'tenant-role-permission-grants-invalid'
          });
        }
        dedupedCodes.set(permissionCodeKey, permissionCodeKey);
      }
      grantsByRoleIdKey.set(roleIdKey, [...dedupedCodes.values()]);
    }
    return grantsByRoleIdKey;
  };

  const normalizePlatformRoleFactsForReplace = async ({
    roles = [],
    enforceRoleCatalogValidation = false
  }) => {
    const normalizedRoleFacts = [];
    const distinctRoleIds = new Set();

    for (const role of roles) {
      if (!isPlainObject(role)) {
        throw errors.invalidPayload();
      }

      const unknownRoleKeys = Object.keys(role).filter(
        (key) => !PLATFORM_ROLE_ASSIGNMENT_ALLOWED_FIELDS.has(key) && key !== 'permission'
      );
      if (enforceRoleCatalogValidation && unknownRoleKeys.length > 0) {
        throw errors.invalidPayload();
      }

      const hasPermissionField = hasOwnProperty(role, 'permission');
      if (
        enforceRoleCatalogValidation
        && (hasPermissionField || hasTopLevelPlatformRolePermissionField(role))
      ) {
        throw errors.invalidPayload();
      }
      if (!enforceRoleCatalogValidation && hasPermissionField && !isPlainObject(role.permission)) {
        throw errors.invalidPayload();
      }
      if (!enforceRoleCatalogValidation && hasTopLevelPlatformRolePermissionField(role)) {
        throw errors.invalidPayload();
      }

      const rawRoleId = resolveRawRoleIdCandidate(role);
      const normalizedRoleId = normalizeRequiredStringField(
        rawRoleId,
        errors.invalidPayload
      );
      const normalizedRoleIdKey = normalizePlatformRoleIdKey(normalizedRoleId);
      if (normalizedRoleIdKey.length > MAX_PLATFORM_ROLE_ID_LENGTH) {
        throw errors.invalidPayload();
      }
      if (distinctRoleIds.has(normalizedRoleIdKey)) {
        throw errors.invalidPayload();
      }
      distinctRoleIds.add(normalizedRoleIdKey);

      let normalizedRoleStatus = 'active';
      if (hasOwnProperty(role, 'status')) {
        if (typeof role.status !== 'string') {
          throw errors.invalidPayload();
        }
        normalizedRoleStatus = role.status.trim().toLowerCase();
        if (!normalizedRoleStatus) {
          throw errors.invalidPayload();
        }
      }
      if (!VALID_PLATFORM_ROLE_FACT_STATUS.has(normalizedRoleStatus)) {
        throw errors.invalidPayload();
      }
      const resolvedRoleStatus = normalizedRoleStatus === 'enabled'
        ? 'active'
        : normalizedRoleStatus;
      if (enforceRoleCatalogValidation && resolvedRoleStatus !== 'active') {
        throw errors.invalidPayload();
      }

      if (!enforceRoleCatalogValidation) {
        const rolePermissionSource = hasPermissionField ? role.permission : {};
        assertOptionalBooleanRolePermission(
          rolePermissionSource?.canViewUserManagement ?? rolePermissionSource?.can_view_user_management,
          errors.invalidPayload
        );
        assertOptionalBooleanRolePermission(
          rolePermissionSource?.canOperateUserManagement ?? rolePermissionSource?.can_operate_user_management,
          errors.invalidPayload
        );
        assertOptionalBooleanRolePermission(
          rolePermissionSource?.canViewTenantManagement ?? rolePermissionSource?.can_view_tenant_management,
          errors.invalidPayload
        );
        assertOptionalBooleanRolePermission(
          rolePermissionSource?.canOperateTenantManagement ?? rolePermissionSource?.can_operate_tenant_management,
          errors.invalidPayload
        );
        normalizedRoleFacts.push({
          roleId: normalizedRoleIdKey,
          status: resolvedRoleStatus,
          permission: {
            canViewUserManagement: Boolean(
              rolePermissionSource?.canViewUserManagement
              ?? rolePermissionSource?.can_view_user_management
            ),
            canOperateUserManagement: Boolean(
              rolePermissionSource?.canOperateUserManagement
              ?? rolePermissionSource?.can_operate_user_management
            ),
            canViewTenantManagement: Boolean(
              rolePermissionSource?.canViewTenantManagement
              ?? rolePermissionSource?.can_view_tenant_management
            ),
            canOperateTenantManagement: Boolean(
              rolePermissionSource?.canOperateTenantManagement
              ?? rolePermissionSource?.can_operate_tenant_management
            )
          }
        });
        continue;
      }

      normalizedRoleFacts.push({
        roleId: normalizedRoleIdKey,
        status: resolvedRoleStatus
      });
    }

    if (!enforceRoleCatalogValidation) {
      return normalizedRoleFacts;
    }

    const { requestedRoleIds } =
      await loadValidatedPlatformRoleCatalogEntriesForRoleFacts({
        roles: normalizedRoleFacts
      });
    const grantsByRoleIdKey = await loadPlatformRolePermissionGrantsByRoleIds({
      roleIds: requestedRoleIds
    });

    return normalizedRoleFacts.map((roleFact) => {
      const roleIdKey = normalizePlatformRoleIdKey(roleFact.roleId);
      const permissionCodes = grantsByRoleIdKey.get(roleIdKey) || [];
      return {
        roleId: roleFact.roleId,
        status: 'active',
        permission: toPlatformPermissionSnapshotFromCodes(permissionCodes)
      };
    });
  };

  const replacePlatformRolesAndSyncSnapshot = async ({
    requestId,
    accessToken = null,
    userId,
    roles,
    authorizationContext = null,
    traceparent = null,
    enforceRoleCatalogValidation = false
  }) => {
    if (typeof authStore.replacePlatformRolesAndSyncSnapshot !== 'function') {
      throw new Error('authStore.replacePlatformRolesAndSyncSnapshot is required');
    }

    const normalizedAccessToken = typeof accessToken === 'string'
      ? accessToken.trim()
      : '';
    if (normalizedAccessToken.length === 0) {
      throw errors.invalidAccess();
    }
    const authorizedRoute = await authorizeRoute({
      requestId,
      accessToken: normalizedAccessToken,
      permissionCode: PLATFORM_ROLE_FACTS_REPLACE_PERMISSION_CODE,
      scope: 'platform',
      authorizationContext
    });
    const operatorUserId = String(
      authorizedRoute?.user_id || authorizedRoute?.user?.id || ''
    ).trim() || null;
    const operatorSessionId = String(
      authorizedRoute?.session_id || authorizedRoute?.session?.sessionId || ''
    ).trim() || null;
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);

    const normalizedUserId = normalizeRequiredStringField(
      userId,
      errors.invalidPayload
    );
    if (!Array.isArray(roles)) {
      throw errors.invalidPayload();
    }
    if (enforceRoleCatalogValidation && roles.length === 0) {
      throw errors.invalidPayload();
    }
    if (roles.length > MAX_PLATFORM_ROLE_FACTS_PER_USER) {
      throw errors.invalidPayload();
    }
    const rolesForPersistence = await normalizePlatformRoleFactsForReplace({
      roles,
      enforceRoleCatalogValidation
    });

    const hasUserLookup = typeof authStore.findUserById === 'function';
    const previousUser = hasUserLookup
      ? await authStore.findUserById(normalizedUserId)
      : null;
    if (hasUserLookup && !previousUser) {
      throw errors.invalidPayload();
    }
    let result;
    try {
      result = await authStore.replacePlatformRolesAndSyncSnapshot({
        userId: normalizedUserId,
        roles: rolesForPersistence
      });
    } catch (error) {
      if (
        error instanceof Error
        && String(error.message || '').includes('invalid platform role status')
      ) {
        throw errors.invalidPayload();
      }
      if (isDuplicateRoleFactEntryError(error)) {
        throw errors.invalidPayload();
      }
      if (isDataTooLongRoleFactError(error)) {
        throw errors.invalidPayload();
      }
      throw error;
    }
    const syncReason = String(result?.reason || 'unknown').trim().toLowerCase();
    if (syncReason === 'invalid-user-id') {
      throw errors.invalidPayload();
    }
    if (syncReason === 'db-deadlock' || syncReason === 'concurrent-role-facts-update') {
      throw errors.platformSnapshotDegraded({
        reason: syncReason
      });
    }
    if (syncReason !== 'ok') {
      throw errors.platformSnapshotDegraded({
        reason: syncReason || 'unknown'
      });
    }

    const nextUser = hasUserLookup
      ? await authStore.findUserById(normalizedUserId)
      : null;
    const sessionVersionChanged = Boolean(
      previousUser
      && nextUser
      && Number(nextUser.sessionVersion) !== Number(previousUser.sessionVersion)
    );

    if (sessionVersionChanged || !hasUserLookup) {
      invalidateSessionCacheByUserId(normalizedUserId);
    }

    addAuditEvent({
      type: 'auth.platform_role_facts.updated',
      requestId,
      userId: normalizedUserId,
      sessionId: operatorSessionId || 'unknown',
      detail: 'platform role facts replaced and snapshot synced',
      metadata: {
        actor_user_id: operatorUserId,
        actor_session_id: operatorSessionId,
        target_user_id: normalizedUserId,
        session_version_changed: sessionVersionChanged,
        sync_reason: syncReason || 'unknown'
      }
    });
    const toPlatformRoleFactsAuditState = (userRecord = null) => {
      const roleFacts = Array.isArray(userRecord?.platformRoles)
        ? userRecord.platformRoles
        : Array.isArray(userRecord?.platform_roles)
          ? userRecord.platform_roles
          : [];
      return roleFacts
        .map((roleFact) => ({
          role_id: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(roleFact, 'roleId', 'role_id'),
            64
          ),
          status: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(roleFact, 'status', 'status'),
            16
          ) || 'active'
        }))
        .filter((roleFact) => roleFact.role_id)
        .sort((left, right) => left.role_id.localeCompare(right.role_id));
    };
    const previousSessionVersion = Number(
      resolveRawCamelSnakeField(previousUser, 'sessionVersion', 'session_version') || 0
    );
    const nextSessionVersion = Number(
      resolveRawCamelSnakeField(nextUser, 'sessionVersion', 'session_version')
        || previousSessionVersion
    );
    await recordPersistentAuditEvent({
      domain: 'platform',
      tenantId: null,
      requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
      traceparent: normalizedTraceparent,
      eventType: 'auth.platform_role_facts.updated',
      actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
      actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
      targetType: 'user',
      targetId: normalizedUserId,
      result: 'success',
      beforeState: {
        session_version: previousSessionVersion,
        role_facts: toPlatformRoleFactsAuditState(previousUser)
      },
      afterState: {
        session_version: nextSessionVersion,
        role_facts: toPlatformRoleFactsAuditState(nextUser)
      },
      metadata: {
        session_version_changed: sessionVersionChanged,
        sync_reason: syncReason || 'unknown'
      }
    });

    return result;
  };

  const tenantOptions = async ({
    requestId,
    accessToken,
    authorizationContext = null
  }) => {
    const { session, user } = await resolveAuthorizedSession({
      requestId,
      accessToken,
      authorizationContext
    });
    const sessionId = session.sessionId || session.session_id;
    let sessionContext = buildSessionContext(session);
    if (sessionContext.entry_domain !== 'tenant') {
      rejectNoDomainAccess({
        requestId,
        userId: user.id,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        tenantId: null,
        detail: `tenant options rejected for entry domain ${sessionContext.entry_domain}`
      });
    }
    const options = await getTenantOptionsForUser(user.id);
    sessionContext = await reconcileTenantSessionContext({
      requestId,
      userId: user.id,
      sessionId,
      sessionContext,
      options
    });
    const selectionRequired = sessionContext.entry_domain === 'tenant'
      && options.length > 1
      && !sessionContext.active_tenant_id;

    const tenantPermissionContext = await getTenantPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: sessionContext.active_tenant_id
    });
    const userName = await resolveLoginUserName({
      userId: user.id,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: sessionContext.active_tenant_id
    });

    return {
      session_id: sessionId,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: sessionContext.active_tenant_id,
      tenant_selection_required: selectionRequired,
      tenant_options: options,
      user_name: userName,
      tenant_permission_context: tenantPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  const platformOptions = async ({
    requestId,
    accessToken,
    authorizationContext = null
  }) => {
    const { session, user } = await resolveAuthorizedSession({
      requestId,
      accessToken,
      authorizationContext
    });
    const sessionId = session.sessionId || session.session_id;
    const sessionContext = buildSessionContext(session);
    if (sessionContext.entry_domain !== 'platform') {
      rejectNoDomainAccess({
        requestId,
        userId: user.id,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        tenantId: null,
        detail: `platform options rejected for entry domain ${sessionContext.entry_domain}`
      });
    }

    const platformPermissionContext = await getPlatformPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: sessionContext.entry_domain
    });
    const userName = await resolveLoginUserName({
      userId: user.id,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: null
    });

    return {
      session_id: sessionId,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: sessionContext.active_tenant_id,
      user_name: userName,
      platform_permission_context: platformPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  const authorizeRoute = async ({
    requestId,
    accessToken,
    permissionCode,
    scope = 'session',
    authorizationContext = null,
    authorizedSession = null
  }) => {
    const normalizedPermissionCode = String(permissionCode || '').trim();
    if (normalizedPermissionCode.length === 0) {
      throw errors.forbidden();
    }

    const resolvedSession = authorizedSession && typeof authorizedSession === 'object'
      ? authorizedSession
      : await resolveAuthorizedSession({
        requestId,
        accessToken,
        authorizationContext
      });
    const { session, user } = resolvedSession;
    const sessionId = session.sessionId || session.session_id;
    const sessionContext = buildSessionContext(session);
    const normalizedScope = String(scope || 'session').trim().toLowerCase();
    const normalizedActiveTenantId = normalizeTenantId(sessionContext.active_tenant_id);

    if (normalizedScope === 'tenant' && sessionContext.entry_domain !== 'tenant') {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: `tenant scoped route blocked in ${sessionContext.entry_domain} entry`,
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: sessionContext.active_tenant_id
        }
      });
      throw errors.noDomainAccess();
    }
    if (normalizedScope === 'platform' && sessionContext.entry_domain !== 'platform') {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: `platform scoped route blocked in ${sessionContext.entry_domain} entry`,
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: sessionContext.active_tenant_id
        }
      });
      throw errors.noDomainAccess();
    }
    if (
      normalizedScope === 'tenant'
      && sessionContext.entry_domain === 'tenant'
      && !normalizedActiveTenantId
      && !TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT.has(normalizedPermissionCode)
    ) {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: 'tenant scoped route blocked without active tenant context',
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: null
        }
      });
      throw errors.noDomainAccess();
    }

    const shouldResolveTenantPermissionContext =
      normalizedScope === 'tenant'
      && !TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT.has(normalizedPermissionCode);
    const shouldResolvePlatformPermissionContext = normalizedScope === 'platform';

    const tenantPermissionContext = shouldResolveTenantPermissionContext
      ? await getTenantPermissionContext({
        requestId,
        userId: user.id,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        activeTenantId: normalizedActiveTenantId
      })
      : null;
    const platformPermissionContext = shouldResolvePlatformPermissionContext
      ? await getPlatformPermissionContext({
        requestId,
        userId: user.id,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        permissionCode: normalizedPermissionCode
      })
      : null;

    const evaluator = ROUTE_PERMISSION_EVALUATORS[normalizedPermissionCode];
    if (typeof evaluator !== 'function') {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: `unknown permission code declaration: ${normalizedPermissionCode}`,
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: normalizedActiveTenantId
        }
      });
      throw errors.forbidden();
    }

    let allowed = evaluator({
      platformPermissionContext,
      tenantPermissionContext,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: normalizedActiveTenantId
    });
    const normalizedPermissionCodeKey = toPlatformPermissionCodeKey(
      normalizedPermissionCode
    );
    if (
      normalizedScope === 'platform'
      && ROLE_MANAGEMENT_PERMISSION_CODE_KEY_SET.has(normalizedPermissionCodeKey)
    ) {
      const grant = await resolveSystemConfigPermissionGrant({
        requestId,
        userId: user.id,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        permissionCode: normalizedPermissionCode
      });
      if (platformPermissionContext && typeof platformPermissionContext === 'object') {
        platformPermissionContext.can_view_role_management = grant.can_view_role_management;
        platformPermissionContext.can_operate_role_management = grant.can_operate_role_management;
      }
      allowed = grant.granted;
    }
    if (!allowed) {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: `permission denied: ${normalizedPermissionCode}`,
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: normalizedActiveTenantId
        }
      });
      throw errors.forbidden();
    }

    return {
      session_id: sessionId,
      user_id: user.id,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: normalizedActiveTenantId || null,
      platform_permission_context: platformPermissionContext,
      tenant_permission_context: tenantPermissionContext,
      session,
      user
    };
  };

  const resolveDefaultProvisioningPassword = async ({
    requestId,
    operatorUserId,
    operatorSessionId
  }) => {
    if (
      !sensitiveConfigProvider
      || typeof sensitiveConfigProvider.getEncryptedConfig !== 'function'
    ) {
      addAuditEvent({
        type: 'auth.user.provision.config_failed',
        requestId,
        userId: operatorUserId || 'unknown',
        sessionId: operatorSessionId || 'unknown',
        detail: 'default password config provider unavailable',
        metadata: {
          config_key: DEFAULT_PASSWORD_CONFIG_KEY,
          failure_reason: 'config-provider-unavailable'
        }
      });
      throw errors.provisioningConfigUnavailable();
    }

    let encryptedDefaultPassword;
    try {
      encryptedDefaultPassword = await sensitiveConfigProvider.getEncryptedConfig(
        DEFAULT_PASSWORD_CONFIG_KEY
      );
      const plainTextDefaultPassword = decryptSensitiveConfigValue({
        encryptedValue: encryptedDefaultPassword,
        decryptionKeys: sensitiveConfigDecryptionKeys,
        decryptionKey: sensitiveConfigDecryptionKey
      });
      validatePasswordPolicy(plainTextDefaultPassword);
      return plainTextDefaultPassword;
    } catch (error) {
      const failureReason = resolveProvisioningConfigFailureReason(error);
      addAuditEvent({
        type: 'auth.user.provision.config_failed',
        requestId,
        userId: operatorUserId || 'unknown',
        sessionId: operatorSessionId || 'unknown',
        detail: 'default password resolution failed',
        metadata: {
          config_key: DEFAULT_PASSWORD_CONFIG_KEY,
          failure_reason: failureReason
        }
      });
      throw errors.provisioningConfigUnavailable();
    }
  };

  const getOrCreateProvisionUserByPhone = async ({
    requestId,
    phone,
    operatorUserId,
    operatorSessionId
  }) => {
    const existingUser = await authStore.findUserByPhone(phone);
    if (existingUser) {
      return {
        user: existingUser,
        createdUser: false
      };
    }

    assertStoreMethod(authStore, 'createUserByPhone', 'authStore');
    const defaultPassword = await resolveDefaultProvisioningPassword({
      requestId,
      operatorUserId,
      operatorSessionId
    });
    let createdUser = null;
    try {
      createdUser = await authStore.createUserByPhone({
        phone,
        passwordHash: hashPassword(defaultPassword),
        status: 'active'
      });
    } catch (error) {
      if (isDataTooLongRoleFactError(error)) {
        throw errors.invalidPayload();
      }
      throw error;
    }
    if (createdUser) {
      return {
        user: createdUser,
        createdUser: true
      };
    }

    const reusedUser = await authStore.findUserByPhone(phone);
    if (reusedUser) {
      return {
        user: reusedUser,
        createdUser: false
      };
    }

    throw errors.provisionConflict();
  };

  const getOrCreateUserIdentityByPhone = async ({
    requestId,
    phone,
    operatorUserId = 'unknown',
    operatorSessionId = 'unknown'
  }) => {
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) {
      throw errors.invalidPayload();
    }

    const resolvedUser = await getOrCreateProvisionUserByPhone({
      requestId,
      phone: normalizedPhone,
      operatorUserId,
      operatorSessionId
    });

    addAuditEvent({
      type: resolvedUser.createdUser
        ? 'auth.user.bootstrap.created'
        : 'auth.user.bootstrap.reused',
      requestId,
      userId: resolvedUser.user.id,
      sessionId: operatorSessionId,
      detail: resolvedUser.createdUser
        ? 'owner user created with default password policy'
        : 'owner user identity reused without credential mutation',
      metadata: {
        operator_user_id: operatorUserId,
        phone_masked: maskPhone(normalizedPhone),
        credential_initialized: resolvedUser.createdUser,
        first_login_force_password_change: false
      }
    });

    return {
      user_id: resolvedUser.user.id,
      phone: resolvedUser.user.phone,
      created_user: resolvedUser.createdUser,
      reused_existing_user: !resolvedUser.createdUser,
      credential_initialized: resolvedUser.createdUser,
      first_login_force_password_change: false
    };
  };

  const createOrganizationWithOwner = async ({
    requestId = 'request_id_unset',
    traceparent = null,
    orgId = randomUUID(),
    orgName,
    ownerDisplayName = null,
    ownerUserId,
    operatorUserId,
    operatorSessionId = null
  }) => {
    const normalizedRequestId =
      normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset';
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);
    const normalizedOrgId = normalizeAuditStringOrNull(orgId, 64) || randomUUID();
    const normalizedOwnerUserId = normalizeAuditStringOrNull(ownerUserId, 64);
    const normalizedOperatorUserId = normalizeAuditStringOrNull(operatorUserId, 64);
    const normalizedOperatorSessionId = normalizeAuditStringOrNull(operatorSessionId, 128);
    const ownerDisplayNameCandidate = ownerDisplayName === null || ownerDisplayName === undefined
      ? null
      : String(ownerDisplayName || '').trim();
    const normalizedOwnerDisplayName = ownerDisplayNameCandidate
      && ownerDisplayNameCandidate.length <= MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH
      && !CONTROL_CHAR_PATTERN.test(ownerDisplayNameCandidate)
      ? ownerDisplayNameCandidate
      : null;
    assertStoreMethod(authStore, 'createOrganizationWithOwner', 'authStore');
    let createdOrg = null;
    try {
      createdOrg = await authStore.createOrganizationWithOwner({
        orgId: normalizedOrgId,
        orgName,
        ownerDisplayName: normalizedOwnerDisplayName,
        ownerUserId,
        operatorUserId,
        operatorSessionId: normalizedOperatorSessionId,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId
        }
      });
    } catch (error) {
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.auditDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw error;
    }
    if (!isPlainObject(createdOrg)) {
      throw errors.auditDependencyUnavailable({
        reason: 'org-create-result-invalid'
      });
    }
    const resolvedCreatedOrgId = normalizeAuditStringOrNull(
      resolveRawCamelSnakeField(createdOrg, 'orgId', 'org_id'),
      64
    );
    const resolvedCreatedOwnerUserId = normalizeAuditStringOrNull(
      resolveRawCamelSnakeField(createdOrg, 'ownerUserId', 'owner_user_id'),
      64
    );
    if (!resolvedCreatedOrgId || !resolvedCreatedOwnerUserId) {
      throw errors.auditDependencyUnavailable({
        reason: 'org-create-result-invalid'
      });
    }
    if (
      resolvedCreatedOrgId !== normalizedOrgId
      || resolvedCreatedOwnerUserId !== normalizedOwnerUserId
    ) {
      throw errors.auditDependencyUnavailable({
        reason: 'org-create-result-target-mismatch'
      });
    }
    const storeAuditRecorded = (
      createdOrg?.auditRecorded === true
      || createdOrg?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'tenant',
        tenantId: normalizedOrgId,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.org.create.succeeded',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'org',
        targetId: normalizedOrgId,
        result: 'success',
        beforeState: null,
        afterState: {
          org_id: resolvedCreatedOrgId,
          org_name: normalizeAuditStringOrNull(orgName, 128),
          owner_user_id: resolvedCreatedOwnerUserId
        },
        metadata: {
          operator_user_id: normalizedOperatorUserId
        }
      });
    }
    const createdOrgResponse = {
      ...(createdOrg || {})
    };
    delete createdOrgResponse.auditRecorded;
    delete createdOrgResponse.audit_recorded;
    return createdOrgResponse;
  };

  const acquireOwnerTransferLock = async ({
    orgId,
    requestId = 'request_id_unset',
    operatorUserId = 'unknown',
    timeoutSeconds = 0
  } = {}) => {
    const normalizedOrgId = String(orgId || '').trim();
    if (
      !normalizedOrgId
      || WHITESPACE_PATTERN.test(normalizedOrgId)
      || CONTROL_CHAR_PATTERN.test(normalizedOrgId)
      || normalizedOrgId.length > MAX_OWNER_TRANSFER_ORG_ID_LENGTH
    ) {
      return false;
    }
    const hasStoreAcquireOwnerTransferLock =
      authStore && typeof authStore.acquireOwnerTransferLock === 'function';
    const hasStoreReleaseOwnerTransferLock =
      authStore && typeof authStore.releaseOwnerTransferLock === 'function';
    if (!hasStoreAcquireOwnerTransferLock || !hasStoreReleaseOwnerTransferLock) {
      throw errors.ownerTransferLockUnavailable();
    }
    if (ownerTransferLocksByOrgId.has(normalizedOrgId)) {
      return false;
    }
    ownerTransferLocksByOrgId.set(normalizedOrgId, {
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      started_at: new Date(now()).toISOString()
    });
    try {
      const acquired = await authStore.acquireOwnerTransferLock({
        orgId: normalizedOrgId,
        requestId: String(requestId || '').trim() || 'request_id_unset',
        operatorUserId: String(operatorUserId || '').trim() || 'unknown',
        timeoutSeconds
      });
      if (acquired === true) {
        return true;
      }
      ownerTransferLocksByOrgId.delete(normalizedOrgId);
      return false;
    } catch (_error) {
      ownerTransferLocksByOrgId.delete(normalizedOrgId);
      throw errors.ownerTransferLockUnavailable();
    }
  };

  const releaseOwnerTransferLock = async ({
    orgId
  } = {}) => {
    const normalizedOrgId = String(orgId || '').trim();
    if (!normalizedOrgId) {
      return false;
    }
    ownerTransferLocksByOrgId.delete(normalizedOrgId);
    if (!authStore || typeof authStore.releaseOwnerTransferLock !== 'function') {
      return false;
    }
    try {
      const released = await authStore.releaseOwnerTransferLock({
        orgId: normalizedOrgId
      });
      return released === true;
    } catch (_error) {
      return false;
    }
  };

  const validateOwnerTransferRequest = async ({
    requestId,
    orgId,
    newOwnerPhone,
    operatorUserId,
    operatorSessionId,
    reason = null
  }) => {
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';

    if (typeof orgId !== 'string' || typeof newOwnerPhone !== 'string') {
      throw errors.invalidPayload();
    }
    const normalizedOrgId = orgId.trim();
    if (
      !normalizedOrgId
      || normalizedOrgId !== orgId
      || WHITESPACE_PATTERN.test(normalizedOrgId)
      || CONTROL_CHAR_PATTERN.test(normalizedOrgId)
      || normalizedOrgId.length > MAX_OWNER_TRANSFER_ORG_ID_LENGTH
    ) {
      throw errors.invalidPayload();
    }
    const normalizedNewOwnerPhone = normalizePhone(newOwnerPhone);
    if (!normalizedNewOwnerPhone || normalizedNewOwnerPhone !== newOwnerPhone) {
      throw errors.invalidPayload();
    }

    const normalizedOperatorUserId = String(operatorUserId || '').trim();
    const normalizedOperatorSessionId = String(operatorSessionId || '').trim();
    let normalizedReason = null;
    if (reason !== null && reason !== undefined) {
      if (typeof reason !== 'string') {
        throw errors.invalidPayload();
      }
      const trimmedReason = reason.trim();
      if (!trimmedReason || trimmedReason !== reason) {
        throw errors.invalidPayload();
      }
      if (CONTROL_CHAR_PATTERN.test(trimmedReason)) {
        throw errors.invalidPayload();
      }
      if (trimmedReason.length > MAX_OWNER_TRANSFER_REASON_LENGTH) {
        throw errors.invalidPayload();
      }
      normalizedReason = trimmedReason;
    }

    if (
      !normalizedOrgId
      || !normalizedNewOwnerPhone
      || !normalizedOperatorUserId
      || !normalizedOperatorSessionId
    ) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'findOrganizationById', 'authStore');
    assertStoreMethod(authStore, 'findUserByPhone', 'authStore');

    const org = await authStore.findOrganizationById({
      orgId: normalizedOrgId
    });
    if (!org) {
      throw errors.orgNotFound();
    }

    const oldOwnerUserId = String(
      org.owner_user_id || org.ownerUserId || ''
    ).trim();
    if (!oldOwnerUserId) {
      throw errors.invalidPayload();
    }

    const normalizedOrgStatus = normalizeOrgStatus(org.status);
    if (normalizedOrgStatus !== 'active') {
      throw errors.ownerTransferOrgNotActive({
        orgId: normalizedOrgId,
        oldOwnerUserId
      });
    }

    const candidateOwner = await authStore.findUserByPhone(normalizedNewOwnerPhone);
    if (!candidateOwner) {
      throw errors.userNotFound({
        extensions: {
          org_id: normalizedOrgId,
          old_owner_user_id: oldOwnerUserId
        }
      });
    }

    const newOwnerUserId = String(
      candidateOwner.id || candidateOwner.user_id || ''
    ).trim();
    if (!newOwnerUserId) {
      throw errors.invalidPayload();
    }
    if (!isUserActive(candidateOwner)) {
      throw errors.ownerTransferTargetUserInactive({
        orgId: normalizedOrgId,
        oldOwnerUserId,
        newOwnerUserId
      });
    }
    if (newOwnerUserId === oldOwnerUserId) {
      throw errors.ownerTransferSameOwner({
        orgId: normalizedOrgId,
        oldOwnerUserId
      });
    }

    addAuditEvent({
      type: 'auth.org.owner_transfer.validated',
      requestId: normalizedRequestId,
      userId: normalizedOperatorUserId,
      sessionId: normalizedOperatorSessionId,
      detail: 'owner transfer request validated',
      metadata: {
        org_id: normalizedOrgId,
        old_owner_user_id: oldOwnerUserId,
        new_owner_user_id: newOwnerUserId,
        new_owner_phone_masked: maskPhone(normalizedNewOwnerPhone),
        reason: normalizedReason
      }
    });

    return {
      org_id: normalizedOrgId,
      old_owner_user_id: oldOwnerUserId,
      new_owner_user_id: newOwnerUserId
    };
  };

  const executeOwnerTransferTakeover = async ({
    requestId,
    traceparent = null,
    orgId,
    newOwnerPhone,
    operatorUserId,
    operatorSessionId,
    reason = null
  }) => {
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedReason = reason === null || reason === undefined
      ? null
      : String(reason || '').trim() || null;

    const validationResult = await validateOwnerTransferRequest({
      requestId: normalizedRequestId,
      orgId,
      newOwnerPhone,
      operatorUserId,
      operatorSessionId,
      reason: normalizedReason
    });
    const validatedOrgId = String(validationResult?.org_id || '').trim();
    const validatedOldOwnerUserId = String(
      validationResult?.old_owner_user_id || ''
    ).trim();
    const validatedNewOwnerUserId = String(
      validationResult?.new_owner_user_id || ''
    ).trim();
    if (
      !validatedOrgId
      || !validatedOldOwnerUserId
      || !validatedNewOwnerUserId
    ) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'owner-transfer-validation-result-invalid'
      });
    }
    const takeoverRoleId = toOwnerTransferTakeoverRoleId({
      orgId: validatedOrgId
    });
    if (!takeoverRoleId) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'owner-transfer-takeover-role-id-invalid'
      });
    }

    assertStoreMethod(authStore, 'executeOwnerTransferTakeover', 'authStore');
    let takeoverResult = null;
    try {
      takeoverResult = await authStore.executeOwnerTransferTakeover({
        requestId: normalizedRequestId,
        orgId: validatedOrgId,
        oldOwnerUserId: validatedOldOwnerUserId,
        newOwnerUserId: validatedNewOwnerUserId,
        operatorUserId,
        operatorSessionId,
        reason: normalizedReason,
        takeoverRoleId,
        takeoverRoleCode: OWNER_TRANSFER_TAKEOVER_ROLE_CODE,
        takeoverRoleName: OWNER_TRANSFER_TAKEOVER_ROLE_NAME,
        requiredPermissionCodes: [...OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES],
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizeAuditStringOrNull(traceparent, 128),
          actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
          actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
          reason: normalizedReason
        }
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      const normalizedStoreErrorCode = String(error?.code || '').trim();
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_ORG_NOT_FOUND') {
        throw errors.orgNotFound();
      }
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_ORG_NOT_ACTIVE') {
        throw errors.ownerTransferOrgNotActive({
          orgId: validatedOrgId,
          oldOwnerUserId: validatedOldOwnerUserId
        });
      }
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_SAME_OWNER') {
        throw errors.ownerTransferSameOwner({
          orgId: validatedOrgId,
          oldOwnerUserId: validatedOldOwnerUserId
        });
      }
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_NEW_OWNER_NOT_FOUND') {
        throw errors.userNotFound({
          extensions: {
            org_id: validatedOrgId,
            old_owner_user_id: validatedOldOwnerUserId
          }
        });
      }
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_NEW_OWNER_INACTIVE') {
        throw errors.ownerTransferTargetUserInactive({
          orgId: validatedOrgId,
          oldOwnerUserId: validatedOldOwnerUserId,
          newOwnerUserId: validatedNewOwnerUserId
        });
      }
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_INVALID') {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'owner-transfer-takeover-role-invalid'
        });
      }
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_PRECONDITION_FAILED') {
        throw errors.ownerTransferConflict({
          orgId: validatedOrgId,
          oldOwnerUserId: validatedOldOwnerUserId,
          newOwnerUserId: validatedNewOwnerUserId
        });
      }
      if (normalizedStoreErrorCode === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw errors.tenantMemberDependencyUnavailable({
        reason: normalizedStoreErrorCode
          || String(error?.message || 'owner-transfer-takeover-write-failed').trim()
          || 'owner-transfer-takeover-write-failed'
      });
    }

    const resolvedOrgId = String(takeoverResult?.org_id || '').trim();
    const resolvedOldOwnerUserId = String(
      takeoverResult?.old_owner_user_id || ''
    ).trim();
    const resolvedNewOwnerUserId = String(
      takeoverResult?.new_owner_user_id || ''
    ).trim();
    if (
      !resolvedOrgId
      || !resolvedOldOwnerUserId
      || !resolvedNewOwnerUserId
      || resolvedOrgId !== validatedOrgId
      || resolvedOldOwnerUserId !== validatedOldOwnerUserId
      || resolvedNewOwnerUserId !== validatedNewOwnerUserId
    ) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'owner-transfer-takeover-result-invalid'
      });
    }

    invalidateSessionCacheByUserId(resolvedNewOwnerUserId);
    addAuditEvent({
      type: 'auth.org.owner_transfer.executed',
      requestId: normalizedRequestId,
      userId: String(operatorUserId || '').trim() || 'unknown',
      sessionId: String(operatorSessionId || '').trim() || 'unknown',
      detail: 'owner transfer takeover committed',
      metadata: {
        org_id: resolvedOrgId,
        old_owner_user_id: resolvedOldOwnerUserId,
        new_owner_user_id: resolvedNewOwnerUserId
      }
    });
    const storeAuditRecorded = (
      takeoverResult?.auditRecorded === true
      || takeoverResult?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'tenant',
        tenantId: resolvedOrgId,
        requestId: normalizedRequestId,
        traceparent: normalizeAuditStringOrNull(traceparent, 128),
        eventType: 'auth.org.owner_transfer.executed',
        actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
        actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
        targetType: 'org',
        targetId: resolvedOrgId,
        result: 'success',
        beforeState: {
          owner_user_id: resolvedOldOwnerUserId
        },
        afterState: {
          owner_user_id: resolvedNewOwnerUserId
        },
        metadata: {
          old_owner_user_id: resolvedOldOwnerUserId,
          new_owner_user_id: resolvedNewOwnerUserId,
          reason: normalizedReason
        }
      });
    }

    return {
      org_id: resolvedOrgId,
      old_owner_user_id: resolvedOldOwnerUserId,
      new_owner_user_id: resolvedNewOwnerUserId
    };
  };

  const createPlatformRoleCatalogEntry = async ({
    requestId = 'request_id_unset',
    traceparent = null,
    roleId,
    code,
    name,
    status = 'active',
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null,
    isSystem = false,
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedCode = normalizeRequiredStringField(
      code,
      errors.invalidPayload
    );
    const normalizedName = normalizeRequiredStringField(
      name,
      errors.invalidPayload
    );
    const normalizedStatus = normalizePlatformRoleCatalogStatus(status);
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (
      !VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)
      || !VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)
    ) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    const normalizedRequestId =
      normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset';
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);
    const normalizedOperatorUserId = normalizeAuditStringOrNull(operatorUserId, 64);
    const normalizedOperatorSessionId = normalizeAuditStringOrNull(operatorSessionId, 128);

    assertStoreMethod(authStore, 'createPlatformRoleCatalogEntry', 'authStore');
    let createdRole = null;
    try {
      createdRole = await authStore.createPlatformRoleCatalogEntry({
        roleId: normalizedRoleId,
        code: normalizedCode,
        name: normalizedName,
        status: normalizedStatus === 'enabled' ? 'active' : normalizedStatus,
        scope: normalizedScope,
        tenantId: normalizedTenantId,
        isSystem: Boolean(isSystem),
        operatorUserId: normalizedOperatorUserId,
        operatorSessionId: normalizedOperatorSessionId,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId
        }
      });
    } catch (error) {
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.auditDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw error;
    }
    if (!isPlainObject(createdRole)) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-create-result-invalid'
      });
    }
    const resolvedCreatedRoleId = normalizeAuditStringOrNull(
      resolveRawCamelSnakeField(createdRole, 'roleId', 'role_id'),
      64
    );
    if (!resolvedCreatedRoleId) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-create-result-invalid'
      });
    }
    if (resolvedCreatedRoleId !== normalizedRoleId) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-create-result-target-mismatch'
      });
    }
    const storeAuditRecorded = (
      createdRole?.auditRecorded === true
      || createdRole?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
        tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.role.catalog.created',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'role',
        targetId: normalizedRoleId,
        result: 'success',
        beforeState: null,
        afterState: {
          role_id: normalizedRoleId,
          code: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(createdRole, 'code', 'code'),
            64
          ) || normalizedCode,
          name: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(createdRole, 'name', 'name'),
            128
          ) || normalizedName,
          status: normalizePlatformRoleCatalogStatus(
            resolveRawCamelSnakeField(createdRole, 'status', 'status')
              || (normalizedStatus === 'enabled' ? 'active' : normalizedStatus)
          ),
          scope: normalizedScope,
          tenant_id: normalizedScope === 'tenant' ? normalizedTenantId : null,
          is_system: Boolean(
            resolveRawCamelSnakeField(createdRole, 'isSystem', 'is_system')
              ?? Boolean(isSystem)
          )
        },
        metadata: {
          scope: normalizedScope
        }
      });
    }
    const createdRoleResponse = {
      ...(createdRole || {})
    };
    delete createdRoleResponse.auditRecorded;
    delete createdRoleResponse.audit_recorded;
    return createdRoleResponse;
  };

  const updatePlatformRoleCatalogEntry = async ({
    requestId = 'request_id_unset',
    traceparent = null,
    roleId,
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null,
    code = undefined,
    name = undefined,
    status = undefined,
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    const normalizedRequestId =
      normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset';
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);
    const normalizedOperatorUserId = normalizeAuditStringOrNull(operatorUserId, 64);
    const normalizedOperatorSessionId = normalizeAuditStringOrNull(operatorSessionId, 128);
    const updates = {};
    if (code !== undefined) {
      updates.code = normalizeRequiredStringField(code, errors.invalidPayload);
    }
    if (name !== undefined) {
      updates.name = normalizeRequiredStringField(name, errors.invalidPayload);
    }
    if (status !== undefined) {
      const normalizedStatus = normalizePlatformRoleCatalogStatus(status);
      if (!VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)) {
        throw errors.invalidPayload();
      }
      updates.status = normalizedStatus === 'enabled'
        ? 'active'
        : normalizedStatus;
    }
    let previousRole = null;
    if (typeof authStore.findPlatformRoleCatalogEntryByRoleId === 'function') {
      try {
        previousRole = await authStore.findPlatformRoleCatalogEntryByRoleId({
          roleId: normalizedRoleId,
          scope: normalizedScope,
          tenantId: normalizedTenantId
        });
      } catch (_error) {
      }
    }
    assertStoreMethod(authStore, 'updatePlatformRoleCatalogEntry', 'authStore');
    let updatedRole = null;
    try {
      updatedRole = await authStore.updatePlatformRoleCatalogEntry({
        roleId: normalizedRoleId,
        scope: normalizedScope,
        tenantId: normalizedTenantId,
        ...updates,
        operatorUserId: normalizedOperatorUserId,
        operatorSessionId: normalizedOperatorSessionId,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId
        }
      });
    } catch (error) {
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.auditDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw error;
    }
    if (!updatedRole) {
      return updatedRole;
    }
    if (!isPlainObject(updatedRole)) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-update-result-invalid'
      });
    }
    const resolvedUpdatedRoleId = normalizeAuditStringOrNull(
      resolveRawCamelSnakeField(updatedRole, 'roleId', 'role_id'),
      64
    );
    if (!resolvedUpdatedRoleId) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-update-result-invalid'
      });
    }
    if (resolvedUpdatedRoleId !== normalizedRoleId) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-update-result-target-mismatch'
      });
    }
    let statusSyncResult = null;
    if (Object.prototype.hasOwnProperty.call(updates, 'status')) {
      const previousRoleStatusRaw = resolveRawCamelSnakeField(
        previousRole,
        'status',
        'status'
      );
      const hasKnownPreviousRoleStatus = normalizePlatformRoleCatalogStatus(
        previousRoleStatusRaw
      ).length > 0;
      const previousRoleStatus = normalizeRoleCatalogStatusForResync(
        previousRoleStatusRaw
      );
      const currentRoleStatus = normalizeRoleCatalogStatusForResync(
        resolveRawCamelSnakeField(updatedRole, 'status', 'status')
      );
      if (!hasKnownPreviousRoleStatus || previousRoleStatus !== currentRoleStatus) {
        statusSyncResult = await resyncRoleStatusAffectedSnapshots({
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          roleId: normalizedRoleId,
          scope: normalizedScope,
          tenantId: normalizedTenantId,
          previousStatus: previousRoleStatusRaw,
          currentStatus: resolveRawCamelSnakeField(updatedRole, 'status', 'status'),
          operatorUserId: normalizedOperatorUserId,
          operatorSessionId: normalizedOperatorSessionId
        });
      }
    }
    const storeAuditRecorded = (
      updatedRole?.auditRecorded === true
      || updatedRole?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
        tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.role.catalog.updated',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'role',
        targetId: normalizedRoleId,
        result: 'success',
        beforeState: previousRole
          ? {
            code: normalizeAuditStringOrNull(
              resolveRawCamelSnakeField(previousRole, 'code', 'code'),
              64
            ),
            name: normalizeAuditStringOrNull(
              resolveRawCamelSnakeField(previousRole, 'name', 'name'),
              128
            ),
            status: normalizePlatformRoleCatalogStatus(
              resolveRawCamelSnakeField(previousRole, 'status', 'status') || 'active'
            )
          }
          : null,
        afterState: {
          code: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(updatedRole, 'code', 'code'),
            64
          ),
          name: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(updatedRole, 'name', 'name'),
            128
          ),
          status: normalizePlatformRoleCatalogStatus(
            resolveRawCamelSnakeField(updatedRole, 'status', 'status') || 'active'
          )
        },
        metadata: {
          scope: normalizedScope,
          changed_fields: Object.keys(updates),
          affected_user_count: Number(statusSyncResult?.affectedUserCount || 0),
          affected_membership_count: Number(statusSyncResult?.affectedMembershipCount || 0)
        }
      });
    }
    const updatedRoleResponse = {
      ...(updatedRole || {})
    };
    if (statusSyncResult) {
      updatedRoleResponse.affected_user_count = Number(
        statusSyncResult.affectedUserCount || 0
      );
      updatedRoleResponse.affected_membership_count = Number(
        statusSyncResult.affectedMembershipCount || 0
      );
    }
    delete updatedRoleResponse.auditRecorded;
    delete updatedRoleResponse.audit_recorded;
    return updatedRoleResponse;
  };

  const deletePlatformRoleCatalogEntry = async ({
    requestId = 'request_id_unset',
    traceparent = null,
    roleId,
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null,
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    const normalizedRequestId =
      normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset';
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);
    const normalizedOperatorUserId = normalizeAuditStringOrNull(operatorUserId, 64);
    const normalizedOperatorSessionId = normalizeAuditStringOrNull(operatorSessionId, 128);
    let previousRole = null;
    if (typeof authStore.findPlatformRoleCatalogEntryByRoleId === 'function') {
      try {
        previousRole = await authStore.findPlatformRoleCatalogEntryByRoleId({
          roleId: normalizedRoleId,
          scope: normalizedScope,
          tenantId: normalizedTenantId
        });
      } catch (_error) {
      }
    }
    assertStoreMethod(authStore, 'deletePlatformRoleCatalogEntry', 'authStore');
    let deletedRole = null;
    try {
      deletedRole = await authStore.deletePlatformRoleCatalogEntry({
        roleId: normalizedRoleId,
        scope: normalizedScope,
        tenantId: normalizedTenantId,
        operatorUserId: normalizedOperatorUserId,
        operatorSessionId: normalizedOperatorSessionId,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId
        }
      });
    } catch (error) {
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.auditDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw error;
    }
    if (!deletedRole) {
      return deletedRole;
    }
    if (!isPlainObject(deletedRole)) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-delete-result-invalid'
      });
    }
    const resolvedDeletedRoleId = normalizeAuditStringOrNull(
      resolveRawCamelSnakeField(deletedRole, 'roleId', 'role_id'),
      64
    );
    if (!resolvedDeletedRoleId) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-delete-result-invalid'
      });
    }
    if (resolvedDeletedRoleId !== normalizedRoleId) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-delete-result-target-mismatch'
      });
    }
    const statusSyncResult = await resyncRoleStatusAffectedSnapshots({
      requestId: normalizedRequestId,
      traceparent: normalizedTraceparent,
      roleId: normalizedRoleId,
      scope: normalizedScope,
      tenantId: normalizedTenantId,
      previousStatus: resolveRawCamelSnakeField(previousRole, 'status', 'status'),
      currentStatus: resolveRawCamelSnakeField(deletedRole, 'status', 'status'),
      operatorUserId: normalizedOperatorUserId,
      operatorSessionId: normalizedOperatorSessionId
    });
    const storeAuditRecorded = (
      deletedRole?.auditRecorded === true
      || deletedRole?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      const deletedRoleBeforeAuditSource = (
        previousRole && typeof previousRole === 'object'
          ? previousRole
          : deletedRole
      );
      await recordPersistentAuditEvent({
        domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
        tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.role.catalog.deleted',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'role',
        targetId: normalizedRoleId,
        result: 'success',
        beforeState: {
          code: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(deletedRoleBeforeAuditSource, 'code', 'code'),
            64
          ),
          name: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(deletedRoleBeforeAuditSource, 'name', 'name'),
            128
          ),
          status: normalizePlatformRoleCatalogStatus(
            resolveRawCamelSnakeField(deletedRoleBeforeAuditSource, 'status', 'status')
            || 'disabled'
          )
        },
        afterState: {
          status: 'disabled'
        },
        metadata: {
          scope: normalizedScope,
          affected_user_count: Number(statusSyncResult?.affectedUserCount || 0),
          affected_membership_count: Number(statusSyncResult?.affectedMembershipCount || 0)
        }
      });
    }
    const deletedRoleResponse = {
      ...(deletedRole || {})
    };
    deletedRoleResponse.affected_user_count = Number(
      statusSyncResult?.affectedUserCount || 0
    );
    deletedRoleResponse.affected_membership_count = Number(
      statusSyncResult?.affectedMembershipCount || 0
    );
    delete deletedRoleResponse.auditRecorded;
    delete deletedRoleResponse.audit_recorded;
    return deletedRoleResponse;
  };

  const listPlatformRoleCatalogEntries = async ({
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null
  } = {}) => {
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    assertStoreMethod(authStore, 'listPlatformRoleCatalogEntries', 'authStore');
    return authStore.listPlatformRoleCatalogEntries({
      scope: normalizedScope,
      tenantId: normalizedTenantId
    });
  };

  const findPlatformRoleCatalogEntryByRoleId = async ({
    roleId,
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null
  } = {}) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    assertStoreMethod(authStore, 'findPlatformRoleCatalogEntryByRoleId', 'authStore');
    return authStore.findPlatformRoleCatalogEntryByRoleId({
      roleId: normalizedRoleId,
      scope: normalizedScope,
      tenantId: normalizedTenantId
    });
  };

  const recordSystemSensitiveConfigAuditEvent = async ({
    requestId = 'request_id_unset',
    traceparent = null,
    actorUserId = null,
    actorSessionId = null,
    targetId = DEFAULT_PASSWORD_CONFIG_KEY,
    eventType = 'auth.system_config.updated',
    result = 'success',
    beforeState = null,
    afterState = null,
    metadata = null
  } = {}) => {
    const normalizedEventType =
      normalizeStrictRequiredStringField(eventType) || 'auth.system_config.updated';
    const normalizedEventTypeKey = normalizedEventType.toLowerCase();
    const isRejectedEventType =
      REJECTED_SYSTEM_CONFIG_AUDIT_EVENT_TYPES.has(normalizedEventTypeKey);
    const normalizedTargetId = normalizeSystemSensitiveConfigKey(targetId);
    const hasSupportedTargetId =
      Boolean(normalizedTargetId)
      && SUPPORTED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(normalizedTargetId);
    if (!hasSupportedTargetId && !isRejectedEventType) {
      throw errors.invalidPayload();
    }
    const resolvedTargetId = hasSupportedTargetId
      ? normalizedTargetId
      : (normalizedTargetId || null);
    return recordPersistentAuditEvent({
      domain: 'platform',
      tenantId: null,
      requestId,
      traceparent,
      eventType: normalizedEventType,
      actorUserId,
      actorSessionId,
      targetType: 'system_config',
      targetId: resolvedTargetId,
      result,
      beforeState,
      afterState,
      metadata
    });
  };

  const getSystemSensitiveConfig = async ({
    configKey = DEFAULT_PASSWORD_CONFIG_KEY
  } = {}) => {
    const normalizedConfigKey = normalizeSystemSensitiveConfigKey(configKey);
    if (
      !normalizedConfigKey
      || !SUPPORTED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(normalizedConfigKey)
    ) {
      throw errors.invalidPayload();
    }
    assertStoreMethod(authStore, 'getSystemSensitiveConfig', 'authStore');
    const record = await authStore.getSystemSensitiveConfig({
      configKey: normalizedConfigKey
    });
    return toSystemSensitiveConfigRecord(record);
  };

  const upsertSystemSensitiveConfig = async ({
    requestId,
    traceparent = null,
    configKey = DEFAULT_PASSWORD_CONFIG_KEY,
    encryptedValue,
    expectedVersion,
    updatedByUserId,
    updatedBySessionId = null,
    status = 'active'
  } = {}) => {
    const normalizedRequestId =
      normalizeAuditRequestIdOrNull(requestId) || 'request_id_unset';
    const normalizedTraceparent = bindRequestTraceparent({
      requestId: normalizedRequestId,
      traceparent
    });
    const normalizedConfigKey = normalizeSystemSensitiveConfigKey(configKey);
    if (
      !normalizedConfigKey
      || !SUPPORTED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(normalizedConfigKey)
    ) {
      throw errors.invalidPayload();
    }
    const normalizedEncryptedValue = String(encryptedValue || '').trim();
    if (
      !normalizedEncryptedValue
      || CONTROL_CHAR_PATTERN.test(normalizedEncryptedValue)
    ) {
      throw errors.invalidPayload();
    }
    const parsedExpectedVersion = Number(expectedVersion);
    if (!Number.isInteger(parsedExpectedVersion) || parsedExpectedVersion < 0) {
      throw errors.invalidPayload();
    }
    const normalizedStatus = normalizeSystemSensitiveConfigStatus(status);
    if (!normalizedStatus) {
      throw errors.invalidPayload();
    }
    const normalizedUpdatedByUserId = normalizeStrictRequiredStringField(updatedByUserId);
    const normalizedUpdatedBySessionId = normalizeStrictRequiredStringField(updatedBySessionId);
    if (!normalizedUpdatedByUserId || !normalizedUpdatedBySessionId) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'upsertSystemSensitiveConfig', 'authStore');
    let normalizedSavedRecord = null;
    try {
      const savedRecord = await authStore.upsertSystemSensitiveConfig({
        configKey: normalizedConfigKey,
        encryptedValue: normalizedEncryptedValue,
        expectedVersion: parsedExpectedVersion,
        updatedByUserId: normalizedUpdatedByUserId,
        status: normalizedStatus
      });
      normalizedSavedRecord = toSystemSensitiveConfigRecord(savedRecord);
      if (!normalizedSavedRecord) {
        throw new Error('system-sensitive-config-upsert-result-invalid');
      }
    } catch (error) {
      const currentVersion = Number(error?.currentVersion ?? error?.current_version ?? -1);
      const expectedVersionValue = Number(
        error?.expectedVersion ?? error?.expected_version ?? parsedExpectedVersion
      );
      const isVersionConflict =
        String(error?.code || '').trim() === 'ERR_SYSTEM_SENSITIVE_CONFIG_VERSION_CONFLICT';
      addAuditEvent({
        type: 'auth.system_config.update.rejected',
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        userId: normalizedUpdatedByUserId,
        sessionId: normalizedUpdatedBySessionId,
        detail: isVersionConflict
          ? 'system sensitive config version conflict'
          : 'system sensitive config update failed',
        metadata: {
          config_key: normalizedConfigKey,
          expected_version: expectedVersionValue,
          current_version: Number.isInteger(currentVersion) && currentVersion >= 0
            ? currentVersion
            : null,
          failure_reason: isVersionConflict
            ? 'version-conflict'
            : String(error?.code || error?.message || 'unknown').trim().toLowerCase()
        }
      });
      await recordSystemSensitiveConfigAuditEvent({
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        actorUserId: normalizedUpdatedByUserId,
        actorSessionId: normalizedUpdatedBySessionId,
        targetId: normalizedConfigKey,
        eventType: 'auth.system_config.update.rejected',
        result: 'rejected',
        beforeState: Number.isInteger(currentVersion) && currentVersion >= 0
          ? { version: currentVersion }
          : null,
        afterState: null,
        metadata: {
          config_key: normalizedConfigKey,
          expected_version: expectedVersionValue,
          current_version: Number.isInteger(currentVersion) && currentVersion >= 0
            ? currentVersion
            : null,
          failure_reason: isVersionConflict
            ? 'version-conflict'
            : String(error?.code || error?.message || 'unknown').trim().toLowerCase()
        }
      }).catch(() => {});
      throw error;
    }

    addAuditEvent({
      type: 'auth.system_config.updated',
      requestId: normalizedRequestId,
      traceparent: normalizedTraceparent,
      userId: normalizedUpdatedByUserId,
      sessionId: normalizedUpdatedBySessionId,
      detail: 'system sensitive config updated',
      metadata: {
        config_key: normalizedConfigKey,
        previous_version: normalizedSavedRecord.previousVersion,
        current_version: normalizedSavedRecord.version,
        status: normalizedSavedRecord.status
      }
    });
    try {
      await recordSystemSensitiveConfigAuditEvent({
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        actorUserId: normalizedUpdatedByUserId,
        actorSessionId: normalizedUpdatedBySessionId,
        targetId: normalizedConfigKey,
        eventType: 'auth.system_config.updated',
        result: 'success',
        beforeState: {
          version: normalizedSavedRecord.previousVersion
        },
        afterState: {
          version: normalizedSavedRecord.version,
          status: normalizedSavedRecord.status
        },
        metadata: {
          config_key: normalizedConfigKey,
          previous_version: normalizedSavedRecord.previousVersion,
          current_version: normalizedSavedRecord.version,
          status: normalizedSavedRecord.status
        }
      });
    } catch (error) {
      addAuditEvent({
        type: 'auth.system_config.audit.degraded',
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        userId: normalizedUpdatedByUserId,
        sessionId: normalizedUpdatedBySessionId,
        detail: 'system sensitive config persistent audit degraded',
        metadata: {
          config_key: normalizedConfigKey,
          previous_version: normalizedSavedRecord.previousVersion,
          current_version: normalizedSavedRecord.version,
          status: normalizedSavedRecord.status,
          failure_reason: String(
            error?.errorCode
              || error?.code
              || error?.message
              || 'audit-write-failed'
          ).trim().toLowerCase()
        }
      });
    }

    return normalizedSavedRecord;
  };

  const listPlatformPermissionCatalog = () =>
    listSupportedPlatformPermissionCodes();

  const listPlatformPermissionCatalogEntries = () =>
    listPlatformPermissionCatalogItems();

  const listPlatformRolePermissionGrants = async ({ roleId }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const {
      requestedRoleIds
    } = await loadValidatedPlatformRoleCatalogEntriesForRoleFacts({
      roles: [{ roleId: normalizedRoleId }],
      allowDisabledRoles: true
    });
    const grantsByRoleIdKey = await loadPlatformRolePermissionGrantsByRoleIds({
      roleIds: requestedRoleIds
    });
    const grants = grantsByRoleIdKey.get(normalizePlatformRoleIdKey(normalizedRoleId)) || [];
    return {
      role_id: normalizedRoleId,
      permission_codes: grants,
      available_permission_codes: listPlatformPermissionCatalog(),
      available_permissions: listPlatformPermissionCatalogEntries()
    };
  };

  const toDistinctNormalizedUserIds = (userIds = []) =>
    [...new Set(
      (Array.isArray(userIds) ? userIds : [])
        .map((userId) => String(userId || '').trim())
        .filter((userId) => userId.length > 0)
    )];

  const normalizeStrictDistinctUserIdsFromPlatformDependency = ({
    userIds,
    dependencyReason = 'platform-role-permission-grants-update-affected-user-ids-invalid'
  } = {}) => {
    if (!Array.isArray(userIds)) {
      throw errors.platformSnapshotDegraded({
        reason: dependencyReason
      });
    }
    const normalizedUserIds = [];
    const seenUserIds = new Set();
    for (const userId of userIds) {
      if (typeof userId !== 'string') {
        throw errors.platformSnapshotDegraded({
          reason: dependencyReason
        });
      }
      const normalizedUserId = userId.trim();
      if (
        userId !== normalizedUserId
        || !normalizedUserId
        || CONTROL_CHAR_PATTERN.test(normalizedUserId)
      ) {
        throw errors.platformSnapshotDegraded({
          reason: dependencyReason
        });
      }
      if (seenUserIds.has(normalizedUserId)) {
        continue;
      }
      seenUserIds.add(normalizedUserId);
      normalizedUserIds.push(normalizedUserId);
    }
    return normalizedUserIds;
  };

  const normalizeStrictNonNegativeIntegerFromPlatformDependency = ({
    value,
    dependencyReason = 'platform-role-permission-grants-update-affected-user-count-invalid'
  } = {}) => {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
      throw errors.platformSnapshotDegraded({
        reason: dependencyReason
      });
    }
    return value;
  };

  const normalizeStrictDistinctUserIdsFromDependency = ({
    userIds,
    dependencyReason = 'tenant-role-permission-grants-update-affected-user-ids-invalid'
  } = {}) => {
    if (!Array.isArray(userIds)) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: dependencyReason
      });
    }
    const normalizedUserIds = [];
    const seenUserIds = new Set();
    for (const userId of userIds) {
      if (typeof userId !== 'string') {
        throw errors.tenantMemberDependencyUnavailable({
          reason: dependencyReason
        });
      }
      const normalizedUserId = userId.trim();
      if (
        userId !== normalizedUserId
        || !normalizedUserId
        || CONTROL_CHAR_PATTERN.test(normalizedUserId)
      ) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: dependencyReason
        });
      }
      if (seenUserIds.has(normalizedUserId)) {
        continue;
      }
      seenUserIds.add(normalizedUserId);
      normalizedUserIds.push(normalizedUserId);
    }
    return normalizedUserIds;
  };

  const normalizeStrictNonNegativeIntegerFromDependency = ({
    value,
    dependencyReason = 'tenant-role-permission-grants-update-affected-user-count-invalid'
  } = {}) => {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: dependencyReason
      });
    }
    return value;
  };

  const normalizeOrgStatusCascadeCountFromDependency = ({
    value,
    dependencyReason = 'org-status-cascade-count-invalid'
  } = {}) => {
    if (value === undefined || value === null) {
      return 0;
    }
    if (
      typeof value !== 'number'
      || !Number.isInteger(value)
      || value < 0
    ) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: dependencyReason
      });
    }
    return Math.min(value, MAX_ORG_STATUS_CASCADE_COUNT);
  };

  const normalizeStoredRoleFactsForPermissionResync = (roleFacts = []) => {
    const normalizedStoredRoleFacts = [];
    for (const roleFact of Array.isArray(roleFacts) ? roleFacts : []) {
      let normalizedRoleFactRoleId;
      try {
        normalizedRoleFactRoleId = normalizeRequiredStringField(
          resolveRawRoleIdCandidate(roleFact),
          errors.invalidPayload
        );
      } catch (_error) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-role-facts-invalid'
        });
      }
      const normalizedRoleFactRoleIdKey =
        normalizePlatformRoleIdKey(normalizedRoleFactRoleId);
      const normalizedRoleFactStatusInput = String(
        roleFact?.status || 'active'
      ).trim().toLowerCase();
      if (!VALID_PLATFORM_ROLE_FACT_STATUS.has(normalizedRoleFactStatusInput)) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-role-facts-invalid'
        });
      }
      const normalizedRoleFactStatus = normalizedRoleFactStatusInput === 'enabled'
        ? 'active'
        : normalizedRoleFactStatusInput;
      normalizedStoredRoleFacts.push({
        roleIdKey: normalizedRoleFactRoleIdKey,
        status: normalizedRoleFactStatus
      });
    }
    return normalizedStoredRoleFacts;
  };

  const cloneRoleFactsSnapshotForRollback = (roleFacts = []) =>
    (Array.isArray(roleFacts) ? roleFacts : []).map((roleFact) => ({
      roleId: String(roleFact?.roleId || roleFact?.role_id || '').trim(),
      role_id: String(roleFact?.roleId || roleFact?.role_id || '').trim(),
      status: String(roleFact?.status || 'active').trim().toLowerCase() || 'active',
      permission:
        roleFact?.permission
        && typeof roleFact.permission === 'object'
        && !Array.isArray(roleFact.permission)
          ? {
            canViewUserManagement: Boolean(
              roleFact.permission.canViewUserManagement
              ?? roleFact.permission.can_view_user_management
            ),
            canOperateUserManagement: Boolean(
              roleFact.permission.canOperateUserManagement
              ?? roleFact.permission.can_operate_user_management
            ),
            canViewTenantManagement: Boolean(
              roleFact.permission.canViewTenantManagement
              ?? roleFact.permission.can_view_tenant_management
            ),
            canOperateTenantManagement: Boolean(
              roleFact.permission.canOperateTenantManagement
              ?? roleFact.permission.can_operate_tenant_management
            )
          }
          : null
    }));

  const normalizeRoleCatalogStatusForResync = (status) => {
    const normalizedStatus = normalizePlatformRoleCatalogStatus(status);
    return normalizedStatus || 'disabled';
  };

  const isPlatformCatalogRoleActiveForPermissionResync = (catalogEntry = null) => {
    if (!catalogEntry || typeof catalogEntry !== 'object') {
      return false;
    }
    const normalizedScope = normalizePlatformRoleCatalogScope(
      resolveRawCamelSnakeField(catalogEntry, 'scope', 'scope')
    );
    const normalizedTenantId = normalizeTenantId(
      resolveRawCamelSnakeField(catalogEntry, 'tenantId', 'tenant_id')
    );
    const normalizedStatus = normalizeRoleCatalogStatusForResync(
      resolveRawCamelSnakeField(catalogEntry, 'status', 'status')
    );
    return normalizedScope === PLATFORM_ROLE_CATALOG_SCOPE
      && !normalizedTenantId
      && (normalizedStatus === 'active' || normalizedStatus === 'enabled');
  };

  const resyncPlatformRoleStatusAffectedSnapshots = async ({
    roleId,
    requestId = 'request_id_unset'
  } = {}) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    if (
      typeof authStore.listUserIdsByPlatformRoleId !== 'function'
      || typeof authStore.listPlatformRoleFactsByUserId !== 'function'
      || typeof authStore.replacePlatformRolesAndSyncSnapshot !== 'function'
      || typeof authStore.findPlatformRoleCatalogEntriesByRoleIds !== 'function'
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-status-resync-unsupported'
      });
    }

    let affectedUserIds = [];
    try {
      affectedUserIds = await authStore.listUserIdsByPlatformRoleId({
        roleId: normalizedRoleId
      });
    } catch (_error) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-status-affected-users-query-failed'
      });
    }
    const normalizedAffectedUserIds = toDistinctNormalizedUserIds(affectedUserIds);
    if (normalizedAffectedUserIds.length === 0) {
      return {
        affectedUserCount: 0,
        affectedMembershipCount: 0
      };
    }

    const preSyncRoleFactsByUserId = new Map();
    const normalizedRoleFactsByUserId = new Map();
    const normalizedAllRoleIds = new Set();
    for (const normalizedAffectedUserId of normalizedAffectedUserIds) {
      let roleFacts = [];
      try {
        roleFacts = await authStore.listPlatformRoleFactsByUserId({
          userId: normalizedAffectedUserId
        });
      } catch (_error) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-status-role-facts-query-failed'
        });
      }
      preSyncRoleFactsByUserId.set(
        normalizedAffectedUserId,
        cloneRoleFactsSnapshotForRollback(roleFacts)
      );
      const normalizedStoredRoleFacts = normalizeStoredRoleFactsForPermissionResync(roleFacts);
      normalizedRoleFactsByUserId.set(
        normalizedAffectedUserId,
        normalizedStoredRoleFacts
      );
      for (const roleFact of normalizedStoredRoleFacts) {
        normalizedAllRoleIds.add(roleFact.roleIdKey);
      }
    }

    let grantsByRoleIdKey = new Map();
    try {
      grantsByRoleIdKey = await loadPlatformRolePermissionGrantsByRoleIds({
        roleIds: [...normalizedAllRoleIds]
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-status-permission-grants-query-failed'
      });
    }

    let catalogEntries = [];
    try {
      catalogEntries = await authStore.findPlatformRoleCatalogEntriesByRoleIds({
        roleIds: [...normalizedAllRoleIds]
      });
    } catch (_error) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-status-catalog-query-failed'
      });
    }
    const activeCatalogRoleIdSet = new Set(
      (Array.isArray(catalogEntries) ? catalogEntries : [])
        .filter((catalogEntry) =>
          isPlatformCatalogRoleActiveForPermissionResync(catalogEntry)
        )
        .map((catalogEntry) =>
          normalizePlatformRoleIdKey(
            resolveRawCamelSnakeField(catalogEntry, 'roleId', 'role_id')
          )
        )
        .filter((roleIdKey) => roleIdKey.length > 0)
    );

    const syncedUserIds = [];
    try {
      for (const normalizedAffectedUserId of normalizedAffectedUserIds) {
        const normalizedStoredRoleFacts =
          normalizedRoleFactsByUserId.get(normalizedAffectedUserId) || [];
        const nextRoleFacts = normalizedStoredRoleFacts.map((roleFact) => {
          const permissionCodes = activeCatalogRoleIdSet.has(roleFact.roleIdKey)
            ? (grantsByRoleIdKey.get(roleFact.roleIdKey) || [])
            : [];
          return {
            roleId: roleFact.roleIdKey,
            status: roleFact.status,
            permission: toPlatformPermissionSnapshotFromCodes(permissionCodes)
          };
        });
        let syncResult;
        try {
          syncResult = await authStore.replacePlatformRolesAndSyncSnapshot({
            userId: normalizedAffectedUserId,
            roles: nextRoleFacts
          });
        } catch (_error) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-status-resync-failed'
          });
        }
        const syncReason = String(syncResult?.reason || 'unknown').trim().toLowerCase();
        if (syncReason !== 'ok') {
          throw errors.platformSnapshotDegraded({
            reason: syncReason || 'platform-role-status-resync-failed'
          });
        }
        syncedUserIds.push(normalizedAffectedUserId);
        invalidateSessionCacheByUserId(normalizedAffectedUserId);
      }
    } catch (error) {
      try {
        for (const syncedUserId of [...syncedUserIds].reverse()) {
          const rollbackRoleFacts = preSyncRoleFactsByUserId.get(syncedUserId) || [];
          const rollbackResult = await authStore.replacePlatformRolesAndSyncSnapshot({
            userId: syncedUserId,
            roles: rollbackRoleFacts
          });
          const rollbackReason = String(
            rollbackResult?.reason || 'unknown'
          ).trim().toLowerCase();
          if (rollbackReason !== 'ok') {
            throw new Error(
              `platform-role-status-resync-rollback-failed:${rollbackReason || 'unknown'}`
            );
          }
          invalidateSessionCacheByUserId(syncedUserId);
        }
      } catch (_rollbackError) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-status-compensation-failed'
        });
      }
      if (error instanceof AuthProblemError) {
        throw error;
      }
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-status-resync-failed'
      });
    }

    addAuditEvent({
      type: 'auth.role.catalog.status.sync',
      requestId,
      userId: 'system',
      sessionId: 'system',
      detail: 'platform role status change resynced affected platform snapshots',
      metadata: {
        role_id: normalizedRoleId,
        scope: PLATFORM_ROLE_CATALOG_SCOPE,
        tenant_id: null,
        affected_user_count: syncedUserIds.length,
        affected_membership_count: 0
      }
    });

    return {
      affectedUserCount: syncedUserIds.length,
      affectedMembershipCount: 0
    };
  };

  const resyncTenantRoleStatusAffectedSnapshots = async ({
    tenantId,
    roleId,
    requestId = 'request_id_unset',
    operatorUserId = null,
    operatorSessionId = null
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedRoleId = normalizeStrictAddressableTenantRoleIdFromInput(roleId);
    if (!normalizedTenantId) {
      throw errors.invalidPayload();
    }
    if (typeof authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots !== 'function') {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-role-status-resync-unsupported'
      });
    }

    let currentPermissionCodes = [];
    try {
      const grantsByRoleIdKey = await loadTenantRolePermissionGrantsByRoleIds({
        roleIds: [normalizedRoleId]
      });
      currentPermissionCodes =
        grantsByRoleIdKey.get(normalizePlatformRoleIdKey(normalizedRoleId)) || [];
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-role-status-permission-grants-query-failed'
      });
    }

    let syncResult = null;
    try {
      syncResult = await authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots({
        tenantId: normalizedTenantId,
        roleId: normalizedRoleId,
        permissionCodes: currentPermissionCodes,
        operatorUserId,
        operatorSessionId,
        maxAffectedMemberships: MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      if (
        String(error?.code || '').trim()
        === 'ERR_TENANT_ROLE_PERMISSION_AFFECTED_MEMBERSHIPS_OVER_LIMIT'
      ) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-role-status-affected-memberships-over-limit'
        });
      }
      if (String(error?.code || '').trim() === 'ERR_TENANT_ROLE_PERMISSION_SYNC_FAILED') {
        throw errors.tenantMemberDependencyUnavailable({
          reason: String(error?.syncReason || 'tenant-role-status-resync-failed')
        });
      }
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-role-status-resync-failed'
      });
    }

    if (!syncResult) {
      return {
        affectedUserCount: 0,
        affectedMembershipCount: 0
      };
    }

    const affectedUserIdsRaw = (
      resolveRawCamelSnakeField(syncResult, 'affectedUserIds', 'affected_user_ids')
    );
    const affectedUserIds = toDistinctNormalizedUserIds(affectedUserIdsRaw);
    const hasExplicitAffectedMembershipCount = (
      hasOwnProperty(syncResult, 'affectedMembershipCount')
      || hasOwnProperty(syncResult, 'affected_membership_count')
    );
    const affectedMembershipCount = hasExplicitAffectedMembershipCount
      ? normalizeStrictNonNegativeIntegerFromDependency({
        value: resolveRawCamelSnakeField(
          syncResult,
          'affectedMembershipCount',
          'affected_membership_count'
        ),
        dependencyReason: 'tenant-role-status-affected-membership-count-invalid'
      })
      : affectedUserIds.length;
    for (const affectedUserId of affectedUserIds) {
      invalidateSessionCacheByUserId(affectedUserId);
    }

    addAuditEvent({
      type: 'auth.role.catalog.status.sync',
      requestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: 'tenant role status change resynced affected tenant snapshots',
      metadata: {
        role_id: normalizedRoleId,
        scope: TENANT_ROLE_SCOPE,
        tenant_id: normalizedTenantId,
        affected_user_count: affectedUserIds.length,
        affected_membership_count: affectedMembershipCount
      }
    });

    return {
      affectedUserCount: affectedUserIds.length,
      affectedMembershipCount
    };
  };

  const resyncRoleStatusAffectedSnapshots = async ({
    requestId = 'request_id_unset',
    traceparent = null,
    roleId,
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null,
    previousStatus = null,
    currentStatus = null,
    operatorUserId = null,
    operatorSessionId = null
  } = {}) => {
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedTenantId = normalizedScope === TENANT_ROLE_SCOPE
      ? normalizeTenantId(tenantId)
      : null;
    if (normalizedScope === TENANT_ROLE_SCOPE && !normalizedTenantId) {
      throw errors.invalidPayload();
    }

    let affectedUserCount = 0;
    let affectedMembershipCount = 0;
    if (normalizedScope === TENANT_ROLE_SCOPE) {
      const result = await resyncTenantRoleStatusAffectedSnapshots({
        tenantId: normalizedTenantId,
        roleId: normalizedRoleId,
        requestId,
        operatorUserId,
        operatorSessionId
      });
      affectedUserCount = Number(result?.affectedUserCount || 0);
      affectedMembershipCount = Number(result?.affectedMembershipCount || 0);
    } else {
      const result = await resyncPlatformRoleStatusAffectedSnapshots({
        roleId: normalizedRoleId,
        requestId
      });
      affectedUserCount = Number(result?.affectedUserCount || 0);
      affectedMembershipCount = Number(result?.affectedMembershipCount || 0);
    }

    await recordPersistentAuditEvent({
      domain: normalizedScope === TENANT_ROLE_SCOPE ? 'tenant' : 'platform',
      tenantId: normalizedScope === TENANT_ROLE_SCOPE ? normalizedTenantId : null,
      requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
      traceparent: normalizeAuditStringOrNull(traceparent, 128),
      eventType: 'auth.role.catalog.status_synced',
      actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
      actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
      targetType: 'role',
      targetId: normalizedRoleId,
      result: 'success',
      beforeState: {
        status: normalizeRoleCatalogStatusForResync(previousStatus),
        scope: normalizedScope,
        tenant_id: normalizedScope === TENANT_ROLE_SCOPE ? normalizedTenantId : null
      },
      afterState: {
        status: normalizeRoleCatalogStatusForResync(currentStatus),
        scope: normalizedScope,
        tenant_id: normalizedScope === TENANT_ROLE_SCOPE ? normalizedTenantId : null
      },
      metadata: {
        affected_user_count: affectedUserCount,
        affected_membership_count: affectedMembershipCount
      }
    });

    return {
      affectedUserCount,
      affectedMembershipCount
    };
  };

  const replacePlatformRolePermissionGrants = async ({
    requestId,
    traceparent = null,
    roleId,
    permissionCodes = [],
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedTargetRoleIdKey = normalizePlatformRoleIdKey(normalizedRoleId);
    if (!Array.isArray(permissionCodes)) {
      throw errors.invalidPayload();
    }
    if (permissionCodes.length > MAX_ROLE_PERMISSION_CODES_PER_REQUEST) {
      throw errors.invalidPayload();
    }
    const dedupedPermissionCodes = new Map();
    for (const permissionCode of permissionCodes) {
      const normalizedPermissionCode = normalizePlatformPermissionCode(permissionCode);
      if (!normalizedPermissionCode) {
        throw errors.invalidPayload();
      }
      const permissionCodeKey = toPlatformPermissionCodeKey(normalizedPermissionCode);
      if (
        !isPlatformPermissionCode(normalizedPermissionCode)
        || !SUPPORTED_PLATFORM_PERMISSION_CODE_SET.has(permissionCodeKey)
      ) {
        throw errors.invalidPayload();
      }
      dedupedPermissionCodes.set(permissionCodeKey, permissionCodeKey);
    }
    const normalizedPermissionCodes = [...dedupedPermissionCodes.values()];

    await loadValidatedPlatformRoleCatalogEntriesForRoleFacts({
      roles: [{ roleId: normalizedRoleId }],
      allowDisabledRoles: true
    });
    let previousPermissionCodesForAudit = null;
    let previousTargetRolePermissionCodes = null;
    try {
      const previousGrantsByRoleIdKey = await loadPlatformRolePermissionGrantsByRoleIds({
        roleIds: [normalizedRoleId]
      });
      const resolvedPreviousPermissionCodes =
        previousGrantsByRoleIdKey.get(normalizedTargetRoleIdKey) || [];
      previousPermissionCodesForAudit = [...resolvedPreviousPermissionCodes];
      previousTargetRolePermissionCodes = [...resolvedPreviousPermissionCodes];
    } catch (_error) {
      previousPermissionCodesForAudit = null;
      previousTargetRolePermissionCodes = null;
    }

    if (typeof authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots === 'function') {
      let atomicWriteResult;
      try {
        atomicWriteResult =
          await authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots({
            roleId: normalizedRoleId,
            permissionCodes: normalizedPermissionCodes,
            operatorUserId,
            operatorSessionId,
            auditContext: {
              requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
              traceparent: normalizeAuditStringOrNull(traceparent, 128),
              actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
              actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128)
            },
            maxAffectedUsers: MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS
          });
      } catch (error) {
        if (error instanceof AuthProblemError) {
          throw error;
        }
        if (String(error?.code || '').trim()
          === 'ERR_PLATFORM_ROLE_PERMISSION_AFFECTED_USERS_OVER_LIMIT') {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-affected-users-over-limit'
          });
        }
        if (String(error?.code || '').trim() === 'ERR_PLATFORM_ROLE_PERMISSION_SYNC_FAILED') {
          throw errors.platformSnapshotDegraded({
            reason: String(error?.syncReason || 'platform-role-permission-resync-failed')
          });
        }
        if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
          throw errors.platformSnapshotDegraded({
            reason: 'audit-write-failed'
          });
        }
        const normalizedErrorMessage = String(error?.message || '')
          .trim()
          .toLowerCase();
        throw errors.platformSnapshotDegraded({
          reason: normalizedErrorMessage.includes('deadlock')
            ? 'db-deadlock'
            : 'platform-role-permission-atomic-write-failed'
        });
      }

      if (!atomicWriteResult) {
        throw errors.roleNotFound();
      }

      const rawResolvedRoleId = (
        resolveRawCamelSnakeField(
          atomicWriteResult,
          'roleId',
          'role_id'
        )
      );
      const resolvedRoleId = normalizeStrictRequiredStringField(rawResolvedRoleId).toLowerCase();
      if (!resolvedRoleId || resolvedRoleId !== normalizedRoleId) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-update-role-mismatch'
        });
      }

      const savedPermissionCodes = Array.isArray(atomicWriteResult?.permissionCodes)
        ? atomicWriteResult.permissionCodes
        : Array.isArray(atomicWriteResult?.permission_codes)
          ? atomicWriteResult.permission_codes
          : [];
      const normalizedSavedPermissionCodeKeys = [];
      const seenSavedPermissionCodeKeys = new Set();
      for (const permissionCode of savedPermissionCodes) {
        const normalizedPermissionCode = normalizeStrictRequiredStringField(permissionCode);
        const permissionCodeKey = toPlatformPermissionCodeKey(normalizedPermissionCode);
        if (
          !normalizedPermissionCode
          || CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)
          || seenSavedPermissionCodeKeys.has(permissionCodeKey)
          || !isPlatformPermissionCode(normalizedPermissionCode)
          || !SUPPORTED_PLATFORM_PERMISSION_CODE_SET.has(permissionCodeKey)
        ) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-grants-update-invalid'
          });
        }
        seenSavedPermissionCodeKeys.add(permissionCodeKey);
        normalizedSavedPermissionCodeKeys.push(permissionCodeKey);
      }
      normalizedSavedPermissionCodeKeys.sort((left, right) => left.localeCompare(right));
      const expectedPermissionCodeKeys = [...normalizedPermissionCodes]
        .sort((left, right) => left.localeCompare(right));
      const hasPermissionCodesMismatch = (
        expectedPermissionCodeKeys.length !== normalizedSavedPermissionCodeKeys.length
        || expectedPermissionCodeKeys.some(
          (permissionCode, index) => permissionCode !== normalizedSavedPermissionCodeKeys[index]
        )
      );
      if (hasPermissionCodesMismatch) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-update-mismatch'
        });
      }
      const hasAffectedUserIds = (
        hasOwnProperty(atomicWriteResult, 'affectedUserIds')
        || hasOwnProperty(atomicWriteResult, 'affected_user_ids')
      );
      const hasExplicitAffectedUserCount = (
        hasOwnProperty(atomicWriteResult, 'affectedUserCount')
        || hasOwnProperty(atomicWriteResult, 'affected_user_count')
      );
      if (!hasAffectedUserIds || !hasExplicitAffectedUserCount) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-update-affected-user-metadata-missing'
        });
      }
      const affectedUserIds = normalizeStrictDistinctUserIdsFromPlatformDependency({
        userIds: resolveRawCamelSnakeField(
          atomicWriteResult,
          'affectedUserIds',
          'affected_user_ids'
        ),
        dependencyReason: 'platform-role-permission-grants-update-affected-user-ids-invalid'
      });
      const resyncedUserCount = normalizeStrictNonNegativeIntegerFromPlatformDependency({
        value: resolveRawCamelSnakeField(
          atomicWriteResult,
          'affectedUserCount',
          'affected_user_count'
        ),
        dependencyReason: 'platform-role-permission-grants-update-affected-user-count-invalid'
      });
      if (
        hasExplicitAffectedUserCount
        && resyncedUserCount !== affectedUserIds.length
      ) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-update-affected-user-count-invalid'
        });
      }
      for (const affectedUserId of affectedUserIds) {
        invalidateSessionCacheByUserId(affectedUserId);
      }

      addAuditEvent({
        type: 'auth.platform_role_permission_grants.updated',
        requestId,
        userId: operatorUserId || 'unknown',
        sessionId: operatorSessionId || 'unknown',
        detail: 'platform role permission grants replaced and affected snapshots resynced',
        metadata: {
          role_id: normalizedRoleId,
          permission_codes: normalizedSavedPermissionCodeKeys,
          affected_user_count: resyncedUserCount
        }
      });
      const storeAuditRecorded = (
        atomicWriteResult?.auditRecorded === true
        || atomicWriteResult?.audit_recorded === true
      );
      if (!storeAuditRecorded) {
        await recordPersistentAuditEvent({
          domain: 'platform',
          tenantId: null,
          requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
          traceparent: normalizeAuditStringOrNull(traceparent, 128),
          eventType: 'auth.platform_role_permission_grants.updated',
          actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
          actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
          targetType: 'role_permission_grants',
          targetId: normalizedRoleId,
          result: 'success',
          beforeState: {
            permission_codes: Array.isArray(previousPermissionCodesForAudit)
              ? [...previousPermissionCodesForAudit]
              : null
          },
          afterState: {
            permission_codes: [...normalizedSavedPermissionCodeKeys]
          },
          metadata: {
            affected_user_count: resyncedUserCount
          }
        });
      }

      return {
        role_id: normalizedRoleId,
        permission_codes: normalizedSavedPermissionCodeKeys,
        affected_user_count: resyncedUserCount
      };
    }

    if (typeof authStore.replacePlatformRolePermissionGrants !== 'function') {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-grants-unsupported'
      });
    }
    if (
      typeof authStore.listUserIdsByPlatformRoleId !== 'function'
      || typeof authStore.listPlatformRoleFactsByUserId !== 'function'
      || typeof authStore.replacePlatformRolesAndSyncSnapshot !== 'function'
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-resync-unsupported'
      });
    }

    let affectedUserIds = [];
    try {
      affectedUserIds = await authStore.listUserIdsByPlatformRoleId({
        roleId: normalizedRoleId
      });
    } catch (_error) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-affected-users-query-failed'
      });
    }
    const precheckedAffectedUserIds = toDistinctNormalizedUserIds(affectedUserIds);
    for (const normalizedAffectedUserId of precheckedAffectedUserIds) {
      try {
        await authStore.listPlatformRoleFactsByUserId({
          userId: normalizedAffectedUserId
        });
      } catch (_error) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-role-facts-query-failed'
        });
      }
    }

    if (!Array.isArray(previousTargetRolePermissionCodes)) {
      try {
        const previousTargetRoleGrantsByRoleIdKey =
          await loadPlatformRolePermissionGrantsByRoleIds({
            roleIds: [normalizedRoleId]
          });
        previousTargetRolePermissionCodes =
          previousTargetRoleGrantsByRoleIdKey.get(normalizedTargetRoleIdKey) || [];
        previousPermissionCodesForAudit = [...previousTargetRolePermissionCodes];
      } catch (error) {
        if (error instanceof AuthProblemError) {
          throw error;
        }
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-query-failed'
        });
      }
    }

    let savedPermissionCodes = [];
    let grantsWriteApplied = false;
    const preSyncRoleFactsByUserId = new Map();
    const normalizedRoleFactsByUserId = new Map();
    const syncedUserIds = [];
    try {
      const saved = await authStore.replacePlatformRolePermissionGrants({
        roleId: normalizedRoleId,
        permissionCodes: normalizedPermissionCodes,
        operatorUserId,
        operatorSessionId
      });
      if (!saved) {
        throw errors.roleNotFound();
      }
      savedPermissionCodes = [...new Set(
        (Array.isArray(saved) ? saved : [])
          .map((permissionCode) => normalizePlatformPermissionCode(permissionCode))
          .filter((permissionCode) => permissionCode.length > 0)
      )];
      grantsWriteApplied = true;

      let postWriteAffectedUserIds = [];
      try {
        postWriteAffectedUserIds = await authStore.listUserIdsByPlatformRoleId({
          roleId: normalizedRoleId
        });
      } catch (_error) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-affected-users-query-failed'
        });
      }
      const normalizedAffectedUserIds = [...new Set([
        ...precheckedAffectedUserIds,
        ...toDistinctNormalizedUserIds(postWriteAffectedUserIds)
      ])];

      const normalizedAllRoleIds = new Set();
      for (const normalizedAffectedUserId of normalizedAffectedUserIds) {
        let roleFacts = [];
        try {
          roleFacts = await authStore.listPlatformRoleFactsByUserId({
            userId: normalizedAffectedUserId
          });
        } catch (_error) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-role-facts-query-failed'
          });
        }
        preSyncRoleFactsByUserId.set(
          normalizedAffectedUserId,
          cloneRoleFactsSnapshotForRollback(roleFacts)
        );
        const normalizedStoredRoleFacts = normalizeStoredRoleFactsForPermissionResync(roleFacts);
        normalizedRoleFactsByUserId.set(
          normalizedAffectedUserId,
          normalizedStoredRoleFacts
        );
        for (const roleFact of normalizedStoredRoleFacts) {
          normalizedAllRoleIds.add(roleFact.roleIdKey);
        }
      }

      let grantsByRoleIdKey = new Map();
      try {
        grantsByRoleIdKey = await loadPlatformRolePermissionGrantsByRoleIds({
          roleIds: [...normalizedAllRoleIds]
        });
      } catch (error) {
        if (error instanceof AuthProblemError) {
          throw error;
        }
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-query-failed'
        });
      }

      for (const normalizedAffectedUserId of normalizedAffectedUserIds) {
        const normalizedStoredRoleFacts =
          normalizedRoleFactsByUserId.get(normalizedAffectedUserId) || [];
        const nextRoleFacts = normalizedStoredRoleFacts.map((roleFact) => {
          const permissionCodes = grantsByRoleIdKey.get(roleFact.roleIdKey) || [];
          return {
            roleId: roleFact.roleIdKey,
            status: roleFact.status,
            permission: toPlatformPermissionSnapshotFromCodes(permissionCodes)
          };
        });

        let syncResult;
        try {
          syncResult = await authStore.replacePlatformRolesAndSyncSnapshot({
            userId: normalizedAffectedUserId,
            roles: nextRoleFacts
          });
        } catch (_error) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-resync-failed'
          });
        }
        const syncReason = String(syncResult?.reason || 'unknown').trim().toLowerCase();
        if (syncReason !== 'ok') {
          throw errors.platformSnapshotDegraded({
            reason: syncReason || 'platform-role-permission-resync-failed'
          });
        }
        syncedUserIds.push(normalizedAffectedUserId);
        invalidateSessionCacheByUserId(normalizedAffectedUserId);
      }
    } catch (error) {
      if (grantsWriteApplied) {
        try {
          const restoredGrants = await authStore.replacePlatformRolePermissionGrants({
            roleId: normalizedRoleId,
            permissionCodes: previousTargetRolePermissionCodes,
            operatorUserId,
            operatorSessionId
          });
          if (!restoredGrants) {
            throw new Error('platform-role-permission-grants-rollback-role-not-found');
          }
          for (const syncedUserId of [...syncedUserIds].reverse()) {
            const rollbackRoleFacts = preSyncRoleFactsByUserId.get(syncedUserId) || [];
            const rollbackResult = await authStore.replacePlatformRolesAndSyncSnapshot({
              userId: syncedUserId,
              roles: rollbackRoleFacts
            });
            const rollbackReason = String(
              rollbackResult?.reason || 'unknown'
            ).trim().toLowerCase();
            if (rollbackReason !== 'ok') {
              throw new Error(`platform-role-permission-resync-rollback-failed:${rollbackReason}`);
            }
            invalidateSessionCacheByUserId(syncedUserId);
          }
        } catch (_rollbackError) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-compensation-failed'
          });
        }
      }
      if (error instanceof AuthProblemError) {
        throw error;
      }
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-resync-failed'
      });
    }
    const resyncedUserCount = syncedUserIds.length;

    addAuditEvent({
      type: 'auth.platform_role_permission_grants.updated',
      requestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: 'platform role permission grants replaced and affected snapshots resynced',
      metadata: {
        role_id: normalizedRoleId,
        permission_codes: savedPermissionCodes,
        affected_user_count: resyncedUserCount
      }
    });
    await recordPersistentAuditEvent({
      domain: 'platform',
      tenantId: null,
      requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
      traceparent: normalizeAuditStringOrNull(traceparent, 128),
      eventType: 'auth.platform_role_permission_grants.updated',
      actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
      actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
      targetType: 'role_permission_grants',
      targetId: normalizedRoleId,
      result: 'success',
      beforeState: {
        permission_codes: Array.isArray(previousPermissionCodesForAudit)
          ? [...previousPermissionCodesForAudit]
          : null
      },
      afterState: {
        permission_codes: [...savedPermissionCodes]
      },
      metadata: {
        affected_user_count: resyncedUserCount
      }
    });

    return {
      role_id: normalizedRoleId,
      permission_codes: savedPermissionCodes,
      affected_user_count: resyncedUserCount
    };
  };

  const listTenantPermissionCatalog = () =>
    listSupportedTenantPermissionCodes();

  const listTenantPermissionCatalogEntries = () =>
    listTenantPermissionCatalogItems();

  const listTenantRolePermissionGrants = async ({
    tenantId,
    roleId
  }) => {
    const normalizedRoleId =
      normalizeStrictAddressableTenantRoleIdFromInput(roleId);
    const {
      requestedRoleIds
    } = await loadValidatedTenantRoleCatalogEntries({
      tenantId,
      roleIds: [normalizedRoleId],
      allowDisabledRoles: true
    });
    const grantsByRoleIdKey = await loadTenantRolePermissionGrantsByRoleIds({
      roleIds: requestedRoleIds
    });
    const grants = grantsByRoleIdKey.get(normalizePlatformRoleIdKey(normalizedRoleId)) || [];
    return {
      role_id: normalizedRoleId,
      permission_codes: grants,
      available_permission_codes: listTenantPermissionCatalog(),
      available_permissions: listTenantPermissionCatalogEntries()
    };
  };

  const replaceTenantRolePermissionGrants = async ({
    requestId,
    traceparent = null,
    tenantId,
    roleId,
    permissionCodes = [],
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId =
      normalizeStrictAddressableTenantRoleIdFromInput(roleId);
    if (!Array.isArray(permissionCodes)) {
      throw errors.invalidPayload();
    }
    if (permissionCodes.length > MAX_ROLE_PERMISSION_CODES_PER_REQUEST) {
      throw errors.invalidPayload();
    }
    const dedupedPermissionCodes = new Map();
    for (const permissionCode of permissionCodes) {
      const normalizedPermissionCode = normalizeTenantPermissionCode(permissionCode);
      if (!normalizedPermissionCode) {
        throw errors.invalidPayload();
      }
      if (CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)) {
        throw errors.invalidPayload();
      }
      const permissionCodeKey = toTenantPermissionCodeKey(normalizedPermissionCode);
      if (
        !isTenantPermissionCode(normalizedPermissionCode)
        || !SUPPORTED_TENANT_PERMISSION_CODE_SET.has(permissionCodeKey)
      ) {
        throw errors.invalidPayload();
      }
      dedupedPermissionCodes.set(permissionCodeKey, permissionCodeKey);
    }
    const normalizedPermissionCodes = [...dedupedPermissionCodes.values()];

    await loadValidatedTenantRoleCatalogEntries({
      tenantId,
      roleIds: [normalizedRoleId],
      allowDisabledRoles: true
    });
    const normalizedTenantId = normalizeTenantId(tenantId);
    let previousPermissionCodesForAudit = null;
    try {
      const previousGrantsByRoleIdKey = await loadTenantRolePermissionGrantsByRoleIds({
        roleIds: [normalizedRoleId]
      });
      previousPermissionCodesForAudit =
        previousGrantsByRoleIdKey.get(normalizePlatformRoleIdKey(normalizedRoleId)) || [];
    } catch (_error) {
      previousPermissionCodesForAudit = null;
    }

    if (typeof authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots !== 'function') {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-role-permission-grants-unsupported'
      });
    }

    let atomicWriteResult;
    try {
      atomicWriteResult = await authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots({
        tenantId,
        roleId: normalizedRoleId,
        permissionCodes: normalizedPermissionCodes,
        operatorUserId,
        operatorSessionId,
        auditContext: {
          requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
          traceparent: normalizeAuditStringOrNull(traceparent, 128),
          actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
          actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128)
        },
        maxAffectedMemberships: MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      if (String(error?.code || '').trim()
        === 'ERR_TENANT_ROLE_PERMISSION_AFFECTED_MEMBERSHIPS_OVER_LIMIT') {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-role-permission-affected-memberships-over-limit'
        });
      }
      if (String(error?.code || '').trim() === 'ERR_TENANT_ROLE_PERMISSION_SYNC_FAILED') {
        throw errors.tenantMemberDependencyUnavailable({
          reason: String(error?.syncReason || 'tenant-role-permission-resync-failed')
        });
      }
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      const normalizedErrorMessage = String(error?.message || '')
        .trim()
        .toLowerCase();
      throw errors.tenantMemberDependencyUnavailable({
        reason: normalizedErrorMessage.includes('deadlock')
          ? 'db-deadlock'
          : 'tenant-role-permission-atomic-write-failed'
      });
    }

    if (!atomicWriteResult) {
      throw errors.roleNotFound();
    }

    const rawResolvedRoleId = (
      resolveRawCamelSnakeField(
        atomicWriteResult,
        'roleId',
        'role_id'
      )
    );
    const resolvedRoleId = normalizeStrictRequiredStringField(rawResolvedRoleId)
      .toLowerCase();
    if (!resolvedRoleId || resolvedRoleId !== normalizedRoleId) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-role-permission-grants-update-role-mismatch'
      });
    }

    const savedPermissionCodes = Array.isArray(atomicWriteResult?.permissionCodes)
      ? atomicWriteResult.permissionCodes
      : Array.isArray(atomicWriteResult?.permission_codes)
        ? atomicWriteResult.permission_codes
        : [];
    const normalizedSavedPermissionCodeKeys = [];
    const seenSavedPermissionCodeKeys = new Set();
    for (const permissionCode of savedPermissionCodes) {
      const normalizedPermissionCode =
        normalizeStrictRequiredStringField(permissionCode);
      const permissionCodeKey = toTenantPermissionCodeKey(normalizedPermissionCode);
      if (
        !normalizedPermissionCode
        || CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)
        || seenSavedPermissionCodeKeys.has(permissionCodeKey)
        || !isTenantPermissionCode(normalizedPermissionCode)
        || !SUPPORTED_TENANT_PERMISSION_CODE_SET.has(permissionCodeKey)
      ) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-role-permission-grants-update-invalid'
        });
      }
      seenSavedPermissionCodeKeys.add(permissionCodeKey);
      normalizedSavedPermissionCodeKeys.push(permissionCodeKey);
    }
    normalizedSavedPermissionCodeKeys.sort((left, right) => left.localeCompare(right));
    const expectedPermissionCodeKeys = [...normalizedPermissionCodes]
      .sort((left, right) => left.localeCompare(right));
    const hasPermissionCodesMismatch = (
      expectedPermissionCodeKeys.length !== normalizedSavedPermissionCodeKeys.length
      || expectedPermissionCodeKeys.some(
        (permissionCode, index) => permissionCode !== normalizedSavedPermissionCodeKeys[index]
      )
    );
    if (hasPermissionCodesMismatch) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-role-permission-grants-update-mismatch'
      });
    }
    const hasAffectedUserIds = (
      hasOwnProperty(atomicWriteResult, 'affectedUserIds')
      || hasOwnProperty(atomicWriteResult, 'affected_user_ids')
    );
    const hasExplicitAffectedUserCount = (
      hasOwnProperty(atomicWriteResult, 'affectedUserCount')
      || hasOwnProperty(atomicWriteResult, 'affected_user_count')
    );
    if (!hasAffectedUserIds || !hasExplicitAffectedUserCount) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-role-permission-grants-update-affected-user-metadata-missing'
      });
    }
    const affectedUserIds = normalizeStrictDistinctUserIdsFromDependency({
      userIds: resolveRawCamelSnakeField(
        atomicWriteResult,
        'affectedUserIds',
        'affected_user_ids'
      )
    });
    const affectedUserCount = normalizeStrictNonNegativeIntegerFromDependency({
      value: resolveRawCamelSnakeField(
        atomicWriteResult,
        'affectedUserCount',
        'affected_user_count'
      ),
      dependencyReason: 'tenant-role-permission-grants-update-affected-user-count-invalid'
    });
    if (
      hasExplicitAffectedUserCount
      && affectedUserCount !== affectedUserIds.length
    ) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-role-permission-grants-update-affected-user-count-invalid'
      });
    }
    for (const affectedUserId of affectedUserIds) {
      invalidateSessionCacheByUserId(affectedUserId);
    }

    addAuditEvent({
      type: 'auth.tenant_role_permission_grants.updated',
      requestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: 'tenant role permission grants replaced and affected snapshots resynced',
      metadata: {
        tenant_id: normalizedTenantId,
        role_id: normalizedRoleId,
        permission_codes: normalizedSavedPermissionCodeKeys,
        affected_user_count: affectedUserCount
      }
    });
    const storeAuditRecorded = (
      atomicWriteResult?.auditRecorded === true
      || atomicWriteResult?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'tenant',
        tenantId: normalizedTenantId,
        requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
        traceparent: normalizeAuditStringOrNull(traceparent, 128),
        eventType: 'auth.tenant_role_permission_grants.updated',
        actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
        actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
        targetType: 'role_permission_grants',
        targetId: normalizedRoleId,
        result: 'success',
        beforeState: {
          permission_codes: Array.isArray(previousPermissionCodesForAudit)
            ? [...previousPermissionCodesForAudit]
            : null
        },
        afterState: {
          permission_codes: [...normalizedSavedPermissionCodeKeys]
        },
        metadata: {
          affected_user_count: affectedUserCount
        }
      });
    }

    return {
      role_id: normalizedRoleId,
      permission_codes: normalizedSavedPermissionCodeKeys,
      affected_user_count: affectedUserCount
    };
  };

  const normalizeStrictTenantMembershipRoleIds = ({
    roleIds,
    minCount = 0,
    maxCount = MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS,
    dependencyReason = 'tenant-membership-role-bindings-invalid'
  } = {}) => {
    if (!Array.isArray(roleIds)) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: dependencyReason
      });
    }
    if (roleIds.length < minCount || roleIds.length > maxCount) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: `${dependencyReason}-count-out-of-range`
      });
    }

    const normalizedRoleIds = [];
    const seenRoleIds = new Set();
    for (const roleId of roleIds) {
      const strictRoleId = normalizeStrictRequiredStringField(roleId);
      const normalizedRoleId = strictRoleId.toLowerCase();
      if (
        !strictRoleId
        || strictRoleId !== normalizedRoleId
        || !normalizedRoleId
        || normalizedRoleId.length > MAX_PLATFORM_ROLE_ID_LENGTH
        || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
        || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
        || seenRoleIds.has(normalizedRoleId)
      ) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: dependencyReason
        });
      }
      seenRoleIds.add(normalizedRoleId);
      normalizedRoleIds.push(normalizedRoleId);
    }
    return normalizedRoleIds.sort((left, right) => left.localeCompare(right));
  };

  const assertTenantMembershipRoleBindingsMatchTenantCatalog = async ({
    tenantId,
    roleIds,
    dependencyReason = 'tenant-membership-role-bindings-invalid'
  }) => {
    if (!Array.isArray(roleIds) || roleIds.length === 0) {
      return;
    }
    try {
      await loadValidatedTenantRoleCatalogEntries({
        tenantId,
        roleIds,
        allowDisabledRoles: true
      });
    } catch (error) {
      if (
        error instanceof AuthProblemError
        && error.errorCode === 'AUTH-404-ROLE-NOT-FOUND'
      ) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: dependencyReason
        });
      }
      throw error;
    }
  };

  const listTenantMemberRoleBindings = async ({
    tenantId,
    membershipId
  }) => {
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: 'tenant',
      tenantId,
      allowEmptyForPlatform: false
    });
    const normalizedMembershipId =
      normalizeStrictTenantMembershipIdFromInput(membershipId);
    assertStoreMethod(
      authStore,
      'findTenantMembershipByMembershipIdAndTenantId',
      'authStore'
    );
    assertStoreMethod(authStore, 'listTenantMembershipRoleBindings', 'authStore');

    const membership = await authStore.findTenantMembershipByMembershipIdAndTenantId({
      membershipId: normalizedMembershipId,
      tenantId: normalizedTenantId
    });
    if (!membership) {
      throw errors.tenantMembershipNotFound();
    }
    const normalizedMembership = normalizeTenantMembershipRecordFromStore({
      membership,
      expectedMembershipId: normalizedMembershipId,
      expectedTenantId: normalizedTenantId
    });
    if (!normalizedMembership) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-record-invalid'
      });
    }

    let roleIds = await authStore.listTenantMembershipRoleBindings({
      membershipId: normalizedMembershipId,
      tenantId: normalizedTenantId
    });
    roleIds = normalizeStrictTenantMembershipRoleIds({
      roleIds,
      minCount: 0,
      maxCount: MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS,
      dependencyReason: 'tenant-membership-role-bindings-invalid'
    });
    await assertTenantMembershipRoleBindingsMatchTenantCatalog({
      tenantId: normalizedTenantId,
      roleIds,
      dependencyReason: 'tenant-membership-role-bindings-invalid'
    });

    return {
      membership_id: normalizedMembershipId,
      role_ids: roleIds
    };
  };

  const replaceTenantMemberRoleBindings = async ({
    requestId,
    traceparent = null,
    tenantId,
    membershipId,
    roleIds = [],
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: 'tenant',
      tenantId,
      allowEmptyForPlatform: false
    });
    const normalizedMembershipId =
      normalizeStrictTenantMembershipIdFromInput(membershipId);
    if (!Array.isArray(roleIds)) {
      throw errors.invalidPayload();
    }
    if (
      roleIds.length < 1
      || roleIds.length > MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS
    ) {
      throw errors.invalidPayload();
    }

    const dedupedRoleIds = new Map();
    for (const roleId of roleIds) {
      const normalizedRoleId = normalizeRequiredStringField(roleId, errors.invalidPayload)
        .toLowerCase();
      if (
        normalizedRoleId.length > MAX_PLATFORM_ROLE_ID_LENGTH
        || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
        || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
      ) {
        throw errors.invalidPayload();
      }
      if (dedupedRoleIds.has(normalizedRoleId)) {
        throw errors.invalidPayload();
      }
      dedupedRoleIds.set(normalizedRoleId, normalizedRoleId);
    }
    const normalizedRoleIds = [...dedupedRoleIds.values()];
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);
    let previousRoleIdsForAudit = null;

    assertStoreMethod(
      authStore,
      'findTenantMembershipByMembershipIdAndTenantId',
      'authStore'
    );
    const membership = await authStore.findTenantMembershipByMembershipIdAndTenantId({
      membershipId: normalizedMembershipId,
      tenantId: normalizedTenantId
    });
    if (!membership) {
      throw errors.tenantMembershipNotFound();
    }
    const normalizedMembership = normalizeTenantMembershipRecordFromStore({
      membership,
      expectedMembershipId: normalizedMembershipId,
      expectedTenantId: normalizedTenantId
    });
    if (!normalizedMembership) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-record-invalid'
      });
    }
    const normalizedMembershipStatus = normalizeTenantMembershipStatus(
      normalizedMembership.status
    );
    if (normalizedMembershipStatus !== 'active') {
      throw errors.tenantMembershipNotFound();
    }

    await loadValidatedTenantRoleCatalogEntries({
      tenantId: normalizedTenantId,
      roleIds: normalizedRoleIds,
      allowDisabledRoles: false
    });

    if (typeof authStore.listTenantMembershipRoleBindings === 'function') {
      try {
        const existingRoleIds = await authStore.listTenantMembershipRoleBindings({
          membershipId: normalizedMembershipId,
          tenantId: normalizedTenantId
        });
        previousRoleIdsForAudit = normalizeStrictTenantMembershipRoleIds({
          roleIds: existingRoleIds,
          minCount: 0,
          maxCount: MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS,
          dependencyReason: 'tenant-membership-role-bindings-audit-invalid'
        });
      } catch (_error) {
        previousRoleIdsForAudit = null;
      }
    }

    if (typeof authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot !== 'function') {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-role-bindings-unsupported'
      });
    }

    let writeResult;
    try {
      writeResult = await authStore.replaceTenantMembershipRoleBindingsAndSyncSnapshot({
        requestId,
        tenantId: normalizedTenantId,
        membershipId: normalizedMembershipId,
        roleIds: normalizedRoleIds,
        operatorUserId,
        operatorSessionId,
        auditContext: {
          requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
          traceparent: normalizedTraceparent,
          actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
          actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128)
        }
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      const normalizedErrorCode = String(error?.code || '').trim();
      if (
        normalizedErrorCode
        === 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_MEMBERSHIP_NOT_ACTIVE'
      ) {
        throw errors.tenantMembershipNotFound();
      }
      if (
        normalizedErrorCode
        === 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_ROLE_INVALID'
      ) {
        throw errors.roleNotFound();
      }
      if (normalizedErrorCode === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      const normalizedErrorMessage = String(error?.message || '')
        .trim()
        .toLowerCase();
      throw errors.tenantMemberDependencyUnavailable({
        reason: normalizedErrorMessage.includes('deadlock')
          ? 'db-deadlock'
          : 'tenant-membership-role-bindings-update-failed'
      });
    }
    if (!writeResult) {
      throw errors.tenantMembershipNotFound();
    }

    const rawResolvedMembershipId = (
      resolveRawCamelSnakeField(
        writeResult,
        'membershipId',
        'membership_id'
      )
    );
    const resolvedMembershipId = normalizeStrictRequiredStringField(rawResolvedMembershipId);
    if (!resolvedMembershipId || resolvedMembershipId !== normalizedMembershipId) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-role-bindings-update-membership-mismatch'
      });
    }

    const rawResolvedRoleIds = Array.isArray(writeResult?.roleIds)
      ? writeResult.roleIds
      : Array.isArray(writeResult?.role_ids)
        ? writeResult.role_ids
        : null;
    const resolvedRoleIds = normalizeStrictTenantMembershipRoleIds({
      roleIds: rawResolvedRoleIds,
      minCount: 1,
      maxCount: MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS,
      dependencyReason: 'tenant-membership-role-bindings-update-invalid'
    });
    await assertTenantMembershipRoleBindingsMatchTenantCatalog({
      tenantId: normalizedTenantId,
      roleIds: resolvedRoleIds,
      dependencyReason: 'tenant-membership-role-bindings-update-invalid'
    });
    const expectedRoleIds = [...normalizedRoleIds]
      .sort((left, right) => left.localeCompare(right));
    const hasRoleBindingsMismatch = (
      expectedRoleIds.length !== resolvedRoleIds.length
      || expectedRoleIds.some(
        (roleId, index) => roleId !== resolvedRoleIds[index]
      )
    );
    if (hasRoleBindingsMismatch) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-role-bindings-update-mismatch'
      });
    }
    const hasAffectedUserIds = (
      hasOwnProperty(writeResult, 'affectedUserIds')
      || hasOwnProperty(writeResult, 'affected_user_ids')
    );
    const hasExplicitAffectedUserCount = (
      hasOwnProperty(writeResult, 'affectedUserCount')
      || hasOwnProperty(writeResult, 'affected_user_count')
    );
    if (!hasAffectedUserIds || !hasExplicitAffectedUserCount) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-role-bindings-update-affected-user-metadata-missing'
      });
    }
    const affectedUserIds = normalizeStrictDistinctUserIdsFromDependency({
      userIds: resolveRawCamelSnakeField(
        writeResult,
        'affectedUserIds',
        'affected_user_ids'
      ),
      dependencyReason: 'tenant-membership-role-bindings-update-affected-user-ids-invalid'
    });
    const affectedUserCount = normalizeStrictNonNegativeIntegerFromDependency({
      value: resolveRawCamelSnakeField(
        writeResult,
        'affectedUserCount',
        'affected_user_count'
      ),
      dependencyReason: 'tenant-membership-role-bindings-update-affected-user-count-invalid'
    });
    if (
      hasExplicitAffectedUserCount
      && affectedUserCount !== affectedUserIds.length
    ) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-role-bindings-update-affected-user-count-invalid'
      });
    }
    for (const affectedUserId of affectedUserIds) {
      invalidateSessionCacheByUserId(affectedUserId);
    }

    addAuditEvent({
      type: 'auth.tenant_membership_roles.updated',
      requestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: 'tenant membership role bindings replaced and permission snapshot synced',
      metadata: {
        tenant_id: normalizedTenantId,
        membership_id: normalizedMembershipId,
        role_ids: resolvedRoleIds,
        affected_user_count: affectedUserCount
      }
    });
    const storeAuditRecorded = (
      writeResult?.auditRecorded === true
      || writeResult?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'tenant',
        tenantId: normalizedTenantId,
        requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
        traceparent: normalizedTraceparent,
        eventType: 'auth.tenant_membership_roles.updated',
        actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
        actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
        targetType: 'membership_role_bindings',
        targetId: normalizedMembershipId,
        result: 'success',
        beforeState: {
          role_ids: Array.isArray(previousRoleIdsForAudit)
            ? [...previousRoleIdsForAudit]
            : null
        },
        afterState: {
          role_ids: [...resolvedRoleIds]
        },
        metadata: {
          affected_user_count: affectedUserCount
        }
      });
    }

    return {
      membership_id: resolvedMembershipId,
      role_ids: resolvedRoleIds
    };
  };

  const updateOrganizationStatus = async ({
    requestId,
    traceparent = null,
    orgId,
    nextStatus,
    operatorUserId,
    operatorSessionId,
    reason = null
  }) => {
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedOrgId = String(orgId || '').trim();
    const normalizedOperatorUserId = String(operatorUserId || '').trim();
    const normalizedOperatorSessionId = String(operatorSessionId || '').trim();
    const normalizedNextStatus = normalizeOrgStatus(nextStatus);
    const normalizedReason = reason === null || reason === undefined
      ? null
      : String(reason).trim() || null;

    if (
      !normalizedOrgId
      || !normalizedOperatorUserId
      || !normalizedOperatorSessionId
      || !VALID_ORG_STATUS.has(normalizedNextStatus)
    ) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'updateOrganizationStatus', 'authStore');
    let result = null;
    try {
      result = await authStore.updateOrganizationStatus({
        requestId: normalizedRequestId,
        orgId: normalizedOrgId,
        nextStatus: normalizedNextStatus,
        operatorUserId: normalizedOperatorUserId,
        reason: normalizedReason,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizeAuditStringOrNull(traceparent, 128),
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId,
          reason: normalizedReason
        }
      });
    } catch (error) {
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.auditDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw error;
    }
    if (!result) {
      throw errors.orgNotFound();
    }

    const previousStatus = normalizeOrgStatus(result.previous_status);
    const currentStatus = normalizeOrgStatus(result.current_status);
    if (!previousStatus || !currentStatus) {
      throw errors.invalidPayload();
    }
    const affectedMembershipCount = normalizeOrgStatusCascadeCountFromDependency({
      value: resolveRawCamelSnakeField(
        result,
        'affectedMembershipCount',
        'affected_membership_count'
      ),
      dependencyReason: 'org-status-cascade-affected-membership-count-invalid'
    });
    const affectedRoleCount = normalizeOrgStatusCascadeCountFromDependency({
      value: resolveRawCamelSnakeField(
        result,
        'affectedRoleCount',
        'affected_role_count'
      ),
      dependencyReason: 'org-status-cascade-affected-role-count-invalid'
    });
    const affectedRoleBindingCount = normalizeOrgStatusCascadeCountFromDependency({
      value: resolveRawCamelSnakeField(
        result,
        'affectedRoleBindingCount',
        'affected_role_binding_count'
      ),
      dependencyReason: 'org-status-cascade-affected-role-binding-count-invalid'
    });
    const revokedSessionCount = normalizeOrgStatusCascadeCountFromDependency({
      value: resolveRawCamelSnakeField(
        result,
        'revokedSessionCount',
        'revoked_session_count'
      ),
      dependencyReason: 'org-status-cascade-revoked-session-count-invalid'
    });
    const revokedRefreshTokenCount = normalizeOrgStatusCascadeCountFromDependency({
      value: resolveRawCamelSnakeField(
        result,
        'revokedRefreshTokenCount',
        'revoked_refresh_token_count'
      ),
      dependencyReason: 'org-status-cascade-revoked-refresh-token-count-invalid'
    });
    if (previousStatus !== currentStatus) {
      invalidateAllAccessSessionCache();
    }
    addAuditEvent({
      type: 'auth.org.status.updated',
      requestId: normalizedRequestId,
      userId: normalizedOperatorUserId,
      sessionId: normalizedOperatorSessionId,
      detail: previousStatus === currentStatus
        ? 'organization status update treated as no-op'
        : 'organization status updated',
      metadata: {
        org_id: normalizedOrgId,
        previous_status: previousStatus,
        current_status: currentStatus,
        reason: normalizedReason,
        affected_membership_count: affectedMembershipCount,
        affected_role_count: affectedRoleCount,
        affected_role_binding_count: affectedRoleBindingCount,
        revoked_session_count: revokedSessionCount,
        revoked_refresh_token_count: revokedRefreshTokenCount
      }
    });
    const storeAuditRecorded = (
      result?.auditRecorded === true
      || result?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'tenant',
        tenantId: normalizedOrgId,
        requestId: normalizedRequestId,
        traceparent: normalizeAuditStringOrNull(traceparent, 128),
        eventType: 'auth.org.status.updated',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'org',
        targetId: normalizedOrgId,
        result: 'success',
        beforeState: {
          status: previousStatus
        },
        afterState: {
          status: currentStatus
        },
        metadata: {
          reason: normalizedReason,
          affected_membership_count: affectedMembershipCount,
          affected_role_count: affectedRoleCount,
          affected_role_binding_count: affectedRoleBindingCount,
          revoked_session_count: revokedSessionCount,
          revoked_refresh_token_count: revokedRefreshTokenCount
        }
      });
    }

    return {
      org_id: normalizedOrgId,
      previous_status: previousStatus,
      current_status: currentStatus,
      affected_membership_count: affectedMembershipCount,
      affected_role_count: affectedRoleCount,
      affected_role_binding_count: affectedRoleBindingCount,
      revoked_session_count: revokedSessionCount,
      revoked_refresh_token_count: revokedRefreshTokenCount
    };
  };

  const updatePlatformUserStatus = async ({
    requestId,
    traceparent = null,
    userId,
    nextStatus,
    operatorUserId,
    operatorSessionId,
    reason = null
  }) => {
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedUserId = String(userId || '').trim();
    const normalizedOperatorUserId = String(operatorUserId || '').trim();
    const normalizedOperatorSessionId = String(operatorSessionId || '').trim();
    const normalizedNextStatus = normalizeOrgStatus(nextStatus);
    const normalizedReason = reason === null || reason === undefined
      ? null
      : String(reason).trim() || null;
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);

    if (
      !normalizedUserId
      || normalizedUserId.length > MAX_PLATFORM_USER_ID_LENGTH
      || !normalizedOperatorUserId
      || !normalizedOperatorSessionId
      || !VALID_PLATFORM_USER_STATUS.has(normalizedNextStatus)
    ) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'updatePlatformUserStatus', 'authStore');
    let result;
    try {
      result = await authStore.updatePlatformUserStatus({
        requestId: normalizedRequestId,
        userId: normalizedUserId,
        nextStatus: normalizedNextStatus,
        operatorUserId: normalizedOperatorUserId,
        reason: normalizedReason,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId,
          reason: normalizedReason
        }
      });
    } catch (error) {
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.auditDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw error;
    }
    if (!result) {
      throw errors.userNotFound();
    }

    const previousStatus = normalizeOrgStatus(result.previous_status);
    const currentStatus = normalizeOrgStatus(result.current_status);
    if (
      !VALID_PLATFORM_USER_STATUS.has(previousStatus)
      || !VALID_PLATFORM_USER_STATUS.has(currentStatus)
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-user-status-result-invalid'
      });
    }
    if (previousStatus !== currentStatus) {
      invalidateSessionCacheByUserId(normalizedUserId);
    }
    addAuditEvent({
      type: 'auth.platform.user.status.updated',
      requestId: normalizedRequestId,
      userId: normalizedOperatorUserId,
      sessionId: normalizedOperatorSessionId,
      detail: previousStatus === currentStatus
        ? 'platform user status update treated as no-op'
        : 'platform user status updated',
      metadata: {
        target_user_id: normalizedUserId,
        previous_status: previousStatus,
        current_status: currentStatus,
        reason: normalizedReason
      }
    });
    const storeAuditRecorded = (
      result?.auditRecorded === true
      || result?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'platform',
        tenantId: null,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.platform.user.status.updated',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'user',
        targetId: normalizedUserId,
        result: 'success',
        beforeState: {
          status: previousStatus
        },
        afterState: {
          status: currentStatus
        },
        metadata: {
          reason: normalizedReason
        }
      });
    }

    return {
      user_id: normalizedUserId,
      previous_status: previousStatus,
      current_status: currentStatus
    };
  };

  const softDeleteUser = async ({
    requestId,
    traceparent = null,
    userId,
    operatorUserId,
    operatorSessionId
  }) => {
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedUserId = String(userId || '').trim();
    const normalizedOperatorUserId = String(operatorUserId || '').trim();
    const normalizedOperatorSessionId = String(operatorSessionId || '').trim();
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);

    if (
      !normalizedUserId
      || normalizedUserId.length > MAX_PLATFORM_USER_ID_LENGTH
      || !normalizedOperatorUserId
      || !normalizedOperatorSessionId
    ) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'softDeleteUser', 'authStore');
    let result;
    try {
      result = await authStore.softDeleteUser({
        requestId: normalizedRequestId,
        userId: normalizedUserId,
        operatorUserId: normalizedOperatorUserId,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId
        }
      });
    } catch (error) {
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.auditDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw error;
    }
    if (!result) {
      throw errors.userNotFound();
    }

    const resolvedResultUserId = normalizeStrictRequiredStringField(
      resolveRawCamelSnakeField(result, 'userId', 'user_id')
    );
    if (!resolvedResultUserId || resolvedResultUserId !== normalizedUserId) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-user-soft-delete-target-mismatch'
      });
    }

    const previousStatus = normalizeOrgStatus(
      resolveRawCamelSnakeField(result, 'previousStatus', 'previous_status')
    );
    const currentStatus = normalizeOrgStatus(
      resolveRawCamelSnakeField(result, 'currentStatus', 'current_status')
    );
    if (
      !VALID_PLATFORM_USER_STATUS.has(previousStatus)
      || !VALID_PLATFORM_USER_STATUS.has(currentStatus)
      || currentStatus !== 'disabled'
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-user-soft-delete-result-invalid'
      });
    }
    if (
      !hasOwnProperty(result, 'revokedSessionCount')
      && !hasOwnProperty(result, 'revoked_session_count')
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-user-soft-delete-revoked-session-count-invalid'
      });
    }
    if (
      !hasOwnProperty(result, 'revokedRefreshTokenCount')
      && !hasOwnProperty(result, 'revoked_refresh_token_count')
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-user-soft-delete-revoked-refresh-token-count-invalid'
      });
    }
    const revokedSessionCount = normalizeStrictNonNegativeIntegerFromPlatformDependency({
      value: resolveRawCamelSnakeField(
        result,
        'revokedSessionCount',
        'revoked_session_count'
      ),
      dependencyReason: 'platform-user-soft-delete-revoked-session-count-invalid'
    });
    const revokedRefreshTokenCount = normalizeStrictNonNegativeIntegerFromPlatformDependency({
      value: resolveRawCamelSnakeField(
        result,
        'revokedRefreshTokenCount',
        'revoked_refresh_token_count'
      ),
      dependencyReason: 'platform-user-soft-delete-revoked-refresh-token-count-invalid'
    });

    // Always clear cached access sessions for the target user to avoid stale cache allow-list
    // windows when soft-delete is replayed as a no-op.
    invalidateSessionCacheByUserId(normalizedUserId);
    addAuditEvent({
      type: 'auth.platform.user.soft_deleted',
      requestId: normalizedRequestId,
      userId: normalizedOperatorUserId,
      sessionId: normalizedOperatorSessionId,
      detail: previousStatus === currentStatus
        && revokedSessionCount === 0
        && revokedRefreshTokenCount === 0
        ? 'platform user soft-delete treated as no-op'
        : 'platform user soft-deleted and global sessions revoked',
      metadata: {
        target_user_id: normalizedUserId,
        previous_status: previousStatus,
        current_status: currentStatus,
        revoked_session_count: revokedSessionCount,
        revoked_refresh_token_count: revokedRefreshTokenCount
      }
    });
    const storeAuditRecorded = (
      result?.auditRecorded === true
      || result?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'platform',
        tenantId: null,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.platform.user.soft_deleted',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'user',
        targetId: normalizedUserId,
        result: 'success',
        beforeState: {
          status: previousStatus
        },
        afterState: {
          status: currentStatus
        },
        metadata: {
          revoked_session_count: revokedSessionCount,
          revoked_refresh_token_count: revokedRefreshTokenCount
        }
      });
    }

    return {
      user_id: normalizedUserId,
      previous_status: previousStatus,
      current_status: currentStatus,
      revoked_session_count: revokedSessionCount,
      revoked_refresh_token_count: revokedRefreshTokenCount
    };
  };

  const rollbackProvisionedUser = async ({
    requestId,
    userId,
    strict = false
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId || typeof authStore.deleteUserById !== 'function') {
      if (strict) {
        throw new Error('rollback-provisioned-user-capability-unavailable');
      }
      return {
        rolledBack: false,
        reason: 'rollback-capability-unavailable'
      };
    }
    try {
      const domainAccess = await getDomainAccessForUser(normalizedUserId);
      if (domainAccess.platform || domainAccess.tenant) {
        if (strict) {
          throw new Error('rollback-skipped-user-has-domain-access');
        }
        return {
          rolledBack: false,
          reason: 'rollback-skipped-user-has-domain-access'
        };
      }
      const tenantOptions = await getTenantOptionsForUser(normalizedUserId);
      if (tenantOptions.length > 0) {
        if (strict) {
          throw new Error('rollback-skipped-user-has-tenant-options');
        }
        return {
          rolledBack: false,
          reason: 'rollback-skipped-user-has-tenant-options'
        };
      }
      if (typeof authStore.hasAnyTenantRelationshipByUserId === 'function') {
        const hasAnyTenantRelationship = await authStore.hasAnyTenantRelationshipByUserId(
          normalizedUserId
        );
        if (hasAnyTenantRelationship) {
          if (strict) {
            throw new Error('rollback-skipped-user-has-tenant-relationship');
          }
          return {
            rolledBack: false,
            reason: 'rollback-skipped-user-has-tenant-relationship'
          };
        }
      }
    } catch (rollbackGuardError) {
      log(
        'warn',
        'Skipped rollback for provisioned user after conflict due to guard check failure',
        {
          request_id: requestId || 'request_id_unset',
          user_id: normalizedUserId,
          reason: String(rollbackGuardError?.message || 'unknown')
        }
      );
      if (strict) {
        throw rollbackGuardError;
      }
      return {
        rolledBack: false,
        reason: 'rollback-guard-check-failed'
      };
    }
    try {
      const rollbackResult = await authStore.deleteUserById(normalizedUserId);
      const rollbackDeleteApplied =
        rollbackResult
        && typeof rollbackResult === 'object'
        && rollbackResult.deleted === true;
      if (!rollbackDeleteApplied) {
        const rollbackReason =
          rollbackResult
          && typeof rollbackResult === 'object'
          && rollbackResult.deleted === false
            ? 'rollback-not-deleted'
            : 'rollback-delete-result-invalid';
        const rollbackNotAppliedError = new Error(
          rollbackReason === 'rollback-not-deleted'
            ? 'rollback-provisioned-user-not-deleted'
            : 'rollback-provisioned-user-delete-result-invalid'
        );
        if (strict) {
          throw rollbackNotAppliedError;
        }
        return {
          rolledBack: false,
          reason: rollbackReason
        };
      }
      return {
        rolledBack: true,
        reason: 'deleted'
      };
    } catch (rollbackError) {
      log('warn', 'Failed to rollback provisioned user after conflict', {
        request_id: requestId || 'request_id_unset',
        user_id: normalizedUserId,
        reason: String(rollbackError?.message || 'unknown')
      });
      if (strict) {
        throw rollbackError;
      }
      return {
        rolledBack: false,
        reason: 'rollback-delete-failed'
      };
    }
  };

  const rollbackProvisionedUserIdentity = async ({ requestId, userId }) =>
    rollbackProvisionedUser({
      requestId,
      userId,
      strict: true
    });

  const rollbackProvisionedTenantMembership = async ({
    requestId,
    userId,
    tenantId
  }) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (
      !normalizedUserId
      || !normalizedTenantId
      || typeof authStore.removeTenantMembershipForUser !== 'function'
    ) {
      return;
    }
    try {
      await authStore.removeTenantMembershipForUser({
        userId: normalizedUserId,
        tenantId: normalizedTenantId
      });
    } catch (rollbackError) {
      log('warn', 'Failed to rollback provisioned tenant membership after conflict', {
        request_id: requestId || 'request_id_unset',
        user_id: normalizedUserId,
        tenant_id: normalizedTenantId,
        reason: String(rollbackError?.message || 'unknown')
      });
    }
    if (typeof authStore.removeTenantDomainAccessForUser !== 'function') {
      return;
    }
    try {
      await authStore.removeTenantDomainAccessForUser(normalizedUserId);
    } catch (rollbackError) {
      log('warn', 'Failed to rollback provisioned tenant domain access after conflict', {
        request_id: requestId || 'request_id_unset',
        user_id: normalizedUserId,
        reason: String(rollbackError?.message || 'unknown')
      });
    }
  };

  const ensureProvisioningRelationship = async ({
    requestId,
    entryDomain,
    activeTenantId,
    userId,
    tenantName
  }) => {
    if (entryDomain === 'platform') {
      const domainAccess = await getDomainAccessForUser(userId);
      if (domainAccess.platform) {
        throw errors.provisionConflict();
      }
      const provisionedDomainAccess = await ensureDefaultDomainAccessForUser({
        requestId,
        userId
      });
      if (!provisionedDomainAccess || provisionedDomainAccess.inserted !== true) {
        throw errors.provisionConflict();
      }
      const updatedDomainAccess = await getDomainAccessForUser(userId);
      if (!updatedDomainAccess.platform) {
        throw errors.provisionConflict();
      }
      return null;
    }

    const normalizedTenantId = normalizeTenantId(activeTenantId);
    if (!normalizedTenantId) {
      throw errors.noDomainAccess();
    }

    const existingTenantOptions = await getTenantOptionsForUser(userId);
    if (existingTenantOptions.some((option) => option.tenant_id === normalizedTenantId)) {
      const domainAccessBefore = await getDomainAccessForUser(userId);
      if (domainAccessBefore.tenant) {
        throw errors.provisionConflict();
      }

      await ensureTenantDomainAccessForUser({
        requestId,
        userId,
        entryDomain: 'tenant'
      });
      const domainAccessAfter = await getDomainAccessForUser(userId);
      if (!domainAccessAfter.tenant) {
        throw errors.provisionConflict();
      }
      return normalizedTenantId;
    }

    assertStoreMethod(authStore, 'createTenantMembershipForUser', 'authStore');
    let createdMembership = null;
    try {
      createdMembership = await authStore.createTenantMembershipForUser({
        userId: String(userId),
        tenantId: normalizedTenantId,
        tenantName
      });
    } catch (error) {
      if (isDataTooLongRoleFactError(error)) {
        throw errors.invalidPayload();
      }
      throw error;
    }
    if (!createdMembership || createdMembership.created !== true) {
      throw errors.provisionConflict();
    }

    try {
      await ensureTenantDomainAccessForUser({
        requestId,
        userId,
        entryDomain: 'tenant'
      });
      const updatedDomainAccess = await getDomainAccessForUser(userId);
      if (!updatedDomainAccess.tenant) {
        throw errors.provisionConflict();
      }
    } catch (error) {
      await rollbackProvisionedTenantMembership({
        requestId,
        userId,
        tenantId: normalizedTenantId
      });
      throw error;
    }
    return normalizedTenantId;
  };

  const resolveProvisionTenantName = async ({
    scope,
    operatorUserId,
    activeTenantId,
    requestedTenantName
  }) => {
    if (scope !== 'tenant') {
      return null;
    }
    const normalizedActiveTenantId = normalizeTenantId(activeTenantId);
    if (!normalizedActiveTenantId) {
      return null;
    }
    const operatorTenantOptions = await getTenantOptionsForUser(operatorUserId);
    const activeTenantOption = operatorTenantOptions.find(
      (option) => option.tenant_id === normalizedActiveTenantId
    );
    const canonicalTenantName = activeTenantOption?.tenant_name
      ? String(activeTenantOption.tenant_name).trim() || null
      : null;
    if (!canonicalTenantName) {
      throw errors.invalidPayload();
    }
    if (
      requestedTenantName
      && canonicalTenantName !== requestedTenantName
    ) {
      throw errors.invalidPayload();
    }
    return canonicalTenantName;
  };

  const recoverProvisioningOutcomeAfterConflict = async ({
    error,
    createdUser,
    userId,
    entryDomain,
    activeTenantId
  }) => {
    if (
      !(error instanceof AuthProblemError)
      || error.errorCode !== 'AUTH-409-PROVISION-CONFLICT'
      || !createdUser
    ) {
      return null;
    }
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return null;
    }
    const domainAccess = await getDomainAccessForUser(normalizedUserId);
    if (entryDomain === 'platform') {
      if (!domainAccess.platform) {
        return null;
      }
      return { active_tenant_id: null };
    }

    const normalizedTenantId = normalizeTenantId(activeTenantId);
    if (!normalizedTenantId || !domainAccess.tenant) {
      return null;
    }
    const tenantOptions = await getTenantOptionsForUser(normalizedUserId);
    if (!tenantOptions.some((option) => option.tenant_id === normalizedTenantId)) {
      return null;
    }
    return { active_tenant_id: normalizedTenantId };
  };

  const provisionUserByPhone = async ({
    requestId,
    accessToken,
    phone,
    scope,
    tenantName = undefined,
    payload = undefined,
    authorizationContext = null,
    authorizedRoute = null
  }) => {
    const normalizedScope = String(scope || '').trim().toLowerCase();
    if (normalizedScope !== 'platform' && normalizedScope !== 'tenant') {
      throw errors.invalidPayload();
    }
    const payloadCandidate = payload === undefined
      ? {
        phone,
        ...(tenantName !== undefined ? { tenant_name: tenantName } : {})
      }
      : payload;
    const parsedPayload = parseProvisionPayload({
      payload: payloadCandidate,
      scope: normalizedScope
    });
    if (!parsedPayload.valid) {
      throw errors.invalidPayload();
    }
    const normalizedPhone = normalizePhone(parsedPayload.phone);
    if (normalizedScope === 'platform' && parsedPayload.tenantNameProvided) {
      throw errors.invalidPayload();
    }
    const parsedTenantName = normalizedScope === 'tenant'
      ? parseOptionalTenantName(parsedPayload.tenantName)
      : { valid: true, value: null };
    if (!normalizedPhone) {
      throw errors.invalidPayload();
    }
    if (!parsedTenantName.valid) {
      throw errors.invalidPayload();
    }

    const permissionCode = normalizedScope === 'platform'
      ? PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE
      : TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE;
    const normalizedAuthorizedRoute =
      authorizedRoute && typeof authorizedRoute === 'object'
        ? {
          user_id: String(
            authorizedRoute.user_id
            || authorizedRoute.userId
            || ''
          ).trim(),
          session_id: String(
            authorizedRoute.session_id
            || authorizedRoute.sessionId
            || ''
          ).trim(),
          entry_domain: normalizeEntryDomain(
            authorizedRoute.entry_domain
            || authorizedRoute.entryDomain
          ),
          active_tenant_id: normalizeTenantId(
            authorizedRoute.active_tenant_id
            || authorizedRoute.activeTenantId
          )
        }
        : null;
    let resolvedAuthorizedRoute = null;
    if (normalizedAuthorizedRoute) {
      if (
        !normalizedAuthorizedRoute.user_id
        || !normalizedAuthorizedRoute.session_id
        || normalizedAuthorizedRoute.entry_domain !== normalizedScope
      ) {
        throw errors.forbidden();
      }
      resolvedAuthorizedRoute = normalizedAuthorizedRoute;
    } else {
      resolvedAuthorizedRoute = await authorizeRoute({
        requestId,
        accessToken,
        permissionCode,
        scope: normalizedScope,
        authorizationContext
      });
    }
    const operatorUserId = String(resolvedAuthorizedRoute?.user_id || '').trim() || 'unknown';
    const operatorSessionId = String(resolvedAuthorizedRoute?.session_id || '').trim() || 'unknown';
    const sessionEntryDomain = String(resolvedAuthorizedRoute?.entry_domain || '').trim().toLowerCase();
    const activeTenantId = normalizeTenantId(resolvedAuthorizedRoute?.active_tenant_id);
    const resolvedTenantName = await resolveProvisionTenantName({
      scope: normalizedScope,
      operatorUserId,
      activeTenantId,
      requestedTenantName: parsedTenantName.value
    });

    let provisionedUser = null;
    let createdUser = false;
    let relationTenantId = null;
    try {
      const provisionedResult = await getOrCreateProvisionUserByPhone({
        requestId,
        phone: normalizedPhone,
        operatorUserId,
        operatorSessionId
      });
      provisionedUser = provisionedResult.user;
      createdUser = provisionedResult.createdUser;
      relationTenantId = await ensureProvisioningRelationship({
        requestId,
        entryDomain: sessionEntryDomain,
        activeTenantId,
        userId: provisionedUser.id,
        tenantName: resolvedTenantName
      });
    } catch (error) {
      let recoveredOutcome = null;
      try {
        recoveredOutcome = await recoverProvisioningOutcomeAfterConflict({
          error,
          createdUser,
          userId: provisionedUser?.id,
          entryDomain: sessionEntryDomain,
          activeTenantId
        });
      } catch (recoveryError) {
        log('warn', 'Post-conflict provisioning recovery check failed', {
          request_id: requestId || 'request_id_unset',
          user_id: String(provisionedUser?.id || 'unknown'),
          reason: String(recoveryError?.message || 'unknown')
        });
      }
      if (recoveredOutcome) {
        relationTenantId = recoveredOutcome.active_tenant_id;
      } else if (createdUser && provisionedUser?.id) {
        await rollbackProvisionedUser({
          requestId,
          userId: provisionedUser.id
        });
        addAuditEvent({
          type: 'auth.user.provision.rejected',
          requestId,
          userId: operatorUserId || 'unknown',
          sessionId: operatorSessionId || 'unknown',
          detail: 'user provisioning rejected after rollback',
          metadata: {
            operator_user_id: operatorUserId,
            phone_masked: maskPhone(normalizedPhone),
            entry_domain: sessionEntryDomain,
            tenant_id: activeTenantId,
            error_code:
              error instanceof AuthProblemError
                ? error.errorCode
                : 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
          }
        });
        throw error;
      } else {
        addAuditEvent({
          type: 'auth.user.provision.rejected',
          requestId,
          userId: operatorUserId || 'unknown',
          sessionId: operatorSessionId || 'unknown',
          detail: 'user provisioning rejected',
          metadata: {
            operator_user_id: operatorUserId,
            phone_masked: maskPhone(normalizedPhone),
            entry_domain: sessionEntryDomain,
            tenant_id: activeTenantId,
            error_code:
              error instanceof AuthProblemError
                ? error.errorCode
                : 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
          }
        });
        throw error;
      }
    }

    addAuditEvent({
      type: createdUser ? 'auth.user.provision.created' : 'auth.user.provision.reused',
      requestId,
      userId: provisionedUser.id,
      sessionId: operatorSessionId,
      detail: createdUser
        ? 'user provisioned with default password policy'
        : 'existing user reused without credential mutation',
      metadata: {
        operator_user_id: operatorUserId,
        phone_masked: maskPhone(normalizedPhone),
        entry_domain: sessionEntryDomain,
        tenant_id: relationTenantId,
        credential_initialized: createdUser,
        first_login_force_password_change: false
      }
    });

    return {
      user_id: provisionedUser.id,
      phone: provisionedUser.phone,
      created_user: createdUser,
      reused_existing_user: !createdUser,
      credential_initialized: createdUser,
      first_login_force_password_change: false,
      entry_domain: sessionEntryDomain,
      active_tenant_id: relationTenantId,
      request_id: requestId || 'request_id_unset'
    };
  };

  const provisionPlatformUserByPhone = async ({
    requestId,
    accessToken,
    phone,
    tenantName = undefined,
    payload = undefined,
    authorizationContext = null,
    authorizedRoute = null
  }) =>
    provisionUserByPhone({
      requestId,
      accessToken,
      phone,
      scope: 'platform',
      tenantName,
      payload,
      authorizationContext,
      authorizedRoute
    });

  const provisionTenantUserByPhone = async ({
    requestId,
    accessToken,
    phone,
    tenantName = undefined,
    payload = undefined,
    authorizationContext = null,
    authorizedRoute = null
  }) =>
    provisionUserByPhone({
      requestId,
      accessToken,
      phone,
      scope: 'tenant',
      tenantName,
      payload,
      authorizationContext,
      authorizedRoute
    });

  const findTenantMembershipByUserAndTenantId = async ({
    userId,
    tenantId
  }) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedUserId || !normalizedTenantId) {
      return null;
    }

    assertStoreMethod(authStore, 'findTenantMembershipByUserAndTenantId', 'authStore');
    let membership = null;
    try {
      membership = await authStore.findTenantMembershipByUserAndTenantId({
        userId: normalizedUserId,
        tenantId: normalizedTenantId
      });
    } catch (error) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: String(error?.code || error?.message || 'query-failed')
      });
    }
    if (!membership) {
      return null;
    }
    const normalizedMembership = normalizeTenantMembershipRecordFromStore({
      membership,
      expectedUserId: normalizedUserId,
      expectedTenantId: normalizedTenantId
    });
    if (!normalizedMembership) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-record-invalid'
      });
    }
    return normalizedMembership;
  };

  const listTenantMembers = async ({
    requestId,
    tenantId,
    page = 1,
    pageSize = 50
  }) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedTenantId) {
      throw errors.noDomainAccess();
    }
    const normalizedPage = normalizeMemberListInteger({
      value: page,
      fallback: 1,
      min: 1,
      max: 100000
    });
    const normalizedPageSize = normalizeMemberListInteger({
      value: pageSize,
      fallback: 50,
      min: 1,
      max: 200
    });
    assertStoreMethod(authStore, 'listTenantMembersByTenantId', 'authStore');
    let members = [];
    try {
      members = await authStore.listTenantMembersByTenantId({
        tenantId: normalizedTenantId,
        page: normalizedPage,
        pageSize: normalizedPageSize
      });
    } catch (error) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: String(error?.code || error?.message || 'query-failed')
      });
    }
    if (!Array.isArray(members)) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-members-list-shape-invalid'
      });
    }
    const normalizedMembers = [];
    for (const member of members) {
      const normalizedMember = normalizeTenantMembershipRecordFromStore({
        membership: member,
        expectedTenantId: normalizedTenantId
      });
      if (!normalizedMember) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-membership-record-invalid'
        });
      }
      normalizedMembers.push(normalizedMember);
    }
    return normalizedMembers;
  };

  const findTenantMembershipByMembershipIdAndTenantId = async ({
    membershipId,
    tenantId
  }) => {
    const normalizedMembershipId =
      normalizeStrictTenantMembershipIdFromInput(membershipId);
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedMembershipId || !normalizedTenantId) {
      return null;
    }

    assertStoreMethod(
      authStore,
      'findTenantMembershipByMembershipIdAndTenantId',
      'authStore'
    );
    let membership = null;
    try {
      membership = await authStore.findTenantMembershipByMembershipIdAndTenantId({
        membershipId: normalizedMembershipId,
        tenantId: normalizedTenantId
      });
    } catch (error) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: String(error?.code || error?.message || 'query-failed')
      });
    }
    if (!membership) {
      return null;
    }

    const normalizedMembership = normalizeTenantMembershipRecordFromStore({
      membership,
      expectedMembershipId: normalizedMembershipId,
      expectedTenantId: normalizedTenantId
    });
    if (!normalizedMembership) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-record-invalid'
      });
    }
    return normalizedMembership;
  };

  const updateTenantMemberProfile = async (input = {}) => {
    const normalizedMembershipId =
      normalizeStrictTenantMembershipIdFromInput(
        resolveRawCamelSnakeField(input, 'membershipId', 'membership_id')
      );
    const requestedTenantId = normalizeTenantId(
      resolveRawCamelSnakeField(input, 'tenantId', 'tenant_id')
    );
    const rawDisplayName = resolveRawCamelSnakeField(
      input,
      'displayName',
      'display_name'
    );
    if (typeof rawDisplayName !== 'string') {
      throw errors.invalidPayload();
    }
    const normalizedDisplayName = normalizeStrictRequiredStringField(rawDisplayName);
    if (
      !normalizedDisplayName
      || normalizedDisplayName.length > MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalizedDisplayName)
    ) {
      throw errors.invalidPayload();
    }
    const hasDepartmentNameProvidedFlag = (
      input?.departmentNameProvided === true
      || input?.department_name_provided === true
    );
    const hasDepartmentNameProvidedKey = (
      hasOwnProperty(input, 'departmentNameProvided')
      || hasOwnProperty(input, 'department_name_provided')
    );
    const hasDepartmentNameField = (
      hasOwnProperty(input, 'departmentName')
      || hasOwnProperty(input, 'department_name')
    );
    const hasDepartmentNameCandidate = (
      hasDepartmentNameProvidedFlag
      || (!hasDepartmentNameProvidedKey && hasDepartmentNameField)
    );
    const rawDepartmentName = hasOwnProperty(input, 'departmentName')
      ? input.departmentName
      : input.department_name;
    let normalizedDepartmentName = null;
    if (hasDepartmentNameCandidate) {
      if (rawDepartmentName === null) {
        normalizedDepartmentName = null;
      } else if (typeof rawDepartmentName === 'string') {
        normalizedDepartmentName = normalizeStrictRequiredStringField(rawDepartmentName);
        if (
          !normalizedDepartmentName
          || normalizedDepartmentName.length > MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH
          || CONTROL_CHAR_PATTERN.test(normalizedDepartmentName)
        ) {
          throw errors.invalidPayload();
        }
      } else {
        throw errors.invalidPayload();
      }
    }

    const normalizedAuthorizedRoute =
      input?.authorizedRoute && typeof input.authorizedRoute === 'object'
        ? {
          user_id: String(
            input.authorizedRoute.user_id
            || input.authorizedRoute.userId
            || ''
          ).trim(),
          session_id: String(
            input.authorizedRoute.session_id
            || input.authorizedRoute.sessionId
            || ''
          ).trim(),
          entry_domain: normalizeEntryDomain(
            input.authorizedRoute.entry_domain
            || input.authorizedRoute.entryDomain
          ),
          active_tenant_id: normalizeTenantId(
            input.authorizedRoute.active_tenant_id
            || input.authorizedRoute.activeTenantId
          )
        }
        : null;
    let resolvedAuthorizedRoute = null;
    if (normalizedAuthorizedRoute) {
      if (
        !normalizedAuthorizedRoute.user_id
        || !normalizedAuthorizedRoute.session_id
        || normalizedAuthorizedRoute.entry_domain !== 'tenant'
      ) {
        throw errors.forbidden();
      }
      resolvedAuthorizedRoute = normalizedAuthorizedRoute;
    } else {
      resolvedAuthorizedRoute = await authorizeRoute({
        requestId: input.requestId,
        accessToken: input.accessToken,
        permissionCode: TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
        scope: 'tenant',
        authorizationContext: input.authorizationContext || null
      });
    }

    const operatorUserId = String(resolvedAuthorizedRoute?.user_id || '').trim();
    const operatorSessionId = String(resolvedAuthorizedRoute?.session_id || '').trim();
    const activeTenantId = normalizeTenantId(resolvedAuthorizedRoute?.active_tenant_id);
    if (!operatorUserId || !operatorSessionId || !activeTenantId) {
      throw errors.noDomainAccess();
    }
    if (requestedTenantId && requestedTenantId !== activeTenantId) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'updateTenantMembershipProfile', 'authStore');
    let result = null;
    try {
      result = await authStore.updateTenantMembershipProfile({
        membershipId: normalizedMembershipId,
        tenantId: activeTenantId,
        displayName: normalizedDisplayName,
        departmentNameProvided: hasDepartmentNameCandidate,
        departmentName: normalizedDepartmentName,
        operatorUserId
      });
    } catch (error) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: String(error?.code || error?.message || 'write-failed')
      });
    }
    if (!result) {
      throw errors.tenantMembershipNotFound();
    }

    const normalizedMembership = normalizeTenantMembershipRecordFromStore({
      membership: result,
      expectedMembershipId: normalizedMembershipId,
      expectedTenantId: activeTenantId,
      expectedDisplayName: normalizedDisplayName,
      expectedDepartmentName: hasDepartmentNameCandidate
        ? normalizedDepartmentName
        : UNSET_EXPECTED_TENANT_MEMBER_PROFILE_FIELD
    });
    if (!normalizedMembership) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-record-invalid'
      });
    }

    addAuditEvent({
      type: 'auth.tenant.member.profile.updated',
      requestId: input.requestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: 'tenant member profile updated',
      metadata: {
        membership_id: normalizedMembershipId,
        tenant_id: activeTenantId,
        changed_fields: hasDepartmentNameCandidate
          ? ['display_name', 'department_name']
          : ['display_name']
      }
    });

    return normalizedMembership;
  };

  const updateTenantMemberStatus = async ({
    requestId,
    traceparent = null,
    accessToken,
    membershipId,
    nextStatus,
    reason = null,
    authorizationContext = null,
    authorizedRoute = null
  }) => {
    const normalizedMembershipId =
      normalizeStrictTenantMembershipIdFromInput(membershipId);
    const normalizedNextStatus = normalizeTenantMembershipStatus(nextStatus);
    let normalizedReason = null;
    if (reason !== null && reason !== undefined) {
      if (typeof reason !== 'string') {
        throw errors.invalidPayload();
      }
      const normalizedReasonCandidate = String(reason).trim();
      if (
        !normalizedReasonCandidate
        || normalizedReasonCandidate.length > MAX_OWNER_TRANSFER_REASON_LENGTH
        || CONTROL_CHAR_PATTERN.test(normalizedReasonCandidate)
      ) {
        throw errors.invalidPayload();
      }
      normalizedReason = normalizedReasonCandidate;
    }
    if (
      !normalizedMembershipId
      || !normalizedNextStatus
      || !isValidTenantMembershipId(normalizedMembershipId)
    ) {
      throw errors.invalidPayload();
    }
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);

    const normalizedAuthorizedRoute =
      authorizedRoute && typeof authorizedRoute === 'object'
        ? {
          user_id: String(
            authorizedRoute.user_id
            || authorizedRoute.userId
            || ''
          ).trim(),
          session_id: String(
            authorizedRoute.session_id
            || authorizedRoute.sessionId
            || ''
          ).trim(),
          entry_domain: normalizeEntryDomain(
            authorizedRoute.entry_domain
            || authorizedRoute.entryDomain
          ),
          active_tenant_id: normalizeTenantId(
            authorizedRoute.active_tenant_id
            || authorizedRoute.activeTenantId
          )
        }
        : null;
    let resolvedAuthorizedRoute = null;
    if (normalizedAuthorizedRoute) {
      if (
        !normalizedAuthorizedRoute.user_id
        || !normalizedAuthorizedRoute.session_id
        || normalizedAuthorizedRoute.entry_domain !== 'tenant'
      ) {
        throw errors.forbidden();
      }
      resolvedAuthorizedRoute = normalizedAuthorizedRoute;
    } else {
      resolvedAuthorizedRoute = await authorizeRoute({
        requestId: normalizedRequestId,
        accessToken,
        permissionCode: TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
        scope: 'tenant',
        authorizationContext
      });
    }

    const operatorUserId = String(resolvedAuthorizedRoute?.user_id || '').trim();
    const operatorSessionId = String(resolvedAuthorizedRoute?.session_id || '').trim();
    const activeTenantId = normalizeTenantId(resolvedAuthorizedRoute?.active_tenant_id);
    if (!operatorUserId || !operatorSessionId || !activeTenantId) {
      throw errors.noDomainAccess();
    }

    assertStoreMethod(authStore, 'updateTenantMembershipStatus', 'authStore');
    let result = null;
    try {
      result = await authStore.updateTenantMembershipStatus({
        membershipId: normalizedMembershipId,
        tenantId: activeTenantId,
        nextStatus: normalizedNextStatus,
        operatorUserId,
        reason: normalizedReason,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          actorUserId: operatorUserId,
          actorSessionId: operatorSessionId,
          reason: normalizedReason
        }
      });
    } catch (error) {
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw errors.tenantMemberDependencyUnavailable({
        reason: String(error?.code || error?.message || 'write-failed')
      });
    }
    if (!result) {
      throw errors.tenantMembershipNotFound();
    }

    const previousStatus = normalizeTenantMembershipStatus(result.previous_status);
    const currentStatus = normalizeTenantMembershipStatus(result.current_status);
    if (!previousStatus || !currentStatus) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-status-result-invalid'
      });
    }
    const rawResolvedMembershipId = hasOwnProperty(result, 'membership_id')
      ? result.membership_id
      : normalizedMembershipId;
    const resolvedMembershipId =
      normalizeStrictRequiredStringField(rawResolvedMembershipId).toLowerCase();
    const rawResolvedTenantId = hasOwnProperty(result, 'tenant_id')
      ? result.tenant_id
      : activeTenantId;
    const resolvedTenantId = normalizeStrictRequiredStringField(rawResolvedTenantId);
    const isRejoinTransition =
      previousStatus === 'left'
      && normalizedNextStatus === 'active'
      && currentStatus === 'active';
    const hasMembershipIdMismatch = resolvedMembershipId !== normalizedMembershipId;
    if (
      !isValidTenantMembershipId(resolvedMembershipId)
      || !resolvedTenantId
      || resolvedTenantId !== activeTenantId
      || (isRejoinTransition && !hasMembershipIdMismatch)
      || (!isRejoinTransition && hasMembershipIdMismatch)
    ) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-result-shape-invalid'
      });
    }
    if (previousStatus !== currentStatus) {
      invalidateSessionCacheByUserId(String(result.user_id || '').trim());
    }
    addAuditEvent({
      type: 'auth.tenant.member.status.updated',
      requestId: normalizedRequestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: previousStatus === currentStatus
        ? 'tenant membership status update treated as no-op'
        : 'tenant membership status updated',
      metadata: {
        membership_id: resolvedMembershipId,
        target_user_id: String(result.user_id || '').trim() || null,
        tenant_id: resolvedTenantId,
        previous_status: previousStatus,
        current_status: currentStatus,
        reason: normalizedReason
      }
    });
    const storeAuditRecorded = (
      result?.auditRecorded === true
      || result?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'tenant',
        tenantId: resolvedTenantId,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.tenant.member.status.updated',
        actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
        actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
        targetType: 'membership',
        targetId: resolvedMembershipId,
        result: 'success',
        beforeState: {
          status: previousStatus
        },
        afterState: {
          status: currentStatus
        },
        metadata: {
          target_user_id: String(result.user_id || '').trim() || null,
          tenant_id: resolvedTenantId,
          membership_id: resolvedMembershipId,
          reason: normalizedReason
        }
      });
    }
    return {
      membership_id: resolvedMembershipId,
      user_id: String(result.user_id || '').trim(),
      tenant_id: resolvedTenantId,
      previous_status: previousStatus,
      current_status: currentStatus
    };
  };

  const selectOrSwitchTenant = async ({
    requestId,
    accessToken,
    tenantId,
    eventType,
    authorizationContext = null
  }) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedTenantId) {
      throw errors.invalidPayload();
    }

    const { session, user } = await resolveAuthorizedSession({
      requestId,
      accessToken,
      authorizationContext
    });
    const sessionId = session.sessionId || session.session_id;
    const sessionContext = buildSessionContext(session);

    await assertDomainAccess({
      requestId,
      userId: user.id,
      entryDomain: 'tenant'
    });

    if (sessionContext.entry_domain !== 'tenant') {
      addAuditEvent({
        type: 'auth.domain.rejected',
        requestId,
        userId: user.id,
        sessionId,
        detail: `tenant selection rejected for entry domain ${sessionContext.entry_domain}`,
        metadata: {
          permission_code: null,
          entry_domain: sessionContext.entry_domain,
          tenant_id: normalizedTenantId
        }
      });
      throw errors.noDomainAccess();
    }

    const options = await getTenantOptionsForUser(user.id);
    const matched = options.find((item) => item.tenant_id === normalizedTenantId);
    if (!matched) {
      addAuditEvent({
        type: 'auth.domain.rejected',
        requestId,
        userId: user.id,
        sessionId,
        detail: `tenant selection rejected: ${normalizedTenantId}`,
        metadata: {
          permission_code: null,
          entry_domain: sessionContext.entry_domain,
          tenant_id: normalizedTenantId
        }
      });
      throw errors.noDomainAccess();
    }

    if (typeof sessionRepository.updateSessionContext !== 'function') {
      throw new Error('sessionRepository.updateSessionContext is required');
    }
    await sessionRepository.updateSessionContext({
      sessionId,
      entryDomain: 'tenant',
      activeTenantId: normalizedTenantId
    });
    invalidateSessionCacheBySessionId(sessionId);

    addAuditEvent({
      type: eventType,
      requestId,
      userId: user.id,
      sessionId,
      detail: `active tenant updated: ${normalizedTenantId}`,
      metadata: {
        entry_domain: 'tenant',
        tenant_id: normalizedTenantId
      }
    });

    const tenantPermissionContext = await getTenantPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: 'tenant',
      activeTenantId: normalizedTenantId
    });
    const userName = await resolveLoginUserName({
      userId: user.id,
      entryDomain: 'tenant',
      activeTenantId: normalizedTenantId
    });

    return {
      session_id: sessionId,
      entry_domain: 'tenant',
      active_tenant_id: normalizedTenantId,
      tenant_selection_required: false,
      user_name: userName,
      tenant_permission_context: tenantPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  const selectTenant = async ({
    requestId,
    accessToken,
    tenantId,
    authorizationContext = null
  }) =>
    selectOrSwitchTenant({
      requestId,
      accessToken,
      tenantId,
      eventType: 'auth.tenant.selected',
      authorizationContext
    });

  const switchTenant = async ({
    requestId,
    accessToken,
    tenantId,
    authorizationContext = null
  }) =>
    selectOrSwitchTenant({
      requestId,
      accessToken,
      tenantId,
      eventType: 'auth.tenant.switched',
      authorizationContext
    });

  return {
    login,
    sendOtp,
    loginWithOtp,
    platformOptions,
    tenantOptions,
    authorizeRoute,
    selectTenant,
    switchTenant,
    refresh,
    logout,
    changePassword,
    provisionPlatformUserByPhone,
    provisionTenantUserByPhone,
    findTenantMembershipByUserAndTenantId,
    findTenantMembershipByMembershipIdAndTenantId,
    listTenantMembers,
    updateTenantMemberProfile,
    updateTenantMemberStatus,
    getOrCreateUserIdentityByPhone,
    createOrganizationWithOwner,
    acquireOwnerTransferLock,
    releaseOwnerTransferLock,
    validateOwnerTransferRequest,
    executeOwnerTransferTakeover,
    createPlatformRoleCatalogEntry,
    updatePlatformRoleCatalogEntry,
    deletePlatformRoleCatalogEntry,
    listPlatformRoleCatalogEntries,
    findPlatformRoleCatalogEntryByRoleId,
    getSystemSensitiveConfig,
    upsertSystemSensitiveConfig,
    recordSystemSensitiveConfigAuditEvent,
    listPlatformRolePermissionGrants,
    replacePlatformRolePermissionGrants,
    listPlatformPermissionCatalog,
    listPlatformPermissionCatalogEntries,
    listTenantRolePermissionGrants,
    replaceTenantRolePermissionGrants,
    listTenantPermissionCatalog,
    listTenantPermissionCatalogEntries,
    listTenantMemberRoleBindings,
    replaceTenantMemberRoleBindings,
    updateOrganizationStatus,
    updatePlatformUserStatus,
    softDeleteUser,
    rollbackProvisionedUserIdentity,
    replacePlatformRolesAndSyncSnapshot,
    listAuditEvents,
    recordIdempotencyEvent,
    // Test support
    _internals: {
      auditTrail,
      authStore,
      accessSessionCache,
      accessSessionCacheTtlMs,
      ownerTransferLocksByOrgId
    }
  };
};

module.exports = {
  ACCESS_TTL_SECONDS,
  REFRESH_TTL_SECONDS,
  OTP_TTL_SECONDS,
  RATE_LIMIT_WINDOW_SECONDS,
  RATE_LIMIT_MAX_ATTEMPTS,
  listSupportedRoutePermissionCodes,
  listSupportedRoutePermissionScopes,
  AuthProblemError,
  createAuthService
};

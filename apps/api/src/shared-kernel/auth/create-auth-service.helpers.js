'use strict';

const { AsyncLocalStorage } = require('node:async_hooks');
const { createHash, createDecipheriv, generateKeyPairSync, pbkdf2Sync, randomBytes, randomUUID, randomInt, timingSafeEqual, createSign, createVerify } = require('node:crypto');
const { log } = require('../../common/logger');
const { normalizeTraceparent } = require('../../common/trace-context');
const { createInMemoryAuthStore } = require('./store/create-in-memory-auth-store');
const {
  TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
  TENANT_ACCOUNT_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_ACCOUNT_MANAGEMENT_OPERATE_PERMISSION_CODE,
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
} = require('../../modules/auth/permission-catalog');
const { createAuthSessionService } = require('../../modules/auth/session-service');
const { createTenantContextService } = require('../../modules/auth/tenant-context-service');
const { createPermissionContextBuilder } = require('../../modules/auth/permission-context-builder');
const { createEntryPolicyService } = require('../../modules/auth/entry-policy-service');
const { createLoginService } = require('../../modules/auth/login-service');
const { createAuthRepositories } = require('../../modules/auth/repositories');
const OTP_CODE_LENGTH = 6;

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
  TENANT_ACCOUNT_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_ACCOUNT_MANAGEMENT_OPERATE_PERMISSION_CODE,
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

const MAX_TENANT_USER_DISPLAY_NAME_LENGTH = 64;

const MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH = 128;

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

const UNSET_EXPECTED_TENANT_USER_PROFILE_FIELD = Symbol(
  'unsetExpectedTenantUserProfileField'
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

  tenantUsershipNotFound: () =>
    authError({
      status: 404,
      title: 'Not Found',
      detail: '目标成员关系不存在',
      errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  tenantUserDependencyUnavailable: ({ reason = 'dependency-unavailable' } = {}) =>
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

const normalizeTenantUsershipStatus = (status) => {
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

const isValidTenantUsershipId = (membershipId) =>
  TENANT_MEMBERSHIP_ID_PATTERN.test(String(membershipId || ''))
  && String(membershipId || '').length <= MAX_TENANT_MEMBERSHIP_ID_LENGTH;

const normalizeStrictTenantUsershipIdFromInput = (membershipId) => {
  const normalizedMembershipId = normalizeStrictRequiredStringField(membershipId)
    .toLowerCase();
  if (
    !normalizedMembershipId
    || CONTROL_CHAR_PATTERN.test(normalizedMembershipId)
    || !isValidTenantUsershipId(normalizedMembershipId)
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

const parseOptionalTenantUserProfileField = ({
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

const normalizeTenantUsershipRecordFromStore = ({
  membership = null,
  expectedMembershipId = '',
  expectedUserId = '',
  expectedTenantId = '',
  expectedDisplayName = UNSET_EXPECTED_TENANT_USER_PROFILE_FIELD,
  expectedDepartmentName = UNSET_EXPECTED_TENANT_USER_PROFILE_FIELD
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
  const normalizedStatus = normalizeTenantUsershipStatus(
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
  const parsedDisplayName = parseOptionalTenantUserProfileField({
    value: resolveRawCamelSnakeField(membership, 'displayName', 'display_name'),
    maxLength: MAX_TENANT_USER_DISPLAY_NAME_LENGTH
  });
  const parsedDepartmentName = parseOptionalTenantUserProfileField({
    value: resolveRawCamelSnakeField(membership, 'departmentName', 'department_name'),
    maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
  });
  if (
    !isValidTenantUsershipId(normalizedMembershipId)
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
  if (expectedDisplayName !== UNSET_EXPECTED_TENANT_USER_PROFILE_FIELD) {
    const normalizedExpectedDisplayName = normalizeStrictRequiredStringField(
      expectedDisplayName
    );
    if (
      !normalizedExpectedDisplayName
      || normalizedExpectedDisplayName.length > MAX_TENANT_USER_DISPLAY_NAME_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalizedExpectedDisplayName)
      || parsedDisplayName.value !== normalizedExpectedDisplayName
    ) {
      return null;
    }
  }
  if (expectedDepartmentName !== UNSET_EXPECTED_TENANT_USER_PROFILE_FIELD) {
    const parsedExpectedDepartmentName = parseOptionalTenantUserProfileField({
      value: expectedDepartmentName,
      maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
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

module.exports = {
  ACCESS_SESSION_CACHE_TTL_MS,
  AUDIT_EVENT_ALLOWED_DOMAINS,
  AUDIT_EVENT_ALLOWED_RESULTS,
  AUDIT_EVENT_REDACTION_KEY_PATTERN,
  CONTROL_CHAR_PATTERN,
  DEFAULT_PASSWORD_CONFIG_KEY,
  DEFAULT_SEED_USERS,
  MAX_AUDIT_QUERY_PAGE_SIZE,
  MAX_AUTH_AUDIT_TRAIL_ENTRIES,
  MAX_ORG_STATUS_CASCADE_COUNT,
  MAX_OWNER_TRANSFER_ORG_ID_LENGTH,
  MAX_OWNER_TRANSFER_REASON_LENGTH,
  MAX_PLATFORM_ROLE_FACTS_PER_USER,
  MAX_PLATFORM_ROLE_ID_LENGTH,
  MAX_PLATFORM_USER_ID_LENGTH,
  MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS,
  MAX_ROLE_PERMISSION_CODES_PER_REQUEST,
  MAX_TENANT_MEMBERSHIP_ID_LENGTH,
  MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS,
  MAX_TENANT_NAME_LENGTH,
  MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  MYSQL_DATA_TOO_LONG_ERRNO,
  MYSQL_DUP_ENTRY_ERRNO,
  OTP_CODE_LENGTH,
  OTP_RESEND_COOLDOWN_SECONDS,
  OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES,
  OWNER_TRANSFER_TAKEOVER_ROLE_CODE,
  OWNER_TRANSFER_TAKEOVER_ROLE_ID_DIGEST_LENGTH,
  OWNER_TRANSFER_TAKEOVER_ROLE_ID_PREFIX,
  OWNER_TRANSFER_TAKEOVER_ROLE_NAME,
  PASSWORD_MIN_LENGTH,
  PBKDF2_DIGEST,
  PBKDF2_ITERATIONS,
  PBKDF2_KEYLEN,
  PLATFORM_ROLE_ASSIGNMENT_ALLOWED_FIELDS,
  PLATFORM_ROLE_CATALOG_SCOPE,
  PLATFORM_ROLE_FACTS_REPLACE_PERMISSION_CODE,
  PLATFORM_ROLE_PERMISSION_FIELD_KEYS,
  REJECTED_SYSTEM_CONFIG_AUDIT_EVENT_TYPES,
  ROLE_ID_ADDRESSABLE_PATTERN,
  SENSITIVE_CONFIG_ENVELOPE_VERSION,
  SENSITIVE_CONFIG_KEY_DERIVATION_ITERATIONS,
  SENSITIVE_CONFIG_KEY_DERIVATION_SALT,
  SUPPORTED_PLATFORM_PERMISSION_CODE_SET,
  SUPPORTED_SYSTEM_SENSITIVE_CONFIG_KEYS,
  SUPPORTED_TENANT_PERMISSION_CODE_SET,
  TENANT_MEMBERSHIP_ID_PATTERN,
  TENANT_ROLE_SCOPE,
  UNSET_EXPECTED_TENANT_USER_PROFILE_FIELD,
  VALID_ORG_STATUS,
  VALID_PLATFORM_ROLE_CATALOG_SCOPE,
  VALID_PLATFORM_ROLE_CATALOG_STATUS,
  VALID_PLATFORM_ROLE_FACT_STATUS,
  VALID_PLATFORM_USER_STATUS,
  VALID_SYSTEM_SENSITIVE_CONFIG_STATUS,
  WHITESPACE_PATTERN,
  AuthProblemError,
  assertOptionalBooleanRolePermission,
  assertOtpStoreContract,
  assertStoreMethod,
  authError,
  createInMemoryOtpStore,
  createInMemoryRateLimitStore,
  createJwtError,
  decryptSensitiveConfigValue,
  deriveLegacySensitiveConfigKey,
  derivePrimarySensitiveConfigKey,
  deriveSensitiveConfigKeys,
  errors,
  fromBase64Url,
  hasOwnProperty,
  hasTopLevelPlatformRolePermissionField,
  hashPassword,
  isDataTooLongRoleFactError,
  isDuplicateRoleFactEntryError,
  isMissingPlatformRoleCatalogTableError,
  isMissingTableError,
  isPlainObject,
  isPlatformPermissionCode,
  isTenantPermissionCode,
  isUserActive,
  isValidTenantUsershipId,
  maskPhone,
  normalizeAuditDomain,
  normalizeAuditOccurredAt,
  normalizeAuditResult,
  normalizeAuditStringOrNull,
  normalizeAuditTraceparentOrNull,
  normalizeEntryDomain,
  normalizeMemberListInteger,
  normalizeOrgStatus,
  normalizePhone,
  normalizePlatformPermissionCode,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogTenantIdForScope,
  normalizePlatformRoleIdKey,
  normalizeRequiredStringField,
  normalizeStrictAddressableTenantRoleIdFromInput,
  normalizeStrictRequiredStringField,
  normalizeStrictTenantUsershipIdFromInput,
  normalizeSystemSensitiveConfigKey,
  normalizeSystemSensitiveConfigStatus,
  normalizeTenantId,
  normalizeTenantPermissionCode,
  normalizeTenantUsershipRecordFromStore,
  normalizeTenantUsershipStatus,
  parseAuditQueryTimestamp,
  parseOptionalTenantName,
  parseOptionalTenantUserProfileField,
  parseProvisionPayload,
  resolveProvisioningConfigFailureReason,
  resolveRawCamelSnakeField,
  resolveRawRoleIdCandidate,
  sanitizeAuditState,
  signJwt,
  toBase64Url,
  toOwnerTransferTakeoverRoleId,
  toPlatformPermissionCodeKey,
  toSystemSensitiveConfigRecord,
  toTenantPermissionCodeKey,
  tokenHash,
  verifyJwt,
  verifyPassword
};

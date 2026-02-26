const { setTimeout: sleep } = require('node:timers/promises');
const { createHash, randomUUID } = require('node:crypto');
const { log } = require('../../../common/logger');
const { normalizeTraceparent } = require('../../../common/trace-context');
const {
  isRetryableDeliveryFailure,
  computeRetrySchedule
} = require('../../../modules/integration');
const {
  KNOWN_PLATFORM_PERMISSION_CODES,
  KNOWN_TENANT_PERMISSION_CODES,
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
  ROLE_MANAGEMENT_PERMISSION_CODE_KEY_SET,
  toPlatformPermissionSnapshotFromCodes,
  toTenantPermissionSnapshotFromCodes
} = require('../../../modules/auth/permission-catalog');
const {
  createMySqlAuthStoreCapabilities
} = require('./methods/mysql-method-map');

const DEFAULT_DEADLOCK_RETRY_CONFIG = Object.freeze({
  maxRetries: 2,
  baseDelayMs: 20,
  maxDelayMs: 200,
  jitterMs: 20
});
const DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS = 100;
const MYSQL_DUP_ENTRY_ERRNO = 1062;
const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const ROLE_ID_ADDRESSABLE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const VALID_ORG_STATUS = new Set(['active', 'disabled']);
const VALID_PLATFORM_USER_STATUS = new Set(['active', 'disabled']);
const VALID_SYSTEM_SENSITIVE_CONFIG_STATUS = new Set(['active', 'disabled']);
const ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS = new Set(['auth.default_password']);
const VALID_PLATFORM_ROLE_CATALOG_STATUS = new Set(['active', 'disabled']);
const VALID_PLATFORM_ROLE_CATALOG_SCOPE = new Set(['platform', 'tenant']);
const VALID_PLATFORM_INTEGRATION_DIRECTION = new Set([
  'inbound',
  'outbound',
  'bidirectional'
]);
const VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS = new Set([
  'draft',
  'active',
  'paused',
  'retired'
]);
const VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE = new Set([
  'openapi',
  'event'
]);
const VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS = new Set([
  'candidate',
  'active',
  'deprecated',
  'retired'
]);
const VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT = new Set([
  'compatible',
  'incompatible'
]);
const VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS = new Set([
  'pending',
  'retrying',
  'succeeded',
  'failed',
  'dlq',
  'replayed'
]);
const VALID_PLATFORM_INTEGRATION_FREEZE_STATUS = new Set([
  'active',
  'released'
]);
const MAX_PLATFORM_INTEGRATION_ID_LENGTH = 64;
const MAX_PLATFORM_INTEGRATION_CODE_LENGTH = 64;
const MAX_PLATFORM_INTEGRATION_NAME_LENGTH = 128;
const MAX_PLATFORM_INTEGRATION_PROTOCOL_LENGTH = 64;
const MAX_PLATFORM_INTEGRATION_AUTH_MODE_LENGTH = 64;
const MAX_PLATFORM_INTEGRATION_ENDPOINT_LENGTH = 512;
const MAX_PLATFORM_INTEGRATION_BASE_URL_LENGTH = 512;
const MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH = 128;
const MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH = 512;
const MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH = 256;
const MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH = 64;
const MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_REF_LENGTH = 512;
const MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_CHECKSUM_LENGTH = 64;
const MAX_PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_NOTES_LENGTH = 4096;
const MAX_PLATFORM_INTEGRATION_CONTRACT_DIFF_SUMMARY_LENGTH = 65535;
const MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH = 128;
const MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH = 64;
const MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH = 128;
const MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH = 128;
const MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH = 65535;
const MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH = 128;
const MAX_PLATFORM_INTEGRATION_RECOVERY_REASON_LENGTH = 256;
const MAX_PLATFORM_INTEGRATION_RECOVERY_LIST_LIMIT = 200;
const MAX_PLATFORM_INTEGRATION_FREEZE_ID_LENGTH = 64;
const MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH = 256;
const MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH = 128;
const MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH = 128;
const MAX_OPERATOR_USER_ID_LENGTH = 64;
const PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS = 3000;
const MAX_PLATFORM_INTEGRATION_TIMEOUT_MS = 300000;
const DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS = Math.min(
  5 * 60 * 1000,
  MAX_PLATFORM_INTEGRATION_TIMEOUT_MS
);
const VALID_TENANT_MEMBERSHIP_STATUS = new Set(['active', 'disabled', 'left']);
const MAX_TENANT_USER_DISPLAY_NAME_LENGTH = 64;
const MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH = 128;
const MAX_PLATFORM_ROLE_CODE_LENGTH = 64;
const MAX_PLATFORM_ROLE_NAME_LENGTH = 128;
const MAINLAND_PHONE_PATTERN = /^1\d{10}$/;
const KNOWN_PLATFORM_PERMISSION_CODE_SET = new Set(KNOWN_PLATFORM_PERMISSION_CODES);
const KNOWN_TENANT_PERMISSION_CODE_SET = new Set(KNOWN_TENANT_PERMISSION_CODES);
const PLATFORM_ROLE_MANAGEMENT_PERMISSION_CODE_SET = ROLE_MANAGEMENT_PERMISSION_CODE_KEY_SET;
const OWNER_TRANSFER_LOCK_TIMEOUT_SECONDS_MAX = 30;
const OWNER_TRANSFER_LOCK_NAME_PREFIX = 'neweast:owner-transfer:';
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
const AUDIT_EVENT_ALLOWED_DOMAINS = new Set(['platform', 'tenant']);
const AUDIT_EVENT_ALLOWED_RESULTS = new Set(['success', 'rejected', 'failed']);
const AUDIT_EVENT_REDACTION_KEY_PATTERN =
  /(password|token|secret|credential|private[_-]?key|access[_-]?key|api[_-]?key|signing[_-]?key)/i;
const AUDIT_EVENT_REDACTION_COUNT_KEY_PATTERN = /_count$/i;
const MAX_AUDIT_QUERY_PAGE_SIZE = 200;
const MYSQL_AUDIT_DATETIME_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?$/;

const normalizeUserStatus = (status) => {
  if (typeof status !== 'string') {
    return 'disabled';
  }
  const value = status.trim().toLowerCase();
  if (value === 'enabled') {
    return 'active';
  }
  return value;
};
const normalizeOrgName = (orgName) => {
  if (typeof orgName !== 'string') {
    return '';
  }
  return orgName.trim();
};
const normalizeOrgStatus = (status) => {
  const value = String(status || '').trim().toLowerCase();
  if (value === 'enabled') {
    return 'active';
  }
  return value;
};
const normalizeTenantUsershipStatus = (status) => {
  const value = String(status ?? '').trim().toLowerCase();
  if (!value) {
    return 'active';
  }
  if (value === 'enabled') {
    return 'active';
  }
  return VALID_TENANT_MEMBERSHIP_STATUS.has(value) ? value : '';
};
const normalizeTenantUsershipStatusForRead = (status) => {
  const value = String(status ?? '').trim().toLowerCase();
  if (!value) {
    return '';
  }
  if (value === 'enabled') {
    return 'active';
  }
  return VALID_TENANT_MEMBERSHIP_STATUS.has(value) ? value : '';
};
const normalizeOptionalTenantUserProfileField = ({
  value,
  maxLength
} = {}) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    return null;
  }
  const normalized = value.trim();
  if (
    !normalized
    || normalized.length > maxLength
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    return null;
  }
  return normalized;
};
const resolveOptionalTenantUserProfileField = (value) =>
  value === null || value === undefined
    ? null
    : value;
const normalizeRequiredPlatformUserProfileField = ({
  value,
  maxLength,
  fieldName
} = {}) => {
  const normalized = normalizeOptionalTenantUserProfileField({
    value,
    maxLength
  });
  if (!normalized) {
    throw new Error(`${fieldName} must be non-empty string within max length`);
  }
  return normalized;
};
const normalizeOptionalPlatformUserProfileField = ({
  value,
  maxLength,
  fieldName
} = {}) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    throw new Error(`${fieldName} must be string or null`);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const normalized = normalizeOptionalTenantUserProfileField({
    value: trimmed,
    maxLength
  });
  if (!normalized) {
    throw new Error(`${fieldName} must be valid string`);
  }
  return normalized;
};
const normalizePlatformRoleCatalogStatus = (status) => {
  const value = String(status || '').trim().toLowerCase();
  if (value === 'enabled') {
    return 'active';
  }
  return value;
};
const normalizePlatformRoleCatalogScope = (scope) =>
  String(scope || '').trim().toLowerCase();
const normalizePlatformRoleCatalogTenantId = (tenantId) =>
  String(tenantId ?? '').trim();
const normalizePlatformRoleCatalogTenantIdForScope = ({
  scope = 'platform',
  tenantId
} = {}) => {
  const normalizedScope = normalizePlatformRoleCatalogScope(scope);
  const normalizedTenantId = normalizePlatformRoleCatalogTenantId(tenantId);
  if (normalizedScope === 'tenant') {
    if (!normalizedTenantId) {
      throw new Error('tenant role catalog entry requires tenantId');
    }
    return normalizedTenantId;
  }
  return '';
};
const normalizePlatformRoleCatalogRoleId = (roleId) =>
  String(roleId || '').trim().toLowerCase();
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
const normalizePlatformRoleCatalogCode = (code) =>
  String(code || '').trim();
const normalizePlatformIntegrationId = (integrationId) =>
  String(integrationId || '').trim().toLowerCase();
const isValidPlatformIntegrationId = (integrationId) =>
  Boolean(integrationId) && integrationId.length <= MAX_PLATFORM_INTEGRATION_ID_LENGTH;
const normalizePlatformIntegrationCode = (code) =>
  String(code || '').trim();
const normalizePlatformIntegrationCodeKey = (code) =>
  normalizePlatformIntegrationCode(code).toLowerCase();
const escapeSqlLikePattern = (value) =>
  String(value || '').replace(/[\\%_]/g, '\\$&');
const normalizePlatformIntegrationDirection = (direction) =>
  String(direction || '').trim().toLowerCase();
const normalizePlatformIntegrationLifecycleStatus = (status) =>
  String(status || '').trim().toLowerCase();
const normalizePlatformIntegrationContractType = (contractType) =>
  String(contractType || '').trim().toLowerCase();
const normalizePlatformIntegrationContractVersion = (contractVersion) =>
  String(contractVersion || '').trim();
const normalizePlatformIntegrationContractStatus = (status) =>
  String(status || '').trim().toLowerCase();
const normalizePlatformIntegrationContractEvaluationResult = (evaluationResult) =>
  String(evaluationResult || '').trim().toLowerCase();
const normalizePlatformIntegrationContractSchemaChecksum = (schemaChecksum) =>
  String(schemaChecksum || '').trim().toLowerCase();
const normalizePlatformIntegrationRecoveryId = (recoveryId) =>
  String(recoveryId || '').trim().toLowerCase();
const normalizePlatformIntegrationRecoveryStatus = (status) =>
  String(status || '').trim().toLowerCase();
const normalizePlatformIntegrationFreezeId = (freezeId) =>
  String(freezeId || '').trim().toLowerCase();
const normalizePlatformIntegrationFreezeStatus = (status) =>
  String(status || '').trim().toLowerCase();
const normalizePlatformIntegrationRecoveryIdempotencyKey = (idempotencyKey) => {
  if (idempotencyKey === null || idempotencyKey === undefined) {
    return '';
  }
  const normalized = String(idempotencyKey || '').trim();
  return normalized;
};
const PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN = /^[a-f0-9]{64}$/;
const normalizePlatformIntegrationOptionalText = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  const normalized = String(value).trim();
  return normalized.length > 0 ? normalized : null;
};
const normalizeStoreIsoTimestamp = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? '' : value.toISOString();
  }
  if (typeof value !== 'string') {
    return '';
  }
  const normalized = value.trim();
  if (
    !normalized
    || normalized !== value
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    return '';
  }
  const parsedDate = new Date(normalized);
  if (Number.isNaN(parsedDate.getTime())) {
    return '';
  }
  return parsedDate.toISOString();
};
const normalizePlatformIntegrationTimeoutMs = (timeoutMs) => {
  if (timeoutMs === undefined || timeoutMs === null) {
    return PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS;
  }
  const parsed = Number(timeoutMs);
  if (!Number.isInteger(parsed)) {
    return NaN;
  }
  return parsed;
};
const normalizePlatformIntegrationJsonForStorage = ({
  value,
  allowUndefined = false
} = {}) => {
  if (value === undefined) {
    return allowUndefined ? undefined : null;
  }
  if (value === null) {
    return null;
  }
  if (typeof value === 'string') {
    const normalized = value.trim();
    if (!normalized) {
      return null;
    }
    try {
      return JSON.stringify(JSON.parse(normalized));
    } catch (_error) {
      return undefined;
    }
  }
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch (_error) {
      return undefined;
    }
  }
  return undefined;
};
const createPlatformIntegrationContractActivationBlockedError = ({
  integrationId = null,
  contractType = null,
  contractVersion = null,
  reason = 'activation-blocked'
} = {}) => {
  const error = new Error('platform integration contract activation blocked');
  error.code = 'ERR_PLATFORM_INTEGRATION_CONTRACT_ACTIVATION_BLOCKED';
  error.integrationId = normalizePlatformIntegrationId(integrationId) || null;
  error.contractType =
    normalizePlatformIntegrationContractType(contractType) || null;
  error.contractVersion =
    normalizePlatformIntegrationContractVersion(contractVersion) || null;
  error.reason = String(reason || 'activation-blocked').trim().toLowerCase();
  return error;
};
const isPlatformIntegrationLifecycleTransitionAllowed = ({
  previousStatus,
  nextStatus
} = {}) => {
  const normalizedPreviousStatus = normalizePlatformIntegrationLifecycleStatus(
    previousStatus
  );
  const normalizedNextStatus = normalizePlatformIntegrationLifecycleStatus(
    nextStatus
  );
  if (
    !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedPreviousStatus)
    || !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedNextStatus)
  ) {
    return false;
  }
  if (normalizedPreviousStatus === normalizedNextStatus) {
    return false;
  }
  if (normalizedPreviousStatus === 'draft') {
    return (
      normalizedNextStatus === 'active'
      || normalizedNextStatus === 'retired'
    );
  }
  if (normalizedPreviousStatus === 'active') {
    return (
      normalizedNextStatus === 'paused'
      || normalizedNextStatus === 'retired'
    );
  }
  if (normalizedPreviousStatus === 'paused') {
    return (
      normalizedNextStatus === 'active'
      || normalizedNextStatus === 'retired'
    );
  }
  return false;
};
const createPlatformIntegrationLifecycleConflictError = ({
  integrationId = null,
  previousStatus = null,
  requestedStatus = null
} = {}) => {
  const error = new Error('platform integration lifecycle transition conflict');
  error.code = 'ERR_PLATFORM_INTEGRATION_LIFECYCLE_CONFLICT';
  error.integrationId = normalizePlatformIntegrationId(integrationId) || null;
  error.previousStatus =
    normalizePlatformIntegrationLifecycleStatus(previousStatus) || null;
  error.requestedStatus =
    normalizePlatformIntegrationLifecycleStatus(requestedStatus) || null;
  return error;
};
const createPlatformIntegrationRecoveryReplayConflictError = ({
  integrationId = null,
  recoveryId = null,
  previousStatus = null,
  requestedStatus = 'replayed'
} = {}) => {
  const error = new Error('platform integration recovery replay conflict');
  error.code = 'ERR_PLATFORM_INTEGRATION_RECOVERY_REPLAY_CONFLICT';
  error.integrationId = normalizePlatformIntegrationId(integrationId) || null;
  error.recoveryId = normalizePlatformIntegrationRecoveryId(recoveryId) || null;
  error.previousStatus =
    normalizePlatformIntegrationRecoveryStatus(previousStatus) || null;
  error.requestedStatus =
    normalizePlatformIntegrationRecoveryStatus(requestedStatus) || 'replayed';
  return error;
};
const createPlatformIntegrationFreezeActiveConflictError = ({
  freezeId = null,
  frozenAt = null,
  freezeReason = null
} = {}) => {
  const error = new Error('platform integration freeze already active');
  error.code = 'ERR_PLATFORM_INTEGRATION_FREEZE_ACTIVE_CONFLICT';
  error.freezeId = normalizePlatformIntegrationFreezeId(freezeId) || null;
  error.frozenAt = normalizeStoreIsoTimestamp(frozenAt) || null;
  error.freezeReason = normalizePlatformIntegrationOptionalText(freezeReason) || null;
  return error;
};
const createPlatformIntegrationFreezeReleaseConflictError = () => {
  const error = new Error('platform integration freeze release conflict');
  error.code = 'ERR_PLATFORM_INTEGRATION_FREEZE_RELEASE_CONFLICT';
  return error;
};
const normalizeOwnerTransferLockTimeoutSeconds = (timeoutSeconds) => {
  const parsed = Number(timeoutSeconds);
  if (!Number.isFinite(parsed)) {
    return 0;
  }
  return Math.max(
    0,
    Math.min(
      OWNER_TRANSFER_LOCK_TIMEOUT_SECONDS_MAX,
      Math.floor(parsed)
    )
  );
};
const toOwnerTransferLockName = (orgId) => {
  const normalizedOrgId = String(orgId || '').trim();
  if (!normalizedOrgId) {
    return '';
  }
  const lockDigest = createHash('sha256')
    .update(normalizedOrgId)
    .digest('hex')
    .slice(0, 40);
  return `${OWNER_TRANSFER_LOCK_NAME_PREFIX}${lockDigest}`;
};
const DEFAULT_DEADLOCK_FALLBACK_RESULT = Object.freeze({
  synced: false,
  reason: 'db-deadlock',
  permission: null
});
const isStrictMainlandPhone = (candidate) => {
  const raw = String(candidate ?? '');
  const normalized = raw.trim();
  return raw === normalized && MAINLAND_PHONE_PATTERN.test(normalized);
};
const isStrictOptionalTenantUserProfileField = ({
  value,
  maxLength
} = {}) => {
  const resolvedRawValue = resolveOptionalTenantUserProfileField(value);
  if (resolvedRawValue === null) {
    return true;
  }
  if (typeof resolvedRawValue !== 'string') {
    return false;
  }
  const normalized = normalizeOptionalTenantUserProfileField({
    value: resolvedRawValue,
    maxLength
  });
  return normalized !== null && normalized === resolvedRawValue;
};

const toSessionRecord = (row) => {
  if (!row) {
    return null;
  }

  return {
    sessionId: row.session_id,
    userId: String(row.user_id),
    sessionVersion: Number(row.session_version),
    entryDomain: row.entry_domain ? String(row.entry_domain) : 'platform',
    activeTenantId: row.active_tenant_id ? String(row.active_tenant_id) : null,
    status: row.status,
    revokedReason: row.revoked_reason || null
  };
};

const toRefreshRecord = (row) => {
  if (!row) {
    return null;
  }

  return {
    tokenHash: row.token_hash,
    sessionId: row.session_id,
    userId: String(row.user_id),
    status: row.status,
    rotatedFrom: row.rotated_from_token_hash || null,
    rotatedTo: row.rotated_to_token_hash || null,
    expiresAt: Number(row.expires_at_epoch_ms)
  };
};

const toUserRecord = (row) => {
  if (!row) {
    return null;
  }

  return {
    id: String(row.id),
    phone: row.phone,
    passwordHash: row.password_hash,
    status: normalizeUserStatus(row.status),
    sessionVersion: Number(row.session_version)
  };
};

const toPlatformRoleCatalogRecord = (row) => {
  if (!row) {
    return null;
  }
  return {
    roleId: String(row.role_id || '').trim(),
    tenantId: normalizePlatformRoleCatalogTenantId(row.tenant_id) || null,
    code: String(row.code || '').trim(),
    name: String(row.name || '').trim(),
    status: normalizePlatformRoleCatalogStatus(row.status || 'active'),
    scope: normalizePlatformRoleCatalogScope(row.scope || 'platform'),
    isSystem: toBoolean(row.is_system),
    createdByUserId: row.created_by_user_id ? String(row.created_by_user_id) : null,
    updatedByUserId: row.updated_by_user_id ? String(row.updated_by_user_id) : null,
    createdAt: row.created_at instanceof Date
      ? row.created_at.toISOString()
      : String(row.created_at || ''),
    updatedAt: row.updated_at instanceof Date
      ? row.updated_at.toISOString()
      : String(row.updated_at || '')
  };
};

const toPlatformIntegrationCatalogRecord = (row) => {
  if (!row) {
    return null;
  }
  const normalizedIntegrationId = normalizePlatformIntegrationId(
    row.integration_id
  );
  const normalizedCode = normalizePlatformIntegrationCode(row.code);
  const normalizedDirection = normalizePlatformIntegrationDirection(row.direction);
  const normalizedLifecycleStatus = normalizePlatformIntegrationLifecycleStatus(
    row.lifecycle_status
  );
  if (
    !isValidPlatformIntegrationId(normalizedIntegrationId)
    || !normalizedCode
    || normalizedCode.length > MAX_PLATFORM_INTEGRATION_CODE_LENGTH
    || !VALID_PLATFORM_INTEGRATION_DIRECTION.has(normalizedDirection)
    || !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedLifecycleStatus)
  ) {
    return null;
  }
  const normalizedProtocol = String(row.protocol || '').trim();
  const normalizedAuthMode = String(row.auth_mode || '').trim();
  const normalizedName = String(row.name || '').trim();
  const normalizedTimeoutMs = Number(row.timeout_ms);
  const normalizedEndpoint = normalizePlatformIntegrationOptionalText(row.endpoint);
  const normalizedBaseUrl = normalizePlatformIntegrationOptionalText(row.base_url);
  const normalizedVersionStrategy = normalizePlatformIntegrationOptionalText(
    row.version_strategy
  );
  const normalizedRunbookUrl = normalizePlatformIntegrationOptionalText(row.runbook_url);
  const normalizedLifecycleReason = normalizePlatformIntegrationOptionalText(
    row.lifecycle_reason
  );
  if (
    !normalizedProtocol
    || normalizedProtocol.length > MAX_PLATFORM_INTEGRATION_PROTOCOL_LENGTH
    || !normalizedAuthMode
    || normalizedAuthMode.length > MAX_PLATFORM_INTEGRATION_AUTH_MODE_LENGTH
    || !normalizedName
    || normalizedName.length > MAX_PLATFORM_INTEGRATION_NAME_LENGTH
    || (
      normalizedEndpoint !== null
      && normalizedEndpoint.length > MAX_PLATFORM_INTEGRATION_ENDPOINT_LENGTH
    )
    || (
      normalizedBaseUrl !== null
      && normalizedBaseUrl.length > MAX_PLATFORM_INTEGRATION_BASE_URL_LENGTH
    )
    || (
      normalizedVersionStrategy !== null
      && normalizedVersionStrategy.length > MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH
    )
    || (
      normalizedRunbookUrl !== null
      && normalizedRunbookUrl.length > MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH
    )
    || (
      normalizedLifecycleReason !== null
      && normalizedLifecycleReason.length > MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH
    )
    || !Number.isInteger(normalizedTimeoutMs)
    || normalizedTimeoutMs < 1
  ) {
    return null;
  }
  return {
    integrationId: normalizedIntegrationId,
    code: normalizedCode,
    codeNormalized: normalizePlatformIntegrationCodeKey(normalizedCode),
    name: normalizedName,
    direction: normalizedDirection,
    protocol: normalizedProtocol,
    authMode: normalizedAuthMode,
    endpoint: normalizedEndpoint,
    baseUrl: normalizedBaseUrl,
    timeoutMs: normalizedTimeoutMs,
    retryPolicy: safeParseJsonValue(row.retry_policy),
    idempotencyPolicy: safeParseJsonValue(row.idempotency_policy),
    versionStrategy: normalizedVersionStrategy,
    runbookUrl: normalizedRunbookUrl,
    lifecycleStatus: normalizedLifecycleStatus,
    lifecycleReason: normalizedLifecycleReason,
    createdByUserId: normalizePlatformIntegrationOptionalText(row.created_by_user_id),
    updatedByUserId: normalizePlatformIntegrationOptionalText(row.updated_by_user_id),
    createdAt: row.created_at instanceof Date
      ? row.created_at.toISOString()
      : String(row.created_at || ''),
    updatedAt: row.updated_at instanceof Date
      ? row.updated_at.toISOString()
      : String(row.updated_at || '')
  };
};

const toPlatformIntegrationContractVersionRecord = (row) => {
  if (!row) {
    return null;
  }
  const integrationId = normalizePlatformIntegrationId(row.integration_id);
  const contractType = normalizePlatformIntegrationContractType(row.contract_type);
  const contractVersion = normalizePlatformIntegrationContractVersion(
    row.contract_version
  );
  const schemaRef = normalizePlatformIntegrationOptionalText(row.schema_ref);
  const schemaChecksum = normalizePlatformIntegrationContractSchemaChecksum(
    row.schema_checksum
  );
  const status = normalizePlatformIntegrationContractStatus(row.status);
  const compatibilityNotes = normalizePlatformIntegrationOptionalText(
    row.compatibility_notes
  );
  const createdByUserId = normalizePlatformIntegrationOptionalText(
    row.created_by_user_id
  );
  const updatedByUserId = normalizePlatformIntegrationOptionalText(
    row.updated_by_user_id
  );
  const createdAt = row.created_at instanceof Date
    ? row.created_at.toISOString()
    : String(row.created_at || '');
  const updatedAt = row.updated_at instanceof Date
    ? row.updated_at.toISOString()
    : String(row.updated_at || '');
  if (
    !isValidPlatformIntegrationId(integrationId)
    || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(contractType)
    || !contractVersion
    || contractVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
    || !schemaRef
    || schemaRef.length > MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_REF_LENGTH
    || !schemaChecksum
    || schemaChecksum.length > MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_CHECKSUM_LENGTH
    || !PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN.test(schemaChecksum)
    || !VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS.has(status)
    || (
      compatibilityNotes !== null
      && compatibilityNotes.length > MAX_PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_NOTES_LENGTH
    )
    || !createdAt
    || !updatedAt
  ) {
    return null;
  }
  return {
    contractId: Number(row.contract_id),
    integrationId,
    contractType,
    contractVersion,
    schemaRef,
    schemaChecksum,
    status,
    isBackwardCompatible: toBoolean(row.is_backward_compatible),
    compatibilityNotes,
    createdByUserId,
    updatedByUserId,
    createdAt,
    updatedAt
  };
};

const toPlatformIntegrationContractCompatibilityCheckRecord = (row) => {
  if (!row) {
    return null;
  }
  const integrationId = normalizePlatformIntegrationId(row.integration_id);
  const contractType = normalizePlatformIntegrationContractType(row.contract_type);
  const baselineVersion = normalizePlatformIntegrationContractVersion(
    row.baseline_version
  );
  const candidateVersion = normalizePlatformIntegrationContractVersion(
    row.candidate_version
  );
  const evaluationResult = normalizePlatformIntegrationContractEvaluationResult(
    row.evaluation_result
  );
  const requestId = String(row.request_id || '').trim();
  const checkedByUserId = normalizePlatformIntegrationOptionalText(
    row.checked_by_user_id
  );
  const checkedAt = row.checked_at instanceof Date
    ? row.checked_at.toISOString()
    : String(row.checked_at || '');
  const breakingChangeCount = Number(row.breaking_change_count);
  const diffSummary = safeParseJsonValue(row.diff_summary);
  if (
    !isValidPlatformIntegrationId(integrationId)
    || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(contractType)
    || !baselineVersion
    || baselineVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
    || !candidateVersion
    || candidateVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
    || !VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT.has(evaluationResult)
    || !Number.isInteger(breakingChangeCount)
    || breakingChangeCount < 0
    || !requestId
    || requestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
    || !checkedAt
    || (
      row.diff_summary !== null
      && row.diff_summary !== undefined
      && diffSummary === null
      && String(row.diff_summary || '').trim() !== ''
    )
  ) {
    return null;
  }
  const normalizedDiffSummary = diffSummary === null
    ? null
    : JSON.stringify(diffSummary);
  if (
    normalizedDiffSummary !== null
    && normalizedDiffSummary.length > MAX_PLATFORM_INTEGRATION_CONTRACT_DIFF_SUMMARY_LENGTH
  ) {
    return null;
  }
  return {
    checkId: Number(row.check_id),
    integrationId,
    contractType,
    baselineVersion,
    candidateVersion,
    evaluationResult,
    breakingChangeCount,
    diffSummary,
    requestId,
    checkedByUserId,
    checkedAt
  };
};

const toPlatformIntegrationRecoveryQueueRecord = (row) => {
  if (!row) {
    return null;
  }
  const recoveryId = normalizePlatformIntegrationRecoveryId(row.recovery_id);
  const integrationId = normalizePlatformIntegrationId(row.integration_id);
  const contractType = normalizePlatformIntegrationContractType(row.contract_type);
  const contractVersion = normalizePlatformIntegrationContractVersion(
    row.contract_version
  );
  const requestId = String(row.request_id || '').trim();
  const traceparent = normalizePlatformIntegrationOptionalText(row.traceparent);
  const idempotencyKey = normalizePlatformIntegrationOptionalText(
    row.idempotency_key
  );
  const attemptCount = Number(row.attempt_count);
  const maxAttempts = Number(row.max_attempts);
  const nextRetryAt = row.next_retry_at instanceof Date
    ? row.next_retry_at.toISOString()
    : (
      row.next_retry_at === null || row.next_retry_at === undefined
        ? null
        : String(row.next_retry_at || '')
    );
  const lastAttemptAt = row.last_attempt_at instanceof Date
    ? row.last_attempt_at.toISOString()
    : (
      row.last_attempt_at === null || row.last_attempt_at === undefined
        ? null
        : String(row.last_attempt_at || '')
    );
  const status = normalizePlatformIntegrationRecoveryStatus(row.status);
  const failureCode = normalizePlatformIntegrationOptionalText(row.failure_code);
  const failureDetail = normalizePlatformIntegrationOptionalText(row.failure_detail);
  const lastHttpStatus = row.last_http_status === null || row.last_http_status === undefined
    ? null
    : Number(row.last_http_status);
  const retryable = toBoolean(row.retryable);
  const payloadSnapshot = safeParseJsonValue(row.payload_snapshot);
  const responseSnapshot = safeParseJsonValue(row.response_snapshot);
  const createdByUserId = normalizePlatformIntegrationOptionalText(
    row.created_by_user_id
  );
  const updatedByUserId = normalizePlatformIntegrationOptionalText(
    row.updated_by_user_id
  );
  const createdAt = row.created_at instanceof Date
    ? row.created_at.toISOString()
    : String(row.created_at || '');
  const updatedAt = row.updated_at instanceof Date
    ? row.updated_at.toISOString()
    : String(row.updated_at || '');
  if (
    !recoveryId
    || recoveryId.length > MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH
    || !isValidPlatformIntegrationId(integrationId)
    || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(contractType)
    || !contractVersion
    || contractVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
    || !requestId
    || requestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
    || (
      traceparent !== null
      && traceparent.length > MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH
    )
    || (
      idempotencyKey !== null
      && idempotencyKey.length > MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH
    )
    || !Number.isInteger(attemptCount)
    || attemptCount < 0
    || !Number.isInteger(maxAttempts)
    || maxAttempts < 1
    || maxAttempts > 5
    || !VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS.has(status)
    || (
      failureCode !== null
      && failureCode.length > MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH
    )
    || (
      failureDetail !== null
      && failureDetail.length > MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH
    )
    || (
      lastHttpStatus !== null
      && (
        !Number.isInteger(lastHttpStatus)
        || lastHttpStatus < 100
        || lastHttpStatus > 599
      )
    )
    || payloadSnapshot === null
    || !createdAt
    || !updatedAt
  ) {
    return null;
  }
  if (
    nextRetryAt !== null
    && Number.isNaN(new Date(nextRetryAt).getTime())
  ) {
    return null;
  }
  if (
    lastAttemptAt !== null
    && Number.isNaN(new Date(lastAttemptAt).getTime())
  ) {
    return null;
  }
  return {
    recoveryId,
    integrationId,
    contractType,
    contractVersion,
    requestId,
    traceparent,
    idempotencyKey,
    attemptCount,
    maxAttempts,
    nextRetryAt,
    lastAttemptAt,
    status,
    failureCode,
    failureDetail,
    lastHttpStatus,
    retryable,
    payloadSnapshot,
    responseSnapshot,
    createdByUserId,
    updatedByUserId,
    createdAt,
    updatedAt
  };
};

const toPlatformIntegrationFreezeRecord = (row) => {
  if (!row) {
    return null;
  }
  const freezeId = normalizePlatformIntegrationFreezeId(row.freeze_id);
  const status = normalizePlatformIntegrationFreezeStatus(row.status);
  const freezeReason = normalizePlatformIntegrationOptionalText(row.freeze_reason);
  const rollbackReason = normalizePlatformIntegrationOptionalText(row.rollback_reason);
  const frozenAt = normalizeStoreIsoTimestamp(row.frozen_at);
  const releasedAt = normalizeStoreIsoTimestamp(row.released_at);
  const frozenByUserId = normalizePlatformIntegrationOptionalText(
    row.frozen_by_user_id
  );
  const releasedByUserId = normalizePlatformIntegrationOptionalText(
    row.released_by_user_id
  );
  const requestId = String(row.request_id || '').trim();
  const traceparent = normalizePlatformIntegrationOptionalText(row.traceparent);
  const createdAt = normalizeStoreIsoTimestamp(row.created_at);
  const updatedAt = normalizeStoreIsoTimestamp(row.updated_at);
  if (
    !freezeId
    || freezeId.length > MAX_PLATFORM_INTEGRATION_FREEZE_ID_LENGTH
    || !VALID_PLATFORM_INTEGRATION_FREEZE_STATUS.has(status)
    || !freezeReason
    || freezeReason.length > MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH
    || (
      rollbackReason !== null
      && rollbackReason.length > MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH
    )
    || !frozenAt
    || (
      releasedAt !== null
      && !releasedAt
    )
    || (
      status === 'active'
      && releasedAt !== null
    )
    || (
      status === 'released'
      && releasedAt === null
    )
    || (
      frozenByUserId !== null
      && frozenByUserId.length > MAX_OPERATOR_USER_ID_LENGTH
    )
    || (
      releasedByUserId !== null
      && releasedByUserId.length > MAX_OPERATOR_USER_ID_LENGTH
    )
    || !requestId
    || requestId.length > MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH
    || (
      traceparent !== null
      && traceparent.length > MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH
    )
    || !createdAt
    || !updatedAt
  ) {
    return null;
  }
  return {
    freezeId,
    status,
    freezeReason,
    rollbackReason,
    frozenAt,
    releasedAt,
    frozenByUserId,
    releasedByUserId,
    requestId,
    traceparent,
    createdAt,
    updatedAt
  };
};

const findActivePlatformIntegrationFreezeRecordForWriteGate = async (queryClient) => {
  const rows = await queryClient.query(
    `
      SELECT freeze_id,
             status,
             freeze_reason,
             rollback_reason,
             frozen_at,
             released_at,
             frozen_by_user_id,
             released_by_user_id,
             request_id,
             traceparent,
             created_at,
             updated_at
      FROM platform_integration_freeze_control
      WHERE status = 'active'
      ORDER BY frozen_at DESC, freeze_id DESC
      LIMIT 1
      FOR UPDATE
    `
  );
  if (!Array.isArray(rows)) {
    throw new Error('platform integration freeze gate query malformed');
  }
  if (rows.length === 0) {
    return null;
  }
  const activeFreeze = toPlatformIntegrationFreezeRecord(rows[0]);
  if (!activeFreeze) {
    throw new Error('platform integration freeze gate row malformed');
  }
  return activeFreeze;
};

const assertPlatformIntegrationWriteAllowedByFreezeGate = async (queryClient) => {
  const activeFreeze = await findActivePlatformIntegrationFreezeRecordForWriteGate(queryClient);
  if (!activeFreeze) {
    return;
  }
  throw createPlatformIntegrationFreezeActiveConflictError({
    freezeId: activeFreeze.freezeId,
    frozenAt: activeFreeze.frozenAt,
    freezeReason: activeFreeze.freezeReason
  });
};

const toBoolean = (value) =>
  value === true || value === 1 || value === '1' || String(value || '').toLowerCase() === 'true';

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

const parseMySqlAuditDateTimeAsUtc = (value) => {
  const normalizedValue = String(value || '').trim();
  const match = MYSQL_AUDIT_DATETIME_PATTERN.exec(normalizedValue);
  if (!match) {
    return null;
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const fraction = String(match[7] || '');
  const milliseconds = Number((fraction + '000').slice(0, 3));
  const epochMs = Date.UTC(year, month - 1, day, hour, minute, second, milliseconds);
  if (Number.isNaN(epochMs)) {
    return null;
  }
  return new Date(epochMs);
};

const resolveAuditOccurredAtDate = (value) => {
  if (value === null || value === undefined) {
    return new Date();
  }
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      return new Date();
    }
    return value;
  }
  if (typeof value === 'string') {
    const parsedMySqlDateTime = parseMySqlAuditDateTimeAsUtc(value);
    if (parsedMySqlDateTime) {
      return parsedMySqlDateTime;
    }
  }
  const dateValue = new Date(value);
  if (Number.isNaN(dateValue.getTime())) {
    return new Date();
  }
  return dateValue;
};

const normalizeAuditOccurredAt = (value) =>
  resolveAuditOccurredAtDate(value).toISOString();

const formatAuditDateTimeForMySql = (dateValue) => {
  const resolvedDateValue = resolveAuditOccurredAtDate(dateValue);
  const iso = resolvedDateValue.toISOString();
  return `${iso.slice(0, 19).replace('T', ' ')}.${iso.slice(20, 23)}`;
};

const safeParseJsonValue = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value === 'object') {
    return value;
  }
  if (typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  try {
    return JSON.parse(trimmed);
  } catch (_error) {
    return null;
  }
};

const resolvePlatformIntegrationNetworkErrorCodeFromSnapshot = (snapshot = null) => {
  const parsedSnapshot = safeParseJsonValue(snapshot);
  if (!parsedSnapshot || typeof parsedSnapshot !== 'object' || Array.isArray(parsedSnapshot)) {
    return null;
  }
  return normalizePlatformIntegrationOptionalText(
    parsedSnapshot.network_error_code
    ?? parsedSnapshot.networkErrorCode
    ?? parsedSnapshot.error_code
    ?? parsedSnapshot.errorCode
  );
};

const isPlatformIntegrationRecoveryFailureRetryable = ({
  retryable = true,
  lastHttpStatus = null,
  failureCode = null,
  responseSnapshot = null
} = {}) => {
  if (!Boolean(retryable)) {
    return false;
  }
  return isRetryableDeliveryFailure({
    httpStatus: lastHttpStatus,
    errorCode: failureCode,
    networkErrorCode: resolvePlatformIntegrationNetworkErrorCodeFromSnapshot(
      responseSnapshot
    )
  });
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
      const keyString = String(key);
      if (
        AUDIT_EVENT_REDACTION_KEY_PATTERN.test(keyString)
        && !AUDIT_EVENT_REDACTION_COUNT_KEY_PATTERN.test(keyString)
      ) {
        sanitized[key] = '[REDACTED]';
        continue;
      }
      sanitized[key] = sanitizeAuditState(itemValue, depth + 1);
    }
    return sanitized;
  }
  return value;
};

const toAuditEventRecord = (row) => ({
  event_id: normalizeAuditStringOrNull(row?.event_id, 64) || '',
  domain: normalizeAuditDomain(row?.domain),
  tenant_id: normalizeAuditStringOrNull(row?.tenant_id, 64),
  request_id: normalizeAuditStringOrNull(row?.request_id, 128) || 'request_id_unset',
  traceparent: normalizeAuditTraceparentOrNull(row?.traceparent),
  event_type: normalizeAuditStringOrNull(row?.event_type, 128) || '',
  actor_user_id: normalizeAuditStringOrNull(row?.actor_user_id, 64),
  actor_session_id: normalizeAuditStringOrNull(row?.actor_session_id, 128),
  target_type: normalizeAuditStringOrNull(row?.target_type, 64) || '',
  target_id: normalizeAuditStringOrNull(row?.target_id, 128),
  result: normalizeAuditResult(row?.result) || 'failed',
  before_state: safeParseJsonValue(row?.before_state),
  after_state: safeParseJsonValue(row?.after_state),
  metadata: safeParseJsonValue(row?.metadata),
  occurred_at: row?.occurred_at instanceof Date
    ? row.occurred_at.toISOString()
    : normalizeAuditOccurredAt(row?.occurred_at)
});

const isActiveLikeStatus = (status) => {
  const normalizedStatus = String(status || 'active').trim().toLowerCase();
  return normalizedStatus === 'active' || normalizedStatus === 'enabled';
};
const VALID_PLATFORM_ROLE_FACT_STATUS = new Set(['active', 'enabled', 'disabled']);

const toPlatformPermissionSnapshot = ({
  canViewUserManagement = false,
  canOperateUserManagement = false,
  canViewTenantManagement = false,
  canOperateTenantManagement = false,
  canViewRoleManagement = false,
  canOperateRoleManagement = false
} = {}, scopeLabel = '平台权限（角色并集）') => ({
  scopeLabel,
  canViewUserManagement: Boolean(canViewUserManagement),
  canOperateUserManagement: Boolean(canOperateUserManagement),
  canViewTenantManagement: Boolean(canViewTenantManagement),
  canOperateTenantManagement: Boolean(canOperateTenantManagement),
  canViewRoleManagement: Boolean(canViewRoleManagement),
  canOperateRoleManagement: Boolean(canOperateRoleManagement)
});

const isSamePlatformPermissionSnapshot = (left, right) => {
  const normalizedLeft = left || toPlatformPermissionSnapshot();
  const normalizedRight = right || toPlatformPermissionSnapshot();
  return (
    Boolean(normalizedLeft.canViewUserManagement) === Boolean(normalizedRight.canViewUserManagement)
    && Boolean(normalizedLeft.canOperateUserManagement) === Boolean(normalizedRight.canOperateUserManagement)
    && Boolean(normalizedLeft.canViewTenantManagement) === Boolean(normalizedRight.canViewTenantManagement)
    && Boolean(normalizedLeft.canOperateTenantManagement) === Boolean(normalizedRight.canOperateTenantManagement)
    && Boolean(normalizedLeft.canViewRoleManagement) === Boolean(normalizedRight.canViewRoleManagement)
    && Boolean(normalizedLeft.canOperateRoleManagement) === Boolean(normalizedRight.canOperateRoleManagement)
  );
};

const normalizePlatformRoleStatus = (status) => {
  if (status === null || status === undefined) {
    return 'active';
  }
  if (typeof status !== 'string') {
    throw new Error(`invalid platform role status: ${String(status)}`);
  }
  const normalizedStatus = status.trim().toLowerCase();
  if (!normalizedStatus) {
    throw new Error('invalid platform role status:');
  }
  if (!VALID_PLATFORM_ROLE_FACT_STATUS.has(normalizedStatus)) {
    throw new Error(`invalid platform role status: ${normalizedStatus}`);
  }
  return normalizedStatus;
};

const aggregatePlatformPermissionFromRoleRows = (rows) => {
  const normalizedRows = Array.isArray(rows) ? rows : [];
  const activeRows = normalizedRows.filter((row) =>
    isActiveLikeStatus(row?.status)
  );

  return {
    hasRoleFacts: normalizedRows.length > 0,
    hasActiveRoleFacts: activeRows.length > 0,
    permission: toPlatformPermissionSnapshot({
      canViewUserManagement: activeRows.some((row) =>
        toBoolean(row?.can_view_user_management ?? row?.canViewUserManagement)
      ),
      canOperateUserManagement: activeRows.some((row) =>
        toBoolean(row?.can_operate_user_management ?? row?.canOperateUserManagement)
      ),
      canViewTenantManagement: activeRows.some((row) =>
        toBoolean(row?.can_view_tenant_management ?? row?.canViewTenantManagement)
      ),
      canOperateTenantManagement: activeRows.some((row) =>
        toBoolean(row?.can_operate_tenant_management ?? row?.canOperateTenantManagement)
      )
    })
  };
};

const normalizePlatformRoleFactPayload = (role) => {
  const roleId = String(role?.roleId || role?.role_id || '').trim();
  if (!roleId) {
    return null;
  }
  const permissionSource = role?.permission || role;
  return {
    roleId,
    status: normalizePlatformRoleStatus(role?.status),
    canViewUserManagement: toBoolean(
      permissionSource?.canViewUserManagement ?? permissionSource?.can_view_user_management
    ),
    canOperateUserManagement: toBoolean(
      permissionSource?.canOperateUserManagement ?? permissionSource?.can_operate_user_management
    ),
    canViewTenantManagement: toBoolean(
      permissionSource?.canViewTenantManagement ?? permissionSource?.can_view_tenant_management
    ),
    canOperateTenantManagement: toBoolean(
      permissionSource?.canOperateTenantManagement ?? permissionSource?.can_operate_tenant_management
    )
  };
};

const dedupePlatformRoleFacts = (roles = []) => {
  const dedupedByRoleId = new Map();
  for (const role of Array.isArray(roles) ? roles : []) {
    const normalizedRole = normalizePlatformRoleFactPayload(role);
    if (!normalizedRole) {
      continue;
    }
    const dedupeKey = String(normalizedRole.roleId || '').trim().toLowerCase();
    if (!dedupeKey) {
      continue;
    }
    dedupedByRoleId.set(dedupeKey, normalizedRole);
  }
  return [...dedupedByRoleId.values()];
};

const isTableMissingError = (error) =>
  String(error?.code || '').toUpperCase() === 'ER_NO_SUCH_TABLE'
  || Number(error?.errno || 0) === 1146;

const isDeadlockError = (error) =>
  String(error?.code || '').toUpperCase() === 'ER_LOCK_DEADLOCK'
  || Number(error?.errno || 0) === 1213
  || String(error?.sqlState || '').trim() === '40001';
const isDuplicateEntryError = (error) =>
  String(error?.code || '').toUpperCase() === 'ER_DUP_ENTRY'
  || Number(error?.errno || 0) === MYSQL_DUP_ENTRY_ERRNO;
const isMissingTenantUsershipHistoryTableError = (error) =>
  isTableMissingError(error)
  && /auth_user_tenant_membership_history/i.test(String(error?.message || ''));
const isMissingTenantsTableError = (error) =>
  isTableMissingError(error)
  && /\btenants\b/i.test(String(error?.message || ''));
const TENANT_MEMBERSHIP_HISTORY_UNAVAILABLE_CODE =
  'AUTH-503-TENANT-MEMBER-HISTORY-UNAVAILABLE';
const createTenantUsershipHistoryUnavailableError = () => {
  const error = new Error(
    'tenant usership history table is required but unavailable'
  );
  error.code = TENANT_MEMBERSHIP_HISTORY_UNAVAILABLE_CODE;
  return error;
};
const buildSqlInPlaceholders = (count) =>
  new Array(Math.max(0, Number(count) || 0)).fill('?').join(', ');
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
const createSystemSensitiveConfigVersionConflictError = ({
  configKey = '',
  expectedVersion = 0,
  currentVersion = 0
} = {}) => {
  const error = new Error('system sensitive config version conflict');
  error.code = 'ERR_SYSTEM_SENSITIVE_CONFIG_VERSION_CONFLICT';
  error.configKey = normalizeSystemSensitiveConfigKey(configKey);
  error.expectedVersion = Number(expectedVersion);
  error.currentVersion = Number(currentVersion);
  return error;
};
const toSystemSensitiveConfigRecord = (row) => {
  if (!row) {
    return null;
  }
  const configKey = normalizeSystemSensitiveConfigKey(row.config_key ?? row.configKey);
  if (!configKey || !ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(configKey)) {
    return null;
  }
  const updatedAtValue = row.updated_at ?? row.updatedAt;
  const createdAtValue = row.created_at ?? row.createdAt;
  return {
    configKey,
    encryptedValue: String(row.encrypted_value ?? row.encryptedValue ?? '').trim(),
    version: Number(row.version || 0),
    previousVersion: Number(row.previous_version || row.previousVersion || 0),
    status: normalizeSystemSensitiveConfigStatus(row.status || 'active') || 'active',
    updatedByUserId: String(row.updated_by_user_id ?? row.updatedByUserId ?? '').trim() || null,
    updatedAt: updatedAtValue instanceof Date
      ? updatedAtValue.toISOString()
      : String(updatedAtValue || ''),
    createdByUserId: String(row.created_by_user_id ?? row.createdByUserId ?? '').trim() || null,
    createdAt: createdAtValue instanceof Date
      ? createdAtValue.toISOString()
      : String(createdAtValue || '')
  };
};
const normalizePlatformPermissionCode = (permissionCode) =>
  String(permissionCode || '').trim();
const toPlatformPermissionCodeKey = (permissionCode) =>
  normalizePlatformPermissionCode(permissionCode).toLowerCase();
const normalizePlatformPermissionCodes = (permissionCodes = []) => {
  const deduped = new Map();
  for (const permissionCode of Array.isArray(permissionCodes) ? permissionCodes : []) {
    const normalizedCode = normalizePlatformPermissionCode(permissionCode);
    if (!normalizedCode) {
      continue;
    }
    const permissionCodeKey = normalizedCode.toLowerCase();
    deduped.set(permissionCodeKey, permissionCodeKey);
  }
  return [...deduped.values()];
};
const createPlatformRolePermissionGrantDataError = (
  reason = 'platform-role-permission-grants-invalid'
) => {
  const error = new Error('platform role permission grants invalid');
  error.code = 'ERR_PLATFORM_ROLE_PERMISSION_GRANTS_INVALID';
  error.reason = String(reason || 'platform-role-permission-grants-invalid')
    .trim()
    .toLowerCase();
  return error;
};
const normalizeStrictPlatformPermissionCodeFromGrantRow = (
  permissionCode,
  reason = 'platform-role-permission-grants-invalid'
) => {
  if (typeof permissionCode !== 'string') {
    throw createPlatformRolePermissionGrantDataError(reason);
  }
  const normalizedPermissionCode = normalizePlatformPermissionCode(permissionCode);
  const permissionCodeKey = toPlatformPermissionCodeKey(normalizedPermissionCode);
  if (
    permissionCode !== normalizedPermissionCode
    || !normalizedPermissionCode
    || CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)
    || !KNOWN_PLATFORM_PERMISSION_CODE_SET.has(permissionCodeKey)
  ) {
    throw createPlatformRolePermissionGrantDataError(reason);
  }
  return permissionCodeKey;
};
const normalizeStrictRoleIdFromPlatformGrantRow = (
  roleId,
  reason = 'platform-role-permission-grants-invalid-role-id'
) => {
  if (typeof roleId !== 'string') {
    throw createPlatformRolePermissionGrantDataError(reason);
  }
  const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
  if (
    roleId !== roleId.trim()
    || roleId !== normalizedRoleId
    || !normalizedRoleId
    || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
    || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
  ) {
    throw createPlatformRolePermissionGrantDataError(reason);
  }
  return normalizedRoleId;
};
const toPlatformPermissionSnapshotFromGrantCodes = (permissionCodes = []) => {
  const snapshot = toPlatformPermissionSnapshotFromCodes(
    normalizePlatformPermissionCodes(permissionCodes)
  );
  return toPlatformPermissionSnapshot({
    canViewUserManagement: snapshot.canViewUserManagement,
    canOperateUserManagement: snapshot.canOperateUserManagement,
    canViewTenantManagement: snapshot.canViewTenantManagement,
    canOperateTenantManagement: snapshot.canOperateTenantManagement,
    canViewRoleManagement: snapshot.canViewRoleManagement,
    canOperateRoleManagement: snapshot.canOperateRoleManagement
  });
};
const normalizeTenantPermissionCode = (permissionCode) =>
  String(permissionCode || '').trim();
const normalizeTenantPermissionCodes = (permissionCodes = []) => {
  const deduped = new Map();
  for (const permissionCode of Array.isArray(permissionCodes) ? permissionCodes : []) {
    const normalizedCode = normalizeTenantPermissionCode(permissionCode);
    if (!normalizedCode) {
      continue;
    }
    const permissionCodeKey = normalizedCode.toLowerCase();
    deduped.set(permissionCodeKey, permissionCodeKey);
  }
  return [...deduped.values()];
};
const createTenantRolePermissionGrantDataError = (
  reason = 'tenant-role-permission-grants-invalid'
) => {
  const error = new Error('tenant role permission grants invalid');
  error.code = 'ERR_TENANT_ROLE_PERMISSION_GRANTS_INVALID';
  error.reason = String(reason || 'tenant-role-permission-grants-invalid')
    .trim()
    .toLowerCase();
  return error;
};
const normalizeStrictTenantPermissionCodeFromGrantRow = (
  permissionCode,
  reason = 'tenant-role-permission-grants-invalid'
) => {
  if (typeof permissionCode !== 'string') {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  const normalizedPermissionCode = normalizeTenantPermissionCode(permissionCode);
  const permissionCodeKey = normalizedPermissionCode.toLowerCase();
  if (
    permissionCode !== normalizedPermissionCode
    || !normalizedPermissionCode
    || CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)
    || !KNOWN_TENANT_PERMISSION_CODE_SET.has(permissionCodeKey)
  ) {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  return permissionCodeKey;
};
const normalizeStrictTenantRolePermissionGrantIdentity = (
  identityValue,
  reason = 'tenant-role-permission-grants-invalid-identity'
) => {
  if (typeof identityValue !== 'string') {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  const normalizedIdentity = identityValue.trim();
  if (
    !normalizedIdentity
    || identityValue !== normalizedIdentity
    || CONTROL_CHAR_PATTERN.test(normalizedIdentity)
  ) {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  return normalizedIdentity;
};
const normalizeStrictRoleIdFromTenantGrantRow = (
  roleId,
  reason = 'tenant-role-permission-grants-invalid-role-id'
) => {
  if (typeof roleId !== 'string') {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
  if (
    roleId !== roleId.trim()
    || roleId !== normalizedRoleId
    || !normalizedRoleId
    || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
    || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
  ) {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  return normalizedRoleId;
};
const createTenantUsershipRoleBindingDataError = (
  reason = 'tenant-membership-role-bindings-invalid'
) => {
  const error = new Error('tenant usership role bindings invalid');
  error.code = 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_INVALID';
  error.reason = String(reason || 'tenant-membership-role-bindings-invalid')
    .trim()
    .toLowerCase();
  return error;
};
const normalizeStrictTenantUsershipRoleIdFromBindingRow = (
  roleId,
  reason = 'tenant-membership-role-bindings-invalid-role-id'
) => {
  if (typeof roleId !== 'string') {
    throw createTenantUsershipRoleBindingDataError(reason);
  }
  const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
  if (
    roleId !== roleId.trim()
    || roleId !== normalizedRoleId
    || !normalizedRoleId
    || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
    || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
  ) {
    throw createTenantUsershipRoleBindingDataError(reason);
  }
  return normalizedRoleId;
};
const normalizeStrictTenantUsershipRoleBindingIdentity = (
  identityValue,
  reason = 'tenant-membership-role-bindings-invalid-identity'
) => {
  if (typeof identityValue !== 'string') {
    throw createTenantUsershipRoleBindingDataError(reason);
  }
  const normalizedIdentity = identityValue.trim();
  if (
    !normalizedIdentity
    || identityValue !== normalizedIdentity
    || CONTROL_CHAR_PATTERN.test(normalizedIdentity)
  ) {
    throw createTenantUsershipRoleBindingDataError(reason);
  }
  return normalizedIdentity;
};
const toTenantPermissionSnapshotFromGrantCodes = (permissionCodes = []) => {
  const snapshot = toTenantPermissionSnapshotFromCodes(
    normalizeTenantPermissionCodes(permissionCodes)
  );
  return toPlatformPermissionSnapshot({
    canViewUserManagement: snapshot.canViewUserManagement,
    canOperateUserManagement: snapshot.canOperateUserManagement,
    canViewRoleManagement: snapshot.canViewRoleManagement,
    canOperateRoleManagement: snapshot.canOperateRoleManagement
  }, '组织权限（角色并集）');
};
const toTenantPermissionSnapshotFromRow = (row, scopeLabel = '组织权限（角色并集）') =>
  toPlatformPermissionSnapshot(
    {
      canViewUserManagement: row?.can_view_user_management ?? row?.canViewUserManagement,
      canOperateUserManagement: row?.can_operate_user_management ?? row?.canOperateUserManagement,
      canViewRoleManagement:
        row?.can_view_role_management
        ?? row?.canViewRoleManagement,
      canOperateRoleManagement:
        row?.can_operate_role_management
        ?? row?.canOperateRoleManagement
    },
    scopeLabel
  );
const isSameTenantPermissionSnapshot = (left, right) =>
  isSamePlatformPermissionSnapshot(
    toPlatformPermissionSnapshot(
      {
        canViewUserManagement: left?.canViewUserManagement,
        canOperateUserManagement: left?.canOperateUserManagement,
        canViewRoleManagement: left?.canViewRoleManagement,
        canOperateRoleManagement: left?.canOperateRoleManagement
      },
      '组织权限（角色并集）'
    ),
    toPlatformPermissionSnapshot(
      {
        canViewUserManagement: right?.canViewUserManagement,
        canOperateUserManagement: right?.canOperateUserManagement,
        canViewRoleManagement: right?.canViewRoleManagement,
        canOperateRoleManagement: right?.canOperateRoleManagement
      },
      '组织权限（角色并集）'
    )
  );

const createMySqlAuthStore = ({
  dbClient,
  random = Math.random,
  sleepFn = sleep,
  deadlockRetryConfig = {},
  onDeadlockMetric = null
}) => {
  if (!dbClient || typeof dbClient.query !== 'function') {
    throw new Error('createMySqlAuthStore requires dbClient.query');
  }
  if (typeof dbClient.inTransaction !== 'function') {
    throw new Error('createMySqlAuthStore requires dbClient.inTransaction');
  }
  if (typeof random !== 'function') {
    throw new Error('createMySqlAuthStore requires random function when random is provided');
  }
  if (typeof sleepFn !== 'function') {
    throw new Error('createMySqlAuthStore requires sleepFn function when sleepFn is provided');
  }

  const retryConfig = {
    maxRetries: Math.max(
      0,
      Math.floor(
        Number(
          deadlockRetryConfig?.maxRetries
            ?? DEFAULT_DEADLOCK_RETRY_CONFIG.maxRetries
        )
      )
    ),
    baseDelayMs: Math.max(
      0,
      Math.floor(
        Number(
          deadlockRetryConfig?.baseDelayMs
            ?? DEFAULT_DEADLOCK_RETRY_CONFIG.baseDelayMs
        )
      )
    ),
    maxDelayMs: Math.max(
      0,
      Math.floor(
        Number(
          deadlockRetryConfig?.maxDelayMs
            ?? DEFAULT_DEADLOCK_RETRY_CONFIG.maxDelayMs
        )
      )
    ),
    jitterMs: Math.max(
      0,
      Math.floor(
        Number(
          deadlockRetryConfig?.jitterMs
            ?? DEFAULT_DEADLOCK_RETRY_CONFIG.jitterMs
        )
      )
    )
  };
  if (retryConfig.maxDelayMs < retryConfig.baseDelayMs) {
    retryConfig.maxDelayMs = retryConfig.baseDelayMs;
  }

  const deadlockMetricsByOperation = new Map();
  const getDeadlockMetricsByOperation = (operation) => {
    const normalizedOperation = String(operation || 'unknown');
    if (!deadlockMetricsByOperation.has(normalizedOperation)) {
      deadlockMetricsByOperation.set(normalizedOperation, {
        deadlockCount: 0,
        retrySuccessCount: 0,
        finalFailureCount: 0
      });
    }
    return deadlockMetricsByOperation.get(normalizedOperation);
  };

  const toDeadlockRates = (metrics) => {
    const resolutionCount =
      Number(metrics?.retrySuccessCount || 0) + Number(metrics?.finalFailureCount || 0);
    if (resolutionCount <= 0) {
      return {
        retrySuccessRate: 0,
        finalFailureRate: 0
      };
    }
    return {
      retrySuccessRate: Number((Number(metrics.retrySuccessCount) / resolutionCount).toFixed(6)),
      finalFailureRate: Number((Number(metrics.finalFailureCount) / resolutionCount).toFixed(6))
    };
  };

  const emitDeadlockMetric = ({
    operation,
    event,
    attemptsUsed,
    retriesUsed,
    retryDelayMs = null,
    error = null
  }) => {
    const metrics = getDeadlockMetricsByOperation(operation);
    if (event === 'deadlock-detected') {
      metrics.deadlockCount += 1;
    } else if (event === 'retry-succeeded') {
      metrics.retrySuccessCount += 1;
    } else if (event === 'final-failure') {
      metrics.finalFailureCount += 1;
    }
    const rates = toDeadlockRates(metrics);
    const payload = {
      operation: String(operation || 'unknown'),
      event: String(event || 'unknown'),
      deadlock_count: Number(metrics.deadlockCount),
      retry_success_count: Number(metrics.retrySuccessCount),
      final_failure_count: Number(metrics.finalFailureCount),
      retry_success_rate: Number(rates.retrySuccessRate),
      final_failure_rate: Number(rates.finalFailureRate),
      attempts_used: Number(attemptsUsed || 0),
      retries_used: Number(retriesUsed || 0),
      max_retries: Number(retryConfig.maxRetries),
      retry_delay_ms: retryDelayMs === null ? null : Number(retryDelayMs),
      error_code: String(error?.code || ''),
      error_errno: Number(error?.errno || 0),
      error_sql_state: String(error?.sqlState || '')
    };
    if (typeof onDeadlockMetric === 'function') {
      try {
        onDeadlockMetric(payload);
      } catch (_error) {}
    }
    return payload;
  };

  const computeRetryDelayMs = (retryNumber) => {
    const exponent = Math.max(0, Number(retryNumber || 1) - 1);
    const baseDelay = retryConfig.baseDelayMs * (2 ** exponent);
    const boundedDelay = Math.min(retryConfig.maxDelayMs, baseDelay);
    const randomValue = Number(random());
    const normalizedRandom = Number.isFinite(randomValue)
      ? Math.min(1, Math.max(0, randomValue))
      : 0;
    const jitter = retryConfig.jitterMs > 0
      ? Math.floor(normalizedRandom * (retryConfig.jitterMs + 1))
      : 0;
    return Math.max(0, Math.floor(boundedDelay + jitter));
  };

  const executeWithDeadlockRetry = async ({
    operation,
    execute,
    onExhausted = 'return-fallback',
    fallbackResult = DEFAULT_DEADLOCK_FALLBACK_RESULT
  }) => {
    let retriesUsed = 0;
    while (true) {
      try {
        const result = await execute();
        if (retriesUsed > 0) {
          const recoveredMetric = emitDeadlockMetric({
            operation,
            event: 'retry-succeeded',
            attemptsUsed: retriesUsed + 1,
            retriesUsed
          });
          log('info', 'MySQL deadlock recovered after retry', {
            component: 'auth.store.mysql',
            ...recoveredMetric
          });
        }
        return result;
      } catch (error) {
        if (!isDeadlockError(error)) {
          throw error;
        }
        const canRetry = retriesUsed < retryConfig.maxRetries;
        const retryDelayMs = canRetry ? computeRetryDelayMs(retriesUsed + 1) : null;
        const deadlockMetric = emitDeadlockMetric({
          operation,
          event: 'deadlock-detected',
          attemptsUsed: retriesUsed + 1,
          retriesUsed,
          retryDelayMs,
          error
        });
        if (canRetry) {
          log('warn', 'MySQL deadlock detected, retrying auth store operation', {
            component: 'auth.store.mysql',
            ...deadlockMetric
          });
          retriesUsed += 1;
          if (retryDelayMs > 0) {
            await sleepFn(retryDelayMs);
          }
          continue;
        }
        const finalFailureMetric = emitDeadlockMetric({
          operation,
          event: 'final-failure',
          attemptsUsed: retriesUsed + 1,
          retriesUsed,
          retryDelayMs: null,
          error
        });
        log('error', 'MySQL deadlock retries exhausted in auth store', {
          component: 'auth.store.mysql',
          alert: true,
          ...finalFailureMetric
        });
        if (onExhausted === 'throw') {
          throw error;
        }
        if (typeof fallbackResult === 'function') {
          return fallbackResult(error);
        }
        if (
          fallbackResult
          && typeof fallbackResult === 'object'
          && !Array.isArray(fallbackResult)
        ) {
          return { ...fallbackResult };
        }
        return DEFAULT_DEADLOCK_FALLBACK_RESULT;
      }
    }
  };
  let orgStatusGuardAvailable = true;
  let tenantUsershipHistoryTableAvailable = true;

  const runTenantUsershipQuery = async ({
    txClient = dbClient,
    sqlWithOrgGuard,
    sqlWithoutOrgGuard,
    params = []
  }) => {
    const queryClient = txClient || dbClient;
    if (!orgStatusGuardAvailable) {
      return queryClient.query(sqlWithoutOrgGuard, params);
    }
    try {
      return await queryClient.query(sqlWithOrgGuard, params);
    } catch (error) {
      if (!isMissingTenantsTableError(error)) {
        throw error;
      }
      orgStatusGuardAvailable = false;
      return queryClient.query(sqlWithoutOrgGuard, params);
    }
  };

  const insertTenantUsershipHistoryTx = async ({
    txClient,
    row,
    archivedReason = null,
    archivedByUserId = null
  }) => {
    if (!tenantUsershipHistoryTableAvailable) {
      throw createTenantUsershipHistoryUnavailableError();
    }
    const normalizedRowStatus = normalizeTenantUsershipStatusForRead(row?.status);
    if (!VALID_TENANT_MEMBERSHIP_STATUS.has(normalizedRowStatus)) {
      throw new Error('insertTenantUsershipHistoryTx encountered unsupported status');
    }
    try {
      await txClient.query(
        `
          INSERT INTO auth_user_tenant_membership_history (
            membership_id,
            user_id,
            tenant_id,
            tenant_name,
            status,
            can_view_user_management,
            can_operate_user_management,
            can_view_role_management,
            can_operate_role_management,
            joined_at,
            left_at,
            archived_reason,
            archived_by_user_id
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          String(row?.membership_id || '').trim(),
          String(row?.user_id || '').trim(),
          String(row?.tenant_id || '').trim(),
          row?.tenant_name === null || row?.tenant_name === undefined
            ? null
            : String(row.tenant_name || '').trim() || null,
          normalizedRowStatus,
          toBoolean(row?.can_view_user_management) ? 1 : 0,
          toBoolean(row?.can_operate_user_management) ? 1 : 0,
          toBoolean(row?.can_view_role_management) ? 1 : 0,
          toBoolean(row?.can_operate_role_management) ? 1 : 0,
          row?.joined_at || row?.created_at || null,
          row?.left_at || null,
          archivedReason === null || archivedReason === undefined
            ? null
            : String(archivedReason || '').trim() || null,
          archivedByUserId === null || archivedByUserId === undefined
            ? null
            : String(archivedByUserId || '').trim() || null
        ]
      );
    } catch (error) {
      if (isMissingTenantUsershipHistoryTableError(error)) {
        tenantUsershipHistoryTableAvailable = false;
        throw createTenantUsershipHistoryUnavailableError();
      }
      throw error;
    }
  };

  const ensureTenantDomainAccessForUserTx = async ({
    txClient,
    userId,
    skipMembershipCheck = false
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return { inserted: false };
    }
    if (skipMembershipCheck) {
      return { inserted: false };
    }
    const tenantCountRows = await runTenantUsershipQuery({
      txClient,
      sqlWithOrgGuard: `
        SELECT COUNT(*) AS tenant_count
        FROM tenant_memberships ut
        LEFT JOIN tenants o ON o.id = ut.tenant_id
        WHERE ut.user_id = ?
          AND ut.status IN ('active', 'enabled')
          AND o.status IN ('active', 'enabled')
      `,
      sqlWithoutOrgGuard: `
        SELECT COUNT(*) AS tenant_count
        FROM tenant_memberships ut
        WHERE ut.user_id = ?
          AND ut.status IN ('active', 'enabled')
      `,
      params: [normalizedUserId]
    });
    const tenantCount = Number(tenantCountRows?.[0]?.tenant_count || 0);
    return {
      inserted: false,
      has_active_tenant_membership: tenantCount > 0
    };
  };

  const removeTenantDomainAccessForUserTx = async ({
    txClient,
    userId
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return { removed: false };
    }
    const tenantCountRows = await runTenantUsershipQuery({
      txClient,
      sqlWithOrgGuard: `
        SELECT COUNT(*) AS tenant_count
        FROM tenant_memberships ut
        LEFT JOIN tenants o ON o.id = ut.tenant_id
        WHERE ut.user_id = ?
          AND ut.status IN ('active', 'enabled')
          AND o.status IN ('active', 'enabled')
      `,
      sqlWithoutOrgGuard: `
        SELECT COUNT(*) AS tenant_count
        FROM tenant_memberships ut
        WHERE ut.user_id = ?
          AND ut.status IN ('active', 'enabled')
      `,
      params: [normalizedUserId]
    });
    const tenantCount = Number(tenantCountRows?.[0]?.tenant_count || 0);
    return { removed: tenantCount <= 0 };
  };

  const normalizeTenantUsershipRoleIds = (roleIds = []) =>
    [...new Set(
      (Array.isArray(roleIds) ? roleIds : [])
        .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
        .filter((roleId) => roleId.length > 0)
    )].sort((left, right) => left.localeCompare(right));

  const revokeTenantSessionsForUserTx = async ({
    txClient,
    userId,
    tenantId,
    reason = 'tenant-membership-permission-changed'
  }) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedTenantId = String(tenantId || '').trim();
    if (!normalizedUserId || !normalizedTenantId) {
      return;
    }
    await txClient.query(
      `
        UPDATE auth_sessions
        SET status = 'revoked',
            revoked_reason = ?,
            updated_at = CURRENT_TIMESTAMP(3)
        WHERE user_id = ?
          AND entry_domain = 'tenant'
          AND active_tenant_id = ?
          AND status = 'active'
      `,
      [reason, normalizedUserId, normalizedTenantId]
    );
    await txClient.query(
      `
        UPDATE auth_refresh_tokens
        SET status = 'revoked',
            updated_at = CURRENT_TIMESTAMP(3)
        WHERE status = 'active'
          AND session_id IN (
            SELECT session_id
            FROM auth_sessions
            WHERE user_id = ?
              AND entry_domain = 'tenant'
              AND active_tenant_id = ?
          )
      `,
      [normalizedUserId, normalizedTenantId]
    );
  };

  const listTenantUsershipRoleBindingsTx = async ({
    txClient,
    membershipId
  }) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    if (!normalizedMembershipId) {
      return [];
    }
    const roleRows = await txClient.query(
      `
        SELECT role_id
        FROM tenant_membership_roles
        WHERE membership_id = ?
        ORDER BY role_id ASC
        FOR UPDATE
      `,
      [normalizedMembershipId]
    );
    const normalizedRoleIds = [];
    const seenRoleIds = new Set();
    for (const row of Array.isArray(roleRows) ? roleRows : []) {
      const normalizedRoleId = normalizeStrictTenantUsershipRoleIdFromBindingRow(
        row?.role_id,
        'tenant-membership-role-bindings-invalid-role-id'
      );
      if (seenRoleIds.has(normalizedRoleId)) {
        throw createTenantUsershipRoleBindingDataError(
          'tenant-membership-role-bindings-duplicate-role-id'
        );
      }
      seenRoleIds.add(normalizedRoleId);
      normalizedRoleIds.push(normalizedRoleId);
    }
    return normalizedRoleIds.sort((left, right) => left.localeCompare(right));
  };

  const loadActiveTenantRoleGrantCodesByRoleIdsTx = async ({
    txClient,
    tenantId,
    roleIds = []
  }) => {
    const normalizedTenantId = String(tenantId || '').trim();
    const normalizedRoleIds = normalizeTenantUsershipRoleIds(roleIds);
    const grantsByRoleId = new Map();
    for (const roleId of normalizedRoleIds) {
      grantsByRoleId.set(roleId, []);
    }
    const seenGrantPermissionCodeKeysByRoleId = new Map(
      normalizedRoleIds.map((roleId) => [roleId, new Set()])
    );
    if (!normalizedTenantId || normalizedRoleIds.length === 0) {
      return grantsByRoleId;
    }
    const rolePlaceholders = buildSqlInPlaceholders(normalizedRoleIds.length);
    const roleRows = await txClient.query(
      `
        SELECT role_id, status, scope, tenant_id
        FROM platform_roles
        WHERE role_id IN (${rolePlaceholders})
        ORDER BY role_id ASC
        FOR UPDATE
      `,
      normalizedRoleIds
    );
    const activeRoleIds = new Set();
    for (const row of Array.isArray(roleRows) ? roleRows : []) {
      const roleId = normalizeStrictRoleIdFromTenantGrantRow(
        row?.role_id,
        'tenant-role-permission-grants-invalid-role-id'
      );
      if (!roleId || !grantsByRoleId.has(roleId)) {
        continue;
      }
      const roleScope = normalizePlatformRoleCatalogScope(row?.scope);
      const roleTenantId = normalizePlatformRoleCatalogTenantId(row?.tenant_id);
      const roleStatus = normalizePlatformRoleCatalogStatus(row?.status || 'disabled');
      if (
        roleScope === 'tenant'
        && roleTenantId === normalizedTenantId
        && isActiveLikeStatus(roleStatus)
      ) {
        activeRoleIds.add(roleId);
      }
    }
    if (activeRoleIds.size === 0) {
      return grantsByRoleId;
    }
    const grantRoleIds = [...activeRoleIds];
    const grantPlaceholders = buildSqlInPlaceholders(grantRoleIds.length);
    const grantRows = await txClient.query(
      `
        SELECT role_id, permission_code
        FROM tenant_role_permission_grants
        WHERE role_id IN (${grantPlaceholders})
        ORDER BY role_id ASC, permission_code ASC
        FOR UPDATE
      `,
      grantRoleIds
    );
    for (const row of Array.isArray(grantRows) ? grantRows : []) {
      const roleId = normalizeStrictRoleIdFromTenantGrantRow(
        row?.role_id,
        'tenant-role-permission-grants-invalid-role-id'
      );
      if (!activeRoleIds.has(roleId)) {
        throw createTenantRolePermissionGrantDataError(
          'tenant-role-permission-grants-unexpected-role-id'
        );
      }
      if (!grantsByRoleId.has(roleId)) {
        throw createTenantRolePermissionGrantDataError(
          'tenant-role-permission-grants-invalid-role-id'
        );
      }
      const permissionCodeKey = normalizeStrictTenantPermissionCodeFromGrantRow(
        row?.permission_code,
        'tenant-role-permission-grants-invalid-permission-code'
      );
      const seenPermissionCodeKeys = seenGrantPermissionCodeKeysByRoleId.get(roleId);
      if (seenPermissionCodeKeys.has(permissionCodeKey)) {
        throw createTenantRolePermissionGrantDataError(
          'tenant-role-permission-grants-duplicate-permission-code'
        );
      }
      seenPermissionCodeKeys.add(permissionCodeKey);
      grantsByRoleId.get(roleId).push(permissionCodeKey);
    }
    for (const roleId of grantsByRoleId.keys()) {
      if (!activeRoleIds.has(roleId)) {
        grantsByRoleId.set(roleId, []);
        continue;
      }
      grantsByRoleId.set(roleId, [...grantsByRoleId.get(roleId)]);
    }
    return grantsByRoleId;
  };

  const resolveTenantPermissionSnapshotForMembershipTx = async ({
    txClient,
    membership = null,
    tenantId,
    roleIds = []
  }) => {
    const normalizedTenantId = String(tenantId || '').trim();
    const membershipStatus = normalizeTenantUsershipStatusForRead(
      membership?.status
    );
    if (!isActiveLikeStatus(membershipStatus)) {
      return toTenantPermissionSnapshotFromGrantCodes([]);
    }
    const normalizedRoleIds = normalizeTenantUsershipRoleIds(roleIds);
    if (normalizedRoleIds.length === 0) {
      return toTenantPermissionSnapshotFromGrantCodes([]);
    }
    const grantsByRoleId = await loadActiveTenantRoleGrantCodesByRoleIdsTx({
      txClient,
      tenantId: normalizedTenantId,
      roleIds: normalizedRoleIds
    });
    const mergedGrantCodes = [];
    for (const roleId of normalizedRoleIds) {
      mergedGrantCodes.push(...(grantsByRoleId.get(roleId) || []));
    }
    return toTenantPermissionSnapshotFromGrantCodes(mergedGrantCodes);
  };

  const syncTenantUsershipPermissionSnapshotInTx = async ({
    txClient,
    membershipId,
    tenantId,
    roleIds = null,
    revokeReason = 'tenant-membership-permission-changed'
  }) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    const normalizedTenantId = String(tenantId || '').trim();
    if (!normalizedMembershipId || !normalizedTenantId) {
      return {
        synced: false,
        reason: 'invalid-membership-reference',
        changed: false,
        permission: null
      };
    }

    const membershipRows = await txClient.query(
      `
        SELECT membership_id,
               user_id,
               tenant_id,
               status,
               can_view_user_management,
               can_operate_user_management,
               can_view_role_management,
               can_operate_role_management
        FROM tenant_memberships
        WHERE membership_id = ? AND tenant_id = ?
        LIMIT 1
        FOR UPDATE
      `,
      [normalizedMembershipId, normalizedTenantId]
    );
    const membership = membershipRows?.[0] || null;
    if (!membership) {
      return {
        synced: false,
        reason: 'membership-not-found',
        changed: false,
        permission: null
      };
    }

    const previousSnapshot = toTenantPermissionSnapshotFromRow(
      membership,
      '组织权限（角色并集）'
    );
    const resolvedRoleIds = Array.isArray(roleIds)
      ? normalizeTenantUsershipRoleIds(roleIds)
      : await listTenantUsershipRoleBindingsTx({
        txClient,
        membershipId: normalizedMembershipId
      });
    const nextSnapshot = await resolveTenantPermissionSnapshotForMembershipTx({
      txClient,
      membership,
      tenantId: normalizedTenantId,
      roleIds: resolvedRoleIds
    });
    const changed = !isSameTenantPermissionSnapshot(previousSnapshot, nextSnapshot);
    if (changed) {
      await txClient.query(
        `
          UPDATE tenant_memberships
          SET can_view_user_management = ?,
              can_operate_user_management = ?,
              can_view_role_management = ?,
              can_operate_role_management = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE membership_id = ? AND tenant_id = ?
        `,
        [
          nextSnapshot.canViewUserManagement ? 1 : 0,
          nextSnapshot.canOperateUserManagement ? 1 : 0,
          nextSnapshot.canViewRoleManagement ? 1 : 0,
          nextSnapshot.canOperateRoleManagement ? 1 : 0,
          normalizedMembershipId,
          normalizedTenantId
        ]
      );
      await revokeTenantSessionsForUserTx({
        txClient,
        userId: membership.user_id,
        tenantId: normalizedTenantId,
        reason: revokeReason
      });
    }

    return {
      synced: true,
      reason: 'ok',
      changed,
      permission: {
        canViewUserManagement: nextSnapshot.canViewUserManagement,
        canOperateUserManagement: nextSnapshot.canOperateUserManagement,
        canViewRoleManagement: nextSnapshot.canViewRoleManagement,
        canOperateRoleManagement: nextSnapshot.canOperateRoleManagement
      },
      membershipId: normalizedMembershipId,
      tenantId: normalizedTenantId,
      userId: String(membership.user_id || '').trim(),
      roleIds: resolvedRoleIds
    };
  };

  const bumpSessionVersionAndConvergeSessionsTx = async ({
    txClient,
    userId,
    passwordHash = null,
    reason = 'critical-state-changed',
    revokeRefreshTokens = true,
    revokeAuthSessions = true
  }) => {
    const normalizedUserId = String(userId);
    const shouldUpdatePassword = passwordHash !== null && passwordHash !== undefined;
    const updateResult = shouldUpdatePassword
      ? await txClient.query(
        `
          UPDATE iam_users
          SET password_hash = ?,
              session_version = session_version + 1,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE id = ?
        `,
        [passwordHash, normalizedUserId]
      )
      : await txClient.query(
        `
          UPDATE iam_users
          SET session_version = session_version + 1,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE id = ?
        `,
        [normalizedUserId]
      );

    if (!updateResult || Number(updateResult.affectedRows || 0) !== 1) {
      return null;
    }

    if (revokeAuthSessions) {
      await txClient.query(
        `
          UPDATE auth_sessions
          SET status = 'revoked',
              revoked_reason = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND status = 'active'
        `,
        [reason || 'critical-state-changed', normalizedUserId]
      );
    }

    if (revokeRefreshTokens) {
      await txClient.query(
        `
          UPDATE auth_refresh_tokens
          SET status = 'revoked',
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND status = 'active'
        `,
        [normalizedUserId]
      );
    }

    const rows = await txClient.query(
      `
        SELECT id, phone, password_hash, status, session_version
        FROM iam_users
        WHERE id = ?
        LIMIT 1
      `,
      [normalizedUserId]
    );
    return toUserRecord(rows[0]);
  };

  const resolveActivePlatformPermissionSnapshotByUserIdTx = async ({
    txClient = dbClient,
    userId
  } = {}) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return null;
    }

    const platformUserRows = await txClient.query(
      `
        SELECT pu.status AS platform_status,
               u.status AS user_status
        FROM platform_users pu
        INNER JOIN iam_users u
          ON u.id = pu.user_id
        WHERE pu.user_id = ?
        LIMIT 1
      `,
      [normalizedUserId]
    );
    const platformUser = platformUserRows?.[0] || null;
    if (!platformUser) {
      return null;
    }

    const normalizedPlatformStatus = normalizeOrgStatus(platformUser.platform_status);
    const normalizedUserStatus = normalizeUserStatus(platformUser.user_status);
    if (
      !VALID_PLATFORM_USER_STATUS.has(normalizedPlatformStatus)
      || normalizedPlatformStatus !== 'active'
      || normalizedUserStatus !== 'active'
    ) {
      return null;
    }

    const grantRows = await txClient.query(
      `
        SELECT prg.permission_code
        FROM platform_user_roles upr
        INNER JOIN platform_roles prc
          ON prc.role_id = upr.role_id
         AND prc.scope = 'platform'
         AND prc.tenant_id = ''
         AND prc.status IN ('active', 'enabled')
        LEFT JOIN platform_role_permission_grants prg
          ON prg.role_id = upr.role_id
        WHERE upr.user_id = ?
          AND upr.status IN ('active', 'enabled')
      `,
      [normalizedUserId]
    );
    const permissionCodes = (Array.isArray(grantRows) ? grantRows : [])
      .map((row) => String(row?.permission_code || '').trim())
      .filter((permissionCode) => permissionCode.length > 0);
    const permissionSnapshot = toPlatformPermissionSnapshotFromCodes(permissionCodes);
    return toPlatformPermissionSnapshot(permissionSnapshot);
  };

  const syncPlatformPermissionSnapshotByUserIdOnce = async ({
    userId,
    forceWhenNoRoleFacts = false,
    txClient = dbClient
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return {
        synced: false,
        reason: 'invalid-user-id',
        permission: null
      };
    }
    const permission = await resolveActivePlatformPermissionSnapshotByUserIdTx({
      txClient,
      userId: normalizedUserId
    });
    if (!permission) {
      if (forceWhenNoRoleFacts) {
        return {
          synced: false,
          reason: 'already-empty',
          permission: toPlatformPermissionSnapshot()
        };
      }
      return {
        synced: false,
        reason: 'no-role-facts',
        permission: null
      };
    }
    return {
      synced: false,
      reason: 'up-to-date',
      permission
    };
  };

  const syncPlatformPermissionSnapshotByUserId = async ({
    userId,
    forceWhenNoRoleFacts = false,
    txClient = dbClient
  }) =>
    executeWithDeadlockRetry({
      operation: 'syncPlatformPermissionSnapshotByUserId',
      execute: () =>
        syncPlatformPermissionSnapshotByUserIdOnce({
          userId,
          forceWhenNoRoleFacts,
          txClient
        })
    });

  const replacePlatformRolesAndSyncSnapshotInTx = async ({
    txClient,
    userId,
    roles = []
  }) => {
    const transactionalClient = txClient || dbClient;
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return {
        synced: false,
        reason: 'invalid-user-id',
        permission: null
      };
    }

    const normalizedRoles = dedupePlatformRoleFacts(roles);

    const userRows = await transactionalClient.query(
      `
        SELECT id
        FROM iam_users
        WHERE id = ?
        LIMIT 1
        FOR UPDATE
      `,
      [normalizedUserId]
    );
    if (!userRows?.[0]) {
      return {
        synced: false,
        reason: 'invalid-user-id',
        permission: null
      };
    }

    await transactionalClient.query(
      `
        INSERT INTO platform_users (
          user_id,
          name,
          department,
          status
        )
        VALUES (?, NULL, NULL, 'active')
        ON DUPLICATE KEY UPDATE
          updated_at = updated_at
      `,
      [normalizedUserId]
    );

    const previousRoleRows = await transactionalClient.query(
      `
        SELECT status,
               can_view_user_management,
               can_operate_user_management,
               can_view_tenant_management,
               can_operate_tenant_management
        FROM platform_user_roles
        WHERE user_id = ?
      `,
      [normalizedUserId]
    );
    const previousPermission = aggregatePlatformPermissionFromRoleRows(previousRoleRows).permission;

    await transactionalClient.query(
      `
        DELETE FROM platform_user_roles
        WHERE user_id = ?
      `,
      [normalizedUserId]
    );

    for (const role of normalizedRoles) {
      await transactionalClient.query(
        `
          INSERT INTO platform_user_roles (
            user_id,
            role_id,
            status,
            can_view_user_management,
            can_operate_user_management,
            can_view_tenant_management,
            can_operate_tenant_management
          )
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `,
        [
          normalizedUserId,
          role.roleId,
          role.status,
          Number(role.canViewUserManagement),
          Number(role.canOperateUserManagement),
          Number(role.canViewTenantManagement),
          Number(role.canOperateTenantManagement)
        ]
      );
    }

    const permission = aggregatePlatformPermissionFromRoleRows(normalizedRoles).permission;

    if (!isSamePlatformPermissionSnapshot(previousPermission, permission)) {
      await bumpSessionVersionAndConvergeSessionsTx({
        txClient: transactionalClient,
        userId: normalizedUserId,
        reason: 'platform-role-facts-changed',
        revokeRefreshTokens: true,
        revokeAuthSessions: true
      });
    }

    return {
      synced: true,
      reason: 'ok',
      permission
    };
  };

  const replacePlatformRolesAndSyncSnapshotOnce = async ({ userId, roles = [] }) =>
    dbClient.inTransaction(async (tx) =>
      replacePlatformRolesAndSyncSnapshotInTx({
        txClient: tx,
        userId,
        roles
      }));

  const replacePlatformRolesAndSyncSnapshot = async ({ userId, roles = [] }) =>
    executeWithDeadlockRetry({
      operation: 'replacePlatformRolesAndSyncSnapshot',
      execute: () =>
        replacePlatformRolesAndSyncSnapshotOnce({
          userId,
          roles
        })
    });

  const recordAuditEventWithQueryClient = async ({
    queryClient,
    eventId = null,
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
    if (!queryClient || typeof queryClient.query !== 'function') {
      throw new Error('recordAuditEventWithQueryClient requires a query-capable client');
    }
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
      throw new Error('recordAuditEvent requires valid domain, result, eventType, and targetType');
    }
    const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
    if (normalizedDomain === 'tenant' && !normalizedTenantId) {
      throw new Error('recordAuditEvent tenant domain requires tenantId');
    }
    const normalizedEventId = normalizeAuditStringOrNull(eventId, 64) || randomUUID();
    const normalizedRequestId =
      normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset';
    const normalizedTraceparent = normalizeAuditTraceparentOrNull(traceparent);
    const normalizedActorUserId = normalizeAuditStringOrNull(actorUserId, 64);
    const normalizedActorSessionId = normalizeAuditStringOrNull(actorSessionId, 128);
    const normalizedTargetId = normalizeAuditStringOrNull(targetId, 128);
    const normalizedOccurredAt = normalizeAuditOccurredAt(occurredAt);
    const persistedOccurredAt = formatAuditDateTimeForMySql(normalizedOccurredAt);
    const sanitizedBeforeState = sanitizeAuditState(beforeState);
    const sanitizedAfterState = sanitizeAuditState(afterState);
    const sanitizedMetadata = sanitizeAuditState(metadata);

    await queryClient.query(
      `
        INSERT INTO audit_events (
          event_id,
          domain,
          tenant_id,
          request_id,
          traceparent,
          event_type,
          actor_user_id,
          actor_session_id,
          target_type,
          target_id,
          result,
          before_state,
          after_state,
          metadata,
          occurred_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        normalizedEventId,
        normalizedDomain,
        normalizedTenantId,
        normalizedRequestId,
        normalizedTraceparent,
        normalizedEventType,
        normalizedActorUserId,
        normalizedActorSessionId,
        normalizedTargetType,
        normalizedTargetId,
        normalizedResult,
        sanitizedBeforeState === null ? null : JSON.stringify(sanitizedBeforeState),
        sanitizedAfterState === null ? null : JSON.stringify(sanitizedAfterState),
        sanitizedMetadata === null ? null : JSON.stringify(sanitizedMetadata),
        persistedOccurredAt
      ]
    );
    return {
      event_id: normalizedEventId,
      domain: normalizedDomain,
      tenant_id: normalizedTenantId,
      request_id: normalizedRequestId,
      traceparent: normalizedTraceparent,
      event_type: normalizedEventType,
      actor_user_id: normalizedActorUserId,
      actor_session_id: normalizedActorSessionId,
      target_type: normalizedTargetType,
      target_id: normalizedTargetId,
      result: normalizedResult,
      before_state: sanitizedBeforeState,
      after_state: sanitizedAfterState,
      metadata: sanitizedMetadata,
      occurred_at: normalizedOccurredAt
    };
  };

  const recordAuditEvent = async (payload = {}) =>
    recordAuditEventWithQueryClient({
      queryClient: dbClient,
      ...payload
    });

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
      throw new Error('listAuditEvents requires a valid domain');
    }
    const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
    if (normalizedDomain === 'tenant' && !normalizedTenantId) {
      throw new Error('listAuditEvents tenant domain requires tenantId');
    }
    const resolvedPage = Math.max(1, Math.floor(Number(page || 1)));
    const resolvedPageSize = Math.min(
      MAX_AUDIT_QUERY_PAGE_SIZE,
      Math.max(1, Math.floor(Number(pageSize || 50)))
    );
    const offset = (resolvedPage - 1) * resolvedPageSize;

    const whereClauses = ['domain = ?'];
    const whereArgs = [normalizedDomain];
    if (normalizedTenantId) {
      whereClauses.push('tenant_id = ?');
      whereArgs.push(normalizedTenantId);
    }

    const normalizedEventType = normalizeAuditStringOrNull(eventType, 128);
    if (normalizedEventType) {
      whereClauses.push('event_type = ?');
      whereArgs.push(normalizedEventType);
    }
    const normalizedResult = normalizeAuditResult(result);
    if (normalizedResult) {
      whereClauses.push('result = ?');
      whereArgs.push(normalizedResult);
    }
    const normalizedRequestId = normalizeAuditStringOrNull(requestId, 128);
    if (normalizedRequestId) {
      whereClauses.push('request_id = ?');
      whereArgs.push(normalizedRequestId);
    }
    let normalizedTraceparent = null;
    if (traceparent !== null && traceparent !== undefined) {
      normalizedTraceparent = normalizeAuditTraceparentOrNull(traceparent);
      if (!normalizedTraceparent) {
        throw new Error('listAuditEvents requires valid traceparent');
      }
    }
    if (normalizedTraceparent) {
      whereClauses.push('traceparent = ?');
      whereArgs.push(normalizedTraceparent);
    }
    const normalizedActorUserId = normalizeAuditStringOrNull(actorUserId, 64);
    if (normalizedActorUserId) {
      whereClauses.push('actor_user_id = ?');
      whereArgs.push(normalizedActorUserId);
    }
    const normalizedTargetType = normalizeAuditStringOrNull(targetType, 64);
    if (normalizedTargetType) {
      whereClauses.push('target_type = ?');
      whereArgs.push(normalizedTargetType);
    }
    const normalizedTargetId = normalizeAuditStringOrNull(targetId, 128);
    if (normalizedTargetId) {
      whereClauses.push('target_id = ?');
      whereArgs.push(normalizedTargetId);
    }

    const fromDate = from ? new Date(from) : null;
    if (fromDate && !Number.isNaN(fromDate.getTime())) {
      whereClauses.push('occurred_at >= ?');
      whereArgs.push(formatAuditDateTimeForMySql(fromDate));
    }
    const toDate = to ? new Date(to) : null;
    if (toDate && !Number.isNaN(toDate.getTime())) {
      whereClauses.push('occurred_at <= ?');
      whereArgs.push(formatAuditDateTimeForMySql(toDate));
    }
    if (
      fromDate && toDate
      && !Number.isNaN(fromDate.getTime())
      && !Number.isNaN(toDate.getTime())
      && fromDate.getTime() > toDate.getTime()
    ) {
      throw new Error('listAuditEvents requires from <= to');
    }

    const whereSql = `WHERE ${whereClauses.join(' AND ')}`;
    const countRows = await dbClient.query(
      `
        SELECT COUNT(*) AS total
        FROM audit_events
        ${whereSql}
      `,
      whereArgs
    );
    const total = Number(countRows?.[0]?.total || 0);
  const rows = await dbClient.query(
      `
        SELECT event_id,
               domain,
               tenant_id,
               request_id,
               traceparent,
               event_type,
               actor_user_id,
               actor_session_id,
               target_type,
               target_id,
               result,
               before_state,
               after_state,
               metadata,
               occurred_at
        FROM audit_events
        ${whereSql}
        ORDER BY occurred_at DESC, event_id DESC
        LIMIT ? OFFSET ?
      `,
      [...whereArgs, resolvedPageSize, offset]
    );
    return {
      total,
      events: (Array.isArray(rows) ? rows : []).map((row) => toAuditEventRecord(row))
    };
  };

  const repositoryMethods = createMySqlAuthStoreCapabilities({
    dbClient,
    runTenantUsershipQuery,
    toUserRecord,
    toSessionRecord,
    toRefreshRecord,
    toBoolean,
    isDuplicateEntryError,
    escapeSqlLikePattern,
    buildSqlInPlaceholders,
    toPlatformPermissionCodeKey,
    normalizeUserStatus,
    normalizeOrgStatus,
    normalizeStoreIsoTimestamp,
    normalizeSystemSensitiveConfigKey,
    normalizeSystemSensitiveConfigStatus,
    createSystemSensitiveConfigVersionConflictError,
    normalizeRequiredPlatformUserProfileField,
    normalizeOptionalPlatformUserProfileField,
    normalizePlatformRoleCatalogRoleId,
    normalizePlatformRoleCatalogScope,
    normalizePlatformRoleCatalogTenantIdForScope,
    normalizePlatformRoleCatalogStatus,
    toSystemSensitiveConfigRecord,
    toPlatformRoleCatalogRecord,
    resolveActivePlatformPermissionSnapshotByUserIdTx,
    syncPlatformPermissionSnapshotByUserIdImpl: syncPlatformPermissionSnapshotByUserId,
    bumpSessionVersionAndConvergeSessionsTx,
    MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
    MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
    MAX_PLATFORM_ROLE_CODE_LENGTH,
    MAX_PLATFORM_ROLE_NAME_LENGTH,
    MAINLAND_PHONE_PATTERN,
    CONTROL_CHAR_PATTERN,
    MYSQL_DUP_ENTRY_ERRNO,
    ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS,
    VALID_ORG_STATUS,
    VALID_PLATFORM_USER_STATUS,
    VALID_PLATFORM_ROLE_CATALOG_SCOPE,
    VALID_PLATFORM_ROLE_CATALOG_STATUS,
    PLATFORM_ROLE_MANAGEMENT_PERMISSION_CODE_SET,
    PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
    PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
  });

  return {
    findUserByPhone: repositoryMethods.findUserByPhone,

    findUserById: repositoryMethods.findUserById,

    updateUserPhone: repositoryMethods.updateUserPhone,

    listPlatformUsers: repositoryMethods.listPlatformUsers,

    listPlatformOrgs: repositoryMethods.listPlatformOrgs,

    getPlatformUserById: repositoryMethods.getPlatformUserById,

    upsertPlatformUserProfile: repositoryMethods.upsertPlatformUserProfile,

    recordAuditEvent: async (payload = {}) =>
      recordAuditEvent(payload),

    listAuditEvents: async (query = {}) =>
      listAuditEvents(query),

    getSystemSensitiveConfig: repositoryMethods.getSystemSensitiveConfig,

    upsertSystemSensitiveConfig: repositoryMethods.upsertSystemSensitiveConfig,

    countPlatformRoleCatalogEntries: repositoryMethods.countPlatformRoleCatalogEntries,

    listPlatformRoleCatalogEntries: repositoryMethods.listPlatformRoleCatalogEntries,

    findPlatformRoleCatalogEntryByRoleId: repositoryMethods.findPlatformRoleCatalogEntryByRoleId,

    findPlatformRoleCatalogEntriesByRoleIds: repositoryMethods.findPlatformRoleCatalogEntriesByRoleIds,

    listPlatformIntegrationCatalogEntries: async ({
      direction = null,
      protocol = null,
      authMode = null,
      lifecycleStatus = null,
      keyword = null
    } = {}) => {
      const whereClauses = [];
      const queryArgs = [];
      if (direction !== null && direction !== undefined) {
        const normalizedDirection = normalizePlatformIntegrationDirection(direction);
        if (!VALID_PLATFORM_INTEGRATION_DIRECTION.has(normalizedDirection)) {
          throw new Error('listPlatformIntegrationCatalogEntries received unsupported direction');
        }
        whereClauses.push('direction = ?');
        queryArgs.push(normalizedDirection);
      }
      if (lifecycleStatus !== null && lifecycleStatus !== undefined) {
        const normalizedLifecycleStatus = normalizePlatformIntegrationLifecycleStatus(
          lifecycleStatus
        );
        if (!VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedLifecycleStatus)) {
          throw new Error(
            'listPlatformIntegrationCatalogEntries received unsupported lifecycleStatus'
          );
        }
        whereClauses.push('lifecycle_status = ?');
        queryArgs.push(normalizedLifecycleStatus);
      }
      if (protocol !== null && protocol !== undefined) {
        const normalizedProtocol = String(protocol || '').trim();
        if (!normalizedProtocol) {
          throw new Error('listPlatformIntegrationCatalogEntries received unsupported protocol');
        }
        whereClauses.push('protocol = ?');
        queryArgs.push(normalizedProtocol);
      }
      if (authMode !== null && authMode !== undefined) {
        const normalizedAuthMode = String(authMode || '').trim();
        if (!normalizedAuthMode) {
          throw new Error('listPlatformIntegrationCatalogEntries received unsupported authMode');
        }
        whereClauses.push('auth_mode = ?');
        queryArgs.push(normalizedAuthMode);
      }
      if (keyword !== null && keyword !== undefined) {
        const normalizedKeyword = String(keyword || '').trim();
        if (normalizedKeyword) {
          const keywordLike = `%${escapeSqlLikePattern(
            normalizedKeyword.toLowerCase()
          )}%`;
          whereClauses.push(
            "(code_normalized LIKE ? ESCAPE '\\\\' OR LOWER(name) LIKE ? ESCAPE '\\\\')"
          );
          queryArgs.push(keywordLike, keywordLike);
        }
      }
      const whereSql = whereClauses.length > 0
        ? `WHERE ${whereClauses.join(' AND ')}`
        : '';
      const rows = await dbClient.query(
        `
          SELECT integration_id,
                 code,
                 code_normalized,
                 name,
                 direction,
                 protocol,
                 auth_mode,
                 endpoint,
                 base_url,
                 timeout_ms,
                 retry_policy,
                 idempotency_policy,
                 version_strategy,
                 runbook_url,
                 lifecycle_status,
                 lifecycle_reason,
                 created_by_user_id,
                 updated_by_user_id,
                 created_at,
                 updated_at
          FROM platform_integration_catalog
          ${whereSql}
          ORDER BY created_at ASC, integration_id ASC
        `,
        queryArgs
      );
      if (!Array.isArray(rows)) {
        throw new Error('listPlatformIntegrationCatalogEntries result malformed');
      }
      const normalizedRows = rows.map((row) => toPlatformIntegrationCatalogRecord(row));
      if (normalizedRows.some((row) => !row)) {
        throw new Error('listPlatformIntegrationCatalogEntries result malformed');
      }
      return normalizedRows;
    },

    findPlatformIntegrationCatalogEntryByIntegrationId: async ({
      integrationId
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT integration_id,
                 code,
                 code_normalized,
                 name,
                 direction,
                 protocol,
                 auth_mode,
                 endpoint,
                 base_url,
                 timeout_ms,
                 retry_policy,
                 idempotency_policy,
                 version_strategy,
                 runbook_url,
                 lifecycle_status,
                 lifecycle_reason,
                 created_by_user_id,
                 updated_by_user_id,
                 created_at,
                 updated_at
          FROM platform_integration_catalog
          WHERE integration_id = ?
          LIMIT 1
        `,
        [normalizedIntegrationId]
      );
      if (!Array.isArray(rows)) {
        throw new Error('findPlatformIntegrationCatalogEntryByIntegrationId result malformed');
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRecord = toPlatformIntegrationCatalogRecord(rows[0]);
      if (!normalizedRecord) {
        throw new Error('findPlatformIntegrationCatalogEntryByIntegrationId result malformed');
      }
      return normalizedRecord;
    },

    createPlatformIntegrationCatalogEntry: async ({
      integrationId = randomUUID(),
      code,
      name,
      direction,
      protocol,
      authMode,
      endpoint = null,
      baseUrl = null,
      timeoutMs = PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS,
      retryPolicy = null,
      idempotencyPolicy = null,
      versionStrategy = null,
      runbookUrl = null,
      lifecycleStatus = 'draft',
      lifecycleReason = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'createPlatformIntegrationCatalogEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const integrationIdProvided =
              integrationId !== undefined && integrationId !== null;
            const normalizedRequestedIntegrationId =
              normalizePlatformIntegrationId(integrationId);
            if (
              integrationIdProvided
              && !isValidPlatformIntegrationId(normalizedRequestedIntegrationId)
            ) {
              throw new Error('createPlatformIntegrationCatalogEntry received invalid integrationId');
            }
            const normalizedIntegrationId = isValidPlatformIntegrationId(
              normalizedRequestedIntegrationId
            )
              ? normalizedRequestedIntegrationId
              : randomUUID();
            const normalizedCode = normalizePlatformIntegrationCode(code);
            const normalizedCodeKey = normalizePlatformIntegrationCodeKey(normalizedCode);
            const normalizedName = String(name || '').trim();
            const normalizedDirection = normalizePlatformIntegrationDirection(direction);
            const normalizedProtocol = String(protocol || '').trim();
            const normalizedAuthMode = String(authMode || '').trim();
            const normalizedEndpoint = normalizePlatformIntegrationOptionalText(endpoint);
            const normalizedBaseUrl = normalizePlatformIntegrationOptionalText(baseUrl);
            const normalizedTimeoutMs = normalizePlatformIntegrationTimeoutMs(timeoutMs);
            const normalizedRetryPolicy = normalizePlatformIntegrationJsonForStorage({
              value: retryPolicy
            });
            const normalizedIdempotencyPolicy = normalizePlatformIntegrationJsonForStorage({
              value: idempotencyPolicy
            });
            const normalizedVersionStrategy = normalizePlatformIntegrationOptionalText(
              versionStrategy
            );
            const normalizedRunbookUrl = normalizePlatformIntegrationOptionalText(runbookUrl);
            const normalizedLifecycleStatus = normalizePlatformIntegrationLifecycleStatus(
              lifecycleStatus
            );
            const normalizedLifecycleReason = normalizePlatformIntegrationOptionalText(
              lifecycleReason
            );
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !normalizedCode
              || normalizedCode.length > MAX_PLATFORM_INTEGRATION_CODE_LENGTH
              || !normalizedName
              || normalizedName.length > MAX_PLATFORM_INTEGRATION_NAME_LENGTH
              || !VALID_PLATFORM_INTEGRATION_DIRECTION.has(normalizedDirection)
              || !normalizedProtocol
              || normalizedProtocol.length > MAX_PLATFORM_INTEGRATION_PROTOCOL_LENGTH
              || !normalizedAuthMode
              || normalizedAuthMode.length > MAX_PLATFORM_INTEGRATION_AUTH_MODE_LENGTH
              || (
                normalizedEndpoint !== null
                && normalizedEndpoint.length > MAX_PLATFORM_INTEGRATION_ENDPOINT_LENGTH
              )
              || (
                normalizedBaseUrl !== null
                && normalizedBaseUrl.length > MAX_PLATFORM_INTEGRATION_BASE_URL_LENGTH
              )
              || (
                normalizedVersionStrategy !== null
                && normalizedVersionStrategy.length
                  > MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH
              )
              || (
                normalizedRunbookUrl !== null
                && normalizedRunbookUrl.length > MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH
              )
              || (
                normalizedLifecycleReason !== null
                && normalizedLifecycleReason.length
                  > MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH
              )
              || !Number.isInteger(normalizedTimeoutMs)
              || normalizedTimeoutMs < 1
              || normalizedTimeoutMs > MAX_PLATFORM_INTEGRATION_TIMEOUT_MS
              || !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedLifecycleStatus)
              || normalizedRetryPolicy === undefined
              || normalizedIdempotencyPolicy === undefined
            ) {
              throw new Error('createPlatformIntegrationCatalogEntry received invalid input');
            }
            await assertPlatformIntegrationWriteAllowedByFreezeGate(tx);
            try {
              await tx.query(
                `
                  INSERT INTO platform_integration_catalog (
                    integration_id,
                    code,
                    code_normalized,
                    name,
                    direction,
                    protocol,
                    auth_mode,
                    endpoint,
                    base_url,
                    timeout_ms,
                    retry_policy,
                    idempotency_policy,
                    version_strategy,
                    runbook_url,
                    lifecycle_status,
                    lifecycle_reason,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), CAST(? AS JSON), ?, ?, ?, ?, ?, ?)
                `,
                [
                  normalizedIntegrationId,
                  normalizedCode,
                  normalizedCodeKey,
                  normalizedName,
                  normalizedDirection,
                  normalizedProtocol,
                  normalizedAuthMode,
                  normalizedEndpoint,
                  normalizedBaseUrl,
                  normalizedTimeoutMs,
                  normalizedRetryPolicy,
                  normalizedIdempotencyPolicy,
                  normalizedVersionStrategy,
                  normalizedRunbookUrl,
                  normalizedLifecycleStatus,
                  normalizedLifecycleReason,
                  normalizePlatformIntegrationOptionalText(operatorUserId),
                  normalizePlatformIntegrationOptionalText(operatorUserId)
                ]
              );
            } catch (error) {
              if (isDuplicateEntryError(error)) {
                const duplicateError = new Error(
                  'duplicate platform integration catalog entry'
                );
                duplicateError.code = 'ER_DUP_ENTRY';
                duplicateError.errno = MYSQL_DUP_ENTRY_ERRNO;
                const duplicateMessage = String(
                  error?.sqlMessage || error?.message || ''
                ).toLowerCase();
                duplicateError.platformIntegrationCatalogConflictTarget =
                  duplicateMessage.includes('code_normalized')
                    ? 'code'
                    : 'integration_id';
                throw duplicateError;
              }
              throw error;
            }
            const rows = await tx.query(
              `
                SELECT integration_id,
                       code,
                       code_normalized,
                       name,
                       direction,
                       protocol,
                       auth_mode,
                       endpoint,
                       base_url,
                       timeout_ms,
                       retry_policy,
                       idempotency_policy,
                       version_strategy,
                       runbook_url,
                       lifecycle_status,
                       lifecycle_reason,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_catalog
                WHERE integration_id = ?
                LIMIT 1
              `,
              [normalizedIntegrationId]
            );
            const createdIntegration = toPlatformIntegrationCatalogRecord(
              rows?.[0] || null
            );
            if (!createdIntegration) {
              throw new Error('createPlatformIntegrationCatalogEntry result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.created',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration',
                  targetId: normalizedIntegrationId,
                  result: 'success',
                  beforeState: null,
                  afterState: {
                    integration_id: normalizedIntegrationId,
                    code: normalizedCode,
                    direction: normalizedDirection,
                    protocol: normalizedProtocol,
                    auth_mode: normalizedAuthMode,
                    lifecycle_status: normalizedLifecycleStatus
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration create audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...createdIntegration,
              auditRecorded
            };
          })
      }),

    updatePlatformIntegrationCatalogEntry: async ({
      integrationId,
      code = undefined,
      name = undefined,
      direction = undefined,
      protocol = undefined,
      authMode = undefined,
      endpoint = undefined,
      baseUrl = undefined,
      timeoutMs = undefined,
      retryPolicy = undefined,
      idempotencyPolicy = undefined,
      versionStrategy = undefined,
      runbookUrl = undefined,
      lifecycleReason = undefined,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'updatePlatformIntegrationCatalogEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
              throw new Error('updatePlatformIntegrationCatalogEntry requires integrationId');
            }
            const hasUpdates = [
              code,
              name,
              direction,
              protocol,
              authMode,
              endpoint,
              baseUrl,
              timeoutMs,
              retryPolicy,
              idempotencyPolicy,
              versionStrategy,
              runbookUrl,
              lifecycleReason
            ].some((value) => value !== undefined);
            if (!hasUpdates) {
              throw new Error('updatePlatformIntegrationCatalogEntry requires update fields');
            }
            await assertPlatformIntegrationWriteAllowedByFreezeGate(tx);
            const rows = await tx.query(
              `
                SELECT integration_id,
                       code,
                       code_normalized,
                       name,
                       direction,
                       protocol,
                       auth_mode,
                       endpoint,
                       base_url,
                       timeout_ms,
                       retry_policy,
                       idempotency_policy,
                       version_strategy,
                       runbook_url,
                       lifecycle_status,
                       lifecycle_reason,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_catalog
                WHERE integration_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedIntegrationId]
            );
            if (!Array.isArray(rows)) {
              throw new Error('updatePlatformIntegrationCatalogEntry existing query malformed');
            }
            if (rows.length === 0) {
              return null;
            }
            const existing = toPlatformIntegrationCatalogRecord(rows[0]);
            if (!existing) {
              throw new Error('updatePlatformIntegrationCatalogEntry existing row malformed');
            }
            const nextCode = code === undefined
              ? existing.code
              : normalizePlatformIntegrationCode(code);
            const nextName = name === undefined
              ? existing.name
              : String(name || '').trim();
            const nextDirection = direction === undefined
              ? existing.direction
              : normalizePlatformIntegrationDirection(direction);
            const nextProtocol = protocol === undefined
              ? existing.protocol
              : String(protocol || '').trim();
            const nextAuthMode = authMode === undefined
              ? existing.authMode
              : String(authMode || '').trim();
            const nextEndpoint = endpoint === undefined
              ? existing.endpoint
              : normalizePlatformIntegrationOptionalText(endpoint);
            const nextBaseUrl = baseUrl === undefined
              ? existing.baseUrl
              : normalizePlatformIntegrationOptionalText(baseUrl);
            const nextTimeoutMs = timeoutMs === undefined
              ? existing.timeoutMs
              : normalizePlatformIntegrationTimeoutMs(timeoutMs);
            const nextRetryPolicy = retryPolicy === undefined
              ? normalizePlatformIntegrationJsonForStorage({
                value: existing.retryPolicy
              })
              : normalizePlatformIntegrationJsonForStorage({
                value: retryPolicy
              });
            const nextIdempotencyPolicy = idempotencyPolicy === undefined
              ? normalizePlatformIntegrationJsonForStorage({
                value: existing.idempotencyPolicy
              })
              : normalizePlatformIntegrationJsonForStorage({
                value: idempotencyPolicy
              });
            const nextVersionStrategy = versionStrategy === undefined
              ? existing.versionStrategy
              : normalizePlatformIntegrationOptionalText(versionStrategy);
            const nextRunbookUrl = runbookUrl === undefined
              ? existing.runbookUrl
              : normalizePlatformIntegrationOptionalText(runbookUrl);
            const nextLifecycleReason = lifecycleReason === undefined
              ? existing.lifecycleReason
              : normalizePlatformIntegrationOptionalText(lifecycleReason);
            if (
              !nextCode
              || nextCode.length > MAX_PLATFORM_INTEGRATION_CODE_LENGTH
              || !nextName
              || nextName.length > MAX_PLATFORM_INTEGRATION_NAME_LENGTH
              || !VALID_PLATFORM_INTEGRATION_DIRECTION.has(nextDirection)
              || !nextProtocol
              || nextProtocol.length > MAX_PLATFORM_INTEGRATION_PROTOCOL_LENGTH
              || !nextAuthMode
              || nextAuthMode.length > MAX_PLATFORM_INTEGRATION_AUTH_MODE_LENGTH
              || (
                nextEndpoint !== null
                && nextEndpoint.length > MAX_PLATFORM_INTEGRATION_ENDPOINT_LENGTH
              )
              || (
                nextBaseUrl !== null
                && nextBaseUrl.length > MAX_PLATFORM_INTEGRATION_BASE_URL_LENGTH
              )
              || (
                nextVersionStrategy !== null
                && nextVersionStrategy.length
                  > MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH
              )
              || (
                nextRunbookUrl !== null
                && nextRunbookUrl.length > MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH
              )
              || (
                nextLifecycleReason !== null
                && nextLifecycleReason.length > MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH
              )
              || !Number.isInteger(nextTimeoutMs)
              || nextTimeoutMs < 1
              || nextTimeoutMs > MAX_PLATFORM_INTEGRATION_TIMEOUT_MS
              || nextRetryPolicy === undefined
              || nextIdempotencyPolicy === undefined
            ) {
              throw new Error('updatePlatformIntegrationCatalogEntry received invalid payload');
            }
            try {
              await tx.query(
                `
                  UPDATE platform_integration_catalog
                  SET code = ?,
                      code_normalized = ?,
                      name = ?,
                      direction = ?,
                      protocol = ?,
                      auth_mode = ?,
                      endpoint = ?,
                      base_url = ?,
                      timeout_ms = ?,
                      retry_policy = CAST(? AS JSON),
                      idempotency_policy = CAST(? AS JSON),
                      version_strategy = ?,
                      runbook_url = ?,
                      lifecycle_reason = ?,
                      updated_by_user_id = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE integration_id = ?
                `,
                [
                  nextCode,
                  normalizePlatformIntegrationCodeKey(nextCode),
                  nextName,
                  nextDirection,
                  nextProtocol,
                  nextAuthMode,
                  nextEndpoint,
                  nextBaseUrl,
                  nextTimeoutMs,
                  nextRetryPolicy,
                  nextIdempotencyPolicy,
                  nextVersionStrategy,
                  nextRunbookUrl,
                  nextLifecycleReason,
                  normalizePlatformIntegrationOptionalText(operatorUserId)
                    || existing.updatedByUserId,
                  normalizedIntegrationId
                ]
              );
            } catch (error) {
              if (isDuplicateEntryError(error)) {
                const duplicateError = new Error(
                  'duplicate platform integration catalog code'
                );
                duplicateError.code = 'ER_DUP_ENTRY';
                duplicateError.errno = MYSQL_DUP_ENTRY_ERRNO;
                duplicateError.platformIntegrationCatalogConflictTarget = 'code';
                throw duplicateError;
              }
              throw error;
            }
            const updatedRows = await tx.query(
              `
                SELECT integration_id,
                       code,
                       code_normalized,
                       name,
                       direction,
                       protocol,
                       auth_mode,
                       endpoint,
                       base_url,
                       timeout_ms,
                       retry_policy,
                       idempotency_policy,
                       version_strategy,
                       runbook_url,
                       lifecycle_status,
                       lifecycle_reason,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_catalog
                WHERE integration_id = ?
                LIMIT 1
              `,
              [normalizedIntegrationId]
            );
            const updated = toPlatformIntegrationCatalogRecord(updatedRows?.[0] || null);
            if (!updated) {
              throw new Error('updatePlatformIntegrationCatalogEntry result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.updated',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration',
                  targetId: normalizedIntegrationId,
                  result: 'success',
                  beforeState: {
                    code: existing.code,
                    direction: existing.direction,
                    protocol: existing.protocol,
                    auth_mode: existing.authMode
                  },
                  afterState: {
                    code: updated.code,
                    direction: updated.direction,
                    protocol: updated.protocol,
                    auth_mode: updated.authMode
                  },
                  metadata: {
                    changed_fields: [
                      ...new Set(Object.keys({
                        ...(code === undefined ? {} : { code: true }),
                        ...(name === undefined ? {} : { name: true }),
                        ...(direction === undefined ? {} : { direction: true }),
                        ...(protocol === undefined ? {} : { protocol: true }),
                        ...(authMode === undefined ? {} : { auth_mode: true }),
                        ...(endpoint === undefined ? {} : { endpoint: true }),
                        ...(baseUrl === undefined ? {} : { base_url: true }),
                        ...(timeoutMs === undefined ? {} : { timeout_ms: true }),
                        ...(retryPolicy === undefined ? {} : { retry_policy: true }),
                        ...(idempotencyPolicy === undefined ? {} : { idempotency_policy: true }),
                        ...(versionStrategy === undefined ? {} : { version_strategy: true }),
                        ...(runbookUrl === undefined ? {} : { runbook_url: true }),
                        ...(lifecycleReason === undefined ? {} : { lifecycle_reason: true })
                      }))
                    ]
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration update audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...updated,
              auditRecorded
            };
          })
      }),

    transitionPlatformIntegrationLifecycle: async ({
      integrationId,
      nextStatus,
      reason = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'transitionPlatformIntegrationLifecycle',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedNextStatus = normalizePlatformIntegrationLifecycleStatus(
              nextStatus
            );
            const normalizedReason = normalizePlatformIntegrationOptionalText(reason);
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedNextStatus)
              || (
                normalizedReason !== null
                && normalizedReason.length > MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH
              )
            ) {
              throw new Error('transitionPlatformIntegrationLifecycle received invalid input');
            }
            await assertPlatformIntegrationWriteAllowedByFreezeGate(tx);
            const rows = await tx.query(
              `
                SELECT integration_id,
                       code,
                       code_normalized,
                       name,
                       direction,
                       protocol,
                       auth_mode,
                       endpoint,
                       base_url,
                       timeout_ms,
                       retry_policy,
                       idempotency_policy,
                       version_strategy,
                       runbook_url,
                       lifecycle_status,
                       lifecycle_reason,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_catalog
                WHERE integration_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedIntegrationId]
            );
            if (!Array.isArray(rows)) {
              throw new Error('transitionPlatformIntegrationLifecycle existing query malformed');
            }
            if (rows.length === 0) {
              return null;
            }
            const existing = toPlatformIntegrationCatalogRecord(rows[0]);
            if (!existing) {
              throw new Error('transitionPlatformIntegrationLifecycle existing row malformed');
            }
            if (
              !isPlatformIntegrationLifecycleTransitionAllowed({
                previousStatus: existing.lifecycleStatus,
                nextStatus: normalizedNextStatus
              })
            ) {
              throw createPlatformIntegrationLifecycleConflictError({
                integrationId: normalizedIntegrationId,
                previousStatus: existing.lifecycleStatus,
                requestedStatus: normalizedNextStatus
              });
            }
            await tx.query(
              `
                UPDATE platform_integration_catalog
                SET lifecycle_status = ?,
                    lifecycle_reason = ?,
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE integration_id = ?
              `,
              [
                normalizedNextStatus,
                normalizedReason,
                normalizePlatformIntegrationOptionalText(operatorUserId)
                  || existing.updatedByUserId,
                normalizedIntegrationId
              ]
            );
            const updatedRows = await tx.query(
              `
                SELECT integration_id,
                       code,
                       code_normalized,
                       name,
                       direction,
                       protocol,
                       auth_mode,
                       endpoint,
                       base_url,
                       timeout_ms,
                       retry_policy,
                       idempotency_policy,
                       version_strategy,
                       runbook_url,
                       lifecycle_status,
                       lifecycle_reason,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_catalog
                WHERE integration_id = ?
                LIMIT 1
              `,
              [normalizedIntegrationId]
            );
            const updated = toPlatformIntegrationCatalogRecord(updatedRows?.[0] || null);
            if (!updated) {
              throw new Error('transitionPlatformIntegrationLifecycle result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.lifecycle_changed',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration',
                  targetId: normalizedIntegrationId,
                  result: 'success',
                  beforeState: {
                    lifecycle_status: existing.lifecycleStatus
                  },
                  afterState: {
                    lifecycle_status: updated.lifecycleStatus
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration lifecycle audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...updated,
              previousStatus: existing.lifecycleStatus,
              currentStatus: updated.lifecycleStatus,
              effectiveInvocationEnabled: updated.lifecycleStatus === 'active',
              auditRecorded
            };
          })
      }),

    findActivePlatformIntegrationFreeze: async () => {
      const rows = await dbClient.query(
        `
          SELECT freeze_id,
                 status,
                 freeze_reason,
                 rollback_reason,
                 frozen_at,
                 released_at,
                 frozen_by_user_id,
                 released_by_user_id,
                 request_id,
                 traceparent,
                 created_at,
                 updated_at
          FROM platform_integration_freeze_control
          WHERE status = 'active'
          ORDER BY frozen_at DESC, freeze_id DESC
          LIMIT 1
        `
      );
      if (!Array.isArray(rows)) {
        throw new Error('findActivePlatformIntegrationFreeze result malformed');
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRow = toPlatformIntegrationFreezeRecord(rows[0]);
      if (!normalizedRow) {
        throw new Error('findActivePlatformIntegrationFreeze result malformed');
      }
      return normalizedRow;
    },

    findLatestPlatformIntegrationFreeze: async () => {
      const rows = await dbClient.query(
        `
          SELECT freeze_id,
                 status,
                 freeze_reason,
                 rollback_reason,
                 frozen_at,
                 released_at,
                 frozen_by_user_id,
                 released_by_user_id,
                 request_id,
                 traceparent,
                 created_at,
                 updated_at
          FROM platform_integration_freeze_control
          ORDER BY frozen_at DESC, updated_at DESC, freeze_id DESC
          LIMIT 1
        `
      );
      if (!Array.isArray(rows)) {
        throw new Error('findLatestPlatformIntegrationFreeze result malformed');
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRow = toPlatformIntegrationFreezeRecord(rows[0]);
      if (!normalizedRow) {
        throw new Error('findLatestPlatformIntegrationFreeze result malformed');
      }
      return normalizedRow;
    },

    activatePlatformIntegrationFreeze: async ({
      freezeId = randomUUID(),
      freezeReason,
      operatorUserId = null,
      operatorSessionId = null,
      requestId,
      traceparent = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'activatePlatformIntegrationFreeze',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const freezeIdProvided = freezeId !== undefined && freezeId !== null;
            const normalizedRequestedFreezeId =
              normalizePlatformIntegrationFreezeId(freezeId);
            if (
              freezeIdProvided
              && (
                !normalizedRequestedFreezeId
                || normalizedRequestedFreezeId.length > MAX_PLATFORM_INTEGRATION_FREEZE_ID_LENGTH
              )
            ) {
              throw new Error('activatePlatformIntegrationFreeze received invalid freezeId');
            }
            const normalizedFreezeId =
              normalizedRequestedFreezeId && normalizedRequestedFreezeId.length > 0
                ? normalizedRequestedFreezeId
                : randomUUID();
            const normalizedFreezeReason =
              normalizePlatformIntegrationOptionalText(freezeReason);
            const normalizedRequestId = String(requestId || '').trim();
            const normalizedTraceparent =
              normalizePlatformIntegrationOptionalText(traceparent);
            if (
              !normalizedFreezeReason
              || normalizedFreezeReason.length > MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH
              || !normalizedRequestId
              || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH
              || (
                normalizedTraceparent !== null
                && normalizedTraceparent.length > MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH
              )
            ) {
              throw new Error('activatePlatformIntegrationFreeze received invalid input');
            }
            const activeRows = await tx.query(
              `
                SELECT freeze_id,
                       status,
                       freeze_reason,
                       rollback_reason,
                       frozen_at,
                       released_at,
                       frozen_by_user_id,
                       released_by_user_id,
                       request_id,
                       traceparent,
                       created_at,
                       updated_at
                FROM platform_integration_freeze_control
                WHERE status = 'active'
                ORDER BY frozen_at DESC, freeze_id DESC
                LIMIT 1
                FOR UPDATE
              `
            );
            if (!Array.isArray(activeRows)) {
              throw new Error('activatePlatformIntegrationFreeze active query malformed');
            }
            if (activeRows.length > 0) {
              const activeFreeze = toPlatformIntegrationFreezeRecord(activeRows[0]);
              if (!activeFreeze) {
                throw new Error('activatePlatformIntegrationFreeze active row malformed');
              }
              throw createPlatformIntegrationFreezeActiveConflictError({
                freezeId: activeFreeze.freezeId,
                frozenAt: activeFreeze.frozenAt
              });
            }
            try {
              await tx.query(
                `
                  INSERT INTO platform_integration_freeze_control (
                    freeze_id,
                    status,
                    freeze_reason,
                    rollback_reason,
                    frozen_by_user_id,
                    released_by_user_id,
                    request_id,
                    traceparent
                  )
                  VALUES (?, 'active', ?, NULL, ?, NULL, ?, ?)
                `,
                [
                  normalizedFreezeId,
                  normalizedFreezeReason,
                  normalizePlatformIntegrationOptionalText(operatorUserId),
                  normalizedRequestId,
                  normalizedTraceparent
                ]
              );
            } catch (error) {
              if (isDuplicateEntryError(error)) {
                const conflictRows = await tx.query(
                  `
                    SELECT freeze_id,
                           status,
                           freeze_reason,
                           rollback_reason,
                           frozen_at,
                           released_at,
                           frozen_by_user_id,
                           released_by_user_id,
                           request_id,
                           traceparent,
                           created_at,
                           updated_at
                    FROM platform_integration_freeze_control
                    WHERE status = 'active'
                    ORDER BY frozen_at DESC, freeze_id DESC
                    LIMIT 1
                  `
                );
                const activeFreeze = Array.isArray(conflictRows)
                  ? toPlatformIntegrationFreezeRecord(conflictRows[0] || null)
                  : null;
                throw createPlatformIntegrationFreezeActiveConflictError({
                  freezeId: activeFreeze?.freezeId || null,
                  frozenAt: activeFreeze?.frozenAt || null
                });
              }
              throw error;
            }
            const createdRows = await tx.query(
              `
                SELECT freeze_id,
                       status,
                       freeze_reason,
                       rollback_reason,
                       frozen_at,
                       released_at,
                       frozen_by_user_id,
                       released_by_user_id,
                       request_id,
                       traceparent,
                       created_at,
                       updated_at
                FROM platform_integration_freeze_control
                WHERE freeze_id = ?
                LIMIT 1
              `,
              [normalizedFreezeId]
            );
            const createdRecord = toPlatformIntegrationFreezeRecord(
              createdRows?.[0] || null
            );
            if (!createdRecord) {
              throw new Error('activatePlatformIntegrationFreeze result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || normalizedRequestId).trim()
                    || 'request_id_unset',
                  traceparent: auditContext.traceparent ?? normalizedTraceparent,
                  eventType: 'platform.integration.freeze.activated',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_freeze',
                  targetId: normalizedFreezeId,
                  result: 'success',
                  beforeState: null,
                  afterState: {
                    freeze_id: createdRecord.freezeId,
                    status: createdRecord.status,
                    freeze_reason: createdRecord.freezeReason,
                    frozen_at: createdRecord.frozenAt
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration freeze activate audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...createdRecord,
              auditRecorded
            };
          })
      }),

    releasePlatformIntegrationFreeze: async ({
      rollbackReason = null,
      operatorUserId = null,
      operatorSessionId = null,
      requestId = 'request_id_unset',
      traceparent = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'releasePlatformIntegrationFreeze',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedRollbackReason =
              normalizePlatformIntegrationOptionalText(rollbackReason);
            const normalizedRequestId = String(requestId || '').trim();
            const normalizedTraceparent =
              normalizePlatformIntegrationOptionalText(traceparent);
            if (
              (
                normalizedRollbackReason !== null
                && normalizedRollbackReason.length > MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH
              )
              || !normalizedRequestId
              || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH
              || (
                normalizedTraceparent !== null
                && normalizedTraceparent.length > MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH
              )
            ) {
              throw new Error('releasePlatformIntegrationFreeze received invalid input');
            }
            const activeRows = await tx.query(
              `
                SELECT freeze_id,
                       status,
                       freeze_reason,
                       rollback_reason,
                       frozen_at,
                       released_at,
                       frozen_by_user_id,
                       released_by_user_id,
                       request_id,
                       traceparent,
                       created_at,
                       updated_at
                FROM platform_integration_freeze_control
                WHERE status = 'active'
                ORDER BY frozen_at DESC, freeze_id DESC
                LIMIT 1
                FOR UPDATE
              `
            );
            if (!Array.isArray(activeRows)) {
              throw new Error('releasePlatformIntegrationFreeze active query malformed');
            }
            if (activeRows.length === 0) {
              throw createPlatformIntegrationFreezeReleaseConflictError();
            }
            const activeRecord = toPlatformIntegrationFreezeRecord(activeRows[0]);
            if (!activeRecord) {
              throw new Error('releasePlatformIntegrationFreeze active row malformed');
            }
            const updateResult = await tx.query(
              `
                UPDATE platform_integration_freeze_control
                SET status = 'released',
                    rollback_reason = ?,
                    released_at = CURRENT_TIMESTAMP(3),
                    released_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE freeze_id = ?
                  AND status = 'active'
              `,
              [
                normalizedRollbackReason,
                normalizePlatformIntegrationOptionalText(operatorUserId),
                activeRecord.freezeId
              ]
            );
            if (
              updateResult
              && Object.prototype.hasOwnProperty.call(updateResult, 'affectedRows')
              && Number(updateResult.affectedRows || 0) < 1
            ) {
              throw createPlatformIntegrationFreezeReleaseConflictError();
            }
            const updatedRows = await tx.query(
              `
                SELECT freeze_id,
                       status,
                       freeze_reason,
                       rollback_reason,
                       frozen_at,
                       released_at,
                       frozen_by_user_id,
                       released_by_user_id,
                       request_id,
                       traceparent,
                       created_at,
                       updated_at
                FROM platform_integration_freeze_control
                WHERE freeze_id = ?
                LIMIT 1
              `,
              [activeRecord.freezeId]
            );
            const releasedRecord = toPlatformIntegrationFreezeRecord(
              updatedRows?.[0] || null
            );
            if (!releasedRecord) {
              throw new Error('releasePlatformIntegrationFreeze result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || normalizedRequestId).trim()
                    || 'request_id_unset',
                  traceparent: auditContext.traceparent ?? normalizedTraceparent,
                  eventType: 'platform.integration.freeze.released',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_freeze',
                  targetId: activeRecord.freezeId,
                  result: 'success',
                  beforeState: {
                    status: activeRecord.status,
                    freeze_reason: activeRecord.freezeReason,
                    frozen_at: activeRecord.frozenAt
                  },
                  afterState: {
                    status: releasedRecord.status,
                    rollback_reason: releasedRecord.rollbackReason,
                    released_at: releasedRecord.releasedAt
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration freeze release audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...releasedRecord,
              previousStatus: activeRecord.status,
              currentStatus: releasedRecord.status,
              released: true,
              auditRecorded
            };
          })
      }),

    listPlatformIntegrationContractVersions: async ({
      integrationId,
      contractType = null,
      status = null
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
        return [];
      }
      const normalizedContractType = contractType === null || contractType === undefined
        ? null
        : normalizePlatformIntegrationContractType(contractType);
      if (
        normalizedContractType !== null
        && !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
      ) {
        throw new Error('listPlatformIntegrationContractVersions received invalid contractType');
      }
      const normalizedStatus = status === null || status === undefined
        ? null
        : normalizePlatformIntegrationContractStatus(status);
      if (
        normalizedStatus !== null
        && !VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS.has(normalizedStatus)
      ) {
        throw new Error('listPlatformIntegrationContractVersions received invalid status');
      }
      const whereClauses = ['integration_id = ?'];
      const queryArgs = [normalizedIntegrationId];
      if (normalizedContractType !== null) {
        whereClauses.push('contract_type = ?');
        queryArgs.push(normalizedContractType);
      }
      if (normalizedStatus !== null) {
        whereClauses.push('status = ?');
        queryArgs.push(normalizedStatus);
      }
      const rows = await dbClient.query(
        `
          SELECT contract_id,
                 integration_id,
                 contract_type,
                 contract_version,
                 schema_ref,
                 schema_checksum,
                 status,
                 is_backward_compatible,
                 compatibility_notes,
                 created_by_user_id,
                 updated_by_user_id,
                 created_at,
                 updated_at
          FROM platform_integration_contract_versions
          WHERE ${whereClauses.join(' AND ')}
          ORDER BY created_at ASC, contract_id ASC
        `,
        queryArgs
      );
      if (!Array.isArray(rows)) {
        throw new Error('listPlatformIntegrationContractVersions result malformed');
      }
      const normalizedRows = rows.map((row) =>
        toPlatformIntegrationContractVersionRecord(row)
      );
      if (normalizedRows.some((row) => !row)) {
        throw new Error('listPlatformIntegrationContractVersions result malformed');
      }
      return normalizedRows;
    },

    findPlatformIntegrationContractVersion: async ({
      integrationId,
      contractType,
      contractVersion
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      const normalizedContractType = normalizePlatformIntegrationContractType(contractType);
      const normalizedContractVersion =
        normalizePlatformIntegrationContractVersion(contractVersion);
      if (
        !isValidPlatformIntegrationId(normalizedIntegrationId)
        || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
        || !normalizedContractVersion
        || normalizedContractVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      ) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT contract_id,
                 integration_id,
                 contract_type,
                 contract_version,
                 schema_ref,
                 schema_checksum,
                 status,
                 is_backward_compatible,
                 compatibility_notes,
                 created_by_user_id,
                 updated_by_user_id,
                 created_at,
                 updated_at
          FROM platform_integration_contract_versions
          WHERE integration_id = ?
            AND contract_type = ?
            AND contract_version = ?
          LIMIT 1
        `,
        [
          normalizedIntegrationId,
          normalizedContractType,
          normalizedContractVersion
        ]
      );
      if (!Array.isArray(rows)) {
        throw new Error('findPlatformIntegrationContractVersion result malformed');
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRow = toPlatformIntegrationContractVersionRecord(rows[0]);
      if (!normalizedRow) {
        throw new Error('findPlatformIntegrationContractVersion result malformed');
      }
      return normalizedRow;
    },

    findLatestActivePlatformIntegrationContractVersion: async ({
      integrationId,
      contractType
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      const normalizedContractType = normalizePlatformIntegrationContractType(contractType);
      if (
        !isValidPlatformIntegrationId(normalizedIntegrationId)
        || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
      ) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT contract_id,
                 integration_id,
                 contract_type,
                 contract_version,
                 schema_ref,
                 schema_checksum,
                 status,
                 is_backward_compatible,
                 compatibility_notes,
                 created_by_user_id,
                 updated_by_user_id,
                 created_at,
                 updated_at
          FROM platform_integration_contract_versions
          WHERE integration_id = ?
            AND contract_type = ?
            AND status = 'active'
          ORDER BY updated_at DESC, contract_id DESC
          LIMIT 1
        `,
        [
          normalizedIntegrationId,
          normalizedContractType
        ]
      );
      if (!Array.isArray(rows)) {
        throw new Error('findLatestActivePlatformIntegrationContractVersion result malformed');
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRow = toPlatformIntegrationContractVersionRecord(rows[0]);
      if (!normalizedRow) {
        throw new Error('findLatestActivePlatformIntegrationContractVersion result malformed');
      }
      return normalizedRow;
    },

    createPlatformIntegrationContractVersion: async ({
      integrationId,
      contractType,
      contractVersion,
      schemaRef,
      schemaChecksum,
      status = 'candidate',
      isBackwardCompatible = false,
      compatibilityNotes = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'createPlatformIntegrationContractVersion',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedContractType =
              normalizePlatformIntegrationContractType(contractType);
            const normalizedContractVersion =
              normalizePlatformIntegrationContractVersion(contractVersion);
            const normalizedSchemaRef = normalizePlatformIntegrationOptionalText(schemaRef);
            const normalizedSchemaChecksum =
              normalizePlatformIntegrationContractSchemaChecksum(schemaChecksum);
            const normalizedStatus = normalizePlatformIntegrationContractStatus(status);
            const normalizedCompatibilityNotes =
              normalizePlatformIntegrationOptionalText(compatibilityNotes);
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
              || !normalizedContractVersion
              || normalizedContractVersion.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
              || !normalizedSchemaRef
              || normalizedSchemaRef.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_REF_LENGTH
              || !normalizedSchemaChecksum
              || normalizedSchemaChecksum.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_CHECKSUM_LENGTH
              || !PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN.test(normalizedSchemaChecksum)
              || !VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS.has(normalizedStatus)
              || typeof isBackwardCompatible !== 'boolean'
              || (
                normalizedCompatibilityNotes !== null
                && normalizedCompatibilityNotes.length
                  > MAX_PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_NOTES_LENGTH
              )
            ) {
              throw new Error('createPlatformIntegrationContractVersion received invalid input');
            }
            await assertPlatformIntegrationWriteAllowedByFreezeGate(tx);
            try {
              await tx.query(
                `
                  INSERT INTO platform_integration_contract_versions (
                    integration_id,
                    contract_type,
                    contract_version,
                    schema_ref,
                    schema_checksum,
                    status,
                    is_backward_compatible,
                    compatibility_notes,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `,
                [
                  normalizedIntegrationId,
                  normalizedContractType,
                  normalizedContractVersion,
                  normalizedSchemaRef,
                  normalizedSchemaChecksum,
                  normalizedStatus,
                  isBackwardCompatible ? 1 : 0,
                  normalizedCompatibilityNotes,
                  normalizePlatformIntegrationOptionalText(operatorUserId),
                  normalizePlatformIntegrationOptionalText(operatorUserId)
                ]
              );
            } catch (error) {
              if (isDuplicateEntryError(error)) {
                const duplicateError = new Error(
                  'duplicate platform integration contract version'
                );
                duplicateError.code = 'ER_DUP_ENTRY';
                duplicateError.errno = MYSQL_DUP_ENTRY_ERRNO;
                duplicateError.platformIntegrationContractConflictTarget = 'contract_version';
                throw duplicateError;
              }
              throw error;
            }
            const rows = await tx.query(
              `
                SELECT contract_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       schema_ref,
                       schema_checksum,
                       status,
                       is_backward_compatible,
                       compatibility_notes,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_contract_versions
                WHERE integration_id = ?
                  AND contract_type = ?
                  AND contract_version = ?
                LIMIT 1
              `,
              [
                normalizedIntegrationId,
                normalizedContractType,
                normalizedContractVersion
              ]
            );
            const createdRecord = toPlatformIntegrationContractVersionRecord(
              rows?.[0] || null
            );
            if (!createdRecord) {
              throw new Error('createPlatformIntegrationContractVersion result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.contract.created',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_contract',
                  targetId: `${normalizedIntegrationId}:${normalizedContractType}:${normalizedContractVersion}`,
                  result: 'success',
                  beforeState: null,
                  afterState: {
                    integration_id: normalizedIntegrationId,
                    contract_type: normalizedContractType,
                    contract_version: normalizedContractVersion,
                    status: normalizedStatus,
                    is_backward_compatible: isBackwardCompatible
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration contract create audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...createdRecord,
              auditRecorded
            };
          })
      }),

    createPlatformIntegrationContractCompatibilityCheck: async ({
      integrationId,
      contractType,
      baselineVersion,
      candidateVersion,
      evaluationResult,
      breakingChangeCount = 0,
      diffSummary = null,
      requestId,
      checkedByUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'createPlatformIntegrationContractCompatibilityCheck',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedContractType =
              normalizePlatformIntegrationContractType(contractType);
            const normalizedBaselineVersion =
              normalizePlatformIntegrationContractVersion(baselineVersion);
            const normalizedCandidateVersion =
              normalizePlatformIntegrationContractVersion(candidateVersion);
            const normalizedEvaluationResult =
              normalizePlatformIntegrationContractEvaluationResult(evaluationResult);
            const normalizedRequestId = String(requestId || '').trim();
            const normalizedBreakingChangeCount = Number(breakingChangeCount);
            const normalizedDiffSummary = normalizePlatformIntegrationJsonForStorage({
              value: diffSummary
            });
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
              || !normalizedBaselineVersion
              || normalizedBaselineVersion.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
              || !normalizedCandidateVersion
              || normalizedCandidateVersion.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
              || !VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT.has(
                normalizedEvaluationResult
              )
              || !Number.isInteger(normalizedBreakingChangeCount)
              || normalizedBreakingChangeCount < 0
              || !normalizedRequestId
              || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
              || normalizedDiffSummary === undefined
              || (
                normalizedDiffSummary !== null
                && normalizedDiffSummary.length > MAX_PLATFORM_INTEGRATION_CONTRACT_DIFF_SUMMARY_LENGTH
              )
            ) {
              throw new Error(
                'createPlatformIntegrationContractCompatibilityCheck received invalid input'
              );
            }
            const insertResult = await tx.query(
              `
                INSERT INTO platform_integration_contract_compatibility_checks (
                  integration_id,
                  contract_type,
                  baseline_version,
                  candidate_version,
                  evaluation_result,
                  breaking_change_count,
                  diff_summary,
                  request_id,
                  checked_by_user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, CAST(? AS JSON), ?, ?)
              `,
              [
                normalizedIntegrationId,
                normalizedContractType,
                normalizedBaselineVersion,
                normalizedCandidateVersion,
                normalizedEvaluationResult,
                normalizedBreakingChangeCount,
                normalizedDiffSummary,
                normalizedRequestId,
                normalizePlatformIntegrationOptionalText(checkedByUserId)
              ]
            );
            const insertedCheckId = Number(insertResult?.insertId || 0);
            if (!Number.isInteger(insertedCheckId) || insertedCheckId < 1) {
              throw new Error(
                'createPlatformIntegrationContractCompatibilityCheck insert result malformed'
              );
            }
            const rows = await tx.query(
              `
                SELECT check_id,
                       integration_id,
                       contract_type,
                       baseline_version,
                       candidate_version,
                       evaluation_result,
                       breaking_change_count,
                       diff_summary,
                       request_id,
                       checked_by_user_id,
                       checked_at
                FROM platform_integration_contract_compatibility_checks
                WHERE check_id = ?
                LIMIT 1
              `,
              [insertedCheckId]
            );
            const createdRecord = toPlatformIntegrationContractCompatibilityCheckRecord(
              rows?.[0] || null
            );
            if (!createdRecord) {
              throw new Error(
                'createPlatformIntegrationContractCompatibilityCheck result unavailable'
              );
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || normalizedRequestId).trim()
                    || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.contract.compatibility_evaluated',
                  actorUserId: auditContext.actorUserId || checkedByUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_contract',
                  targetId: `${normalizedIntegrationId}:${normalizedContractType}:${normalizedCandidateVersion}`,
                  result: 'success',
                  beforeState: null,
                  afterState: {
                    integration_id: normalizedIntegrationId,
                    contract_type: normalizedContractType,
                    baseline_version: normalizedBaselineVersion,
                    candidate_version: normalizedCandidateVersion,
                    evaluation_result: normalizedEvaluationResult,
                    breaking_change_count: normalizedBreakingChangeCount
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration contract compatibility audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...createdRecord,
              auditRecorded
            };
          })
      }),

    findLatestPlatformIntegrationContractCompatibilityCheck: async ({
      integrationId,
      contractType,
      baselineVersion,
      candidateVersion
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      const normalizedContractType = normalizePlatformIntegrationContractType(contractType);
      const normalizedBaselineVersion =
        normalizePlatformIntegrationContractVersion(baselineVersion);
      const normalizedCandidateVersion =
        normalizePlatformIntegrationContractVersion(candidateVersion);
      if (
        !isValidPlatformIntegrationId(normalizedIntegrationId)
        || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
        || !normalizedBaselineVersion
        || normalizedBaselineVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
        || !normalizedCandidateVersion
        || normalizedCandidateVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      ) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT check_id,
                 integration_id,
                 contract_type,
                 baseline_version,
                 candidate_version,
                 evaluation_result,
                 breaking_change_count,
                 diff_summary,
                 request_id,
                 checked_by_user_id,
                 checked_at
          FROM platform_integration_contract_compatibility_checks
          WHERE integration_id = ?
            AND contract_type = ?
            AND baseline_version = ?
            AND candidate_version = ?
          ORDER BY checked_at DESC, check_id DESC
          LIMIT 1
        `,
        [
          normalizedIntegrationId,
          normalizedContractType,
          normalizedBaselineVersion,
          normalizedCandidateVersion
        ]
      );
      if (!Array.isArray(rows)) {
        throw new Error(
          'findLatestPlatformIntegrationContractCompatibilityCheck result malformed'
        );
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRow = toPlatformIntegrationContractCompatibilityCheckRecord(
        rows[0]
      );
      if (!normalizedRow) {
        throw new Error(
          'findLatestPlatformIntegrationContractCompatibilityCheck result malformed'
        );
      }
      return normalizedRow;
    },

    activatePlatformIntegrationContractVersion: async ({
      integrationId,
      contractType,
      contractVersion,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'activatePlatformIntegrationContractVersion',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedContractType =
              normalizePlatformIntegrationContractType(contractType);
            const normalizedContractVersion =
              normalizePlatformIntegrationContractVersion(contractVersion);
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
              || !normalizedContractVersion
              || normalizedContractVersion.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
            ) {
              throw new Error('activatePlatformIntegrationContractVersion received invalid input');
            }
            await assertPlatformIntegrationWriteAllowedByFreezeGate(tx);
            const scopeLockRows = await tx.query(
              `
                SELECT contract_id
                FROM platform_integration_contract_versions
                WHERE integration_id = ?
                  AND contract_type = ?
                ORDER BY contract_id ASC
                FOR UPDATE
              `,
              [
                normalizedIntegrationId,
                normalizedContractType
              ]
            );
            if (!Array.isArray(scopeLockRows)) {
              throw new Error(
                'activatePlatformIntegrationContractVersion scope lock malformed'
              );
            }
            const targetRows = await tx.query(
              `
                SELECT contract_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       schema_ref,
                       schema_checksum,
                       status,
                       is_backward_compatible,
                       compatibility_notes,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_contract_versions
                WHERE integration_id = ?
                  AND contract_type = ?
                  AND contract_version = ?
                LIMIT 1
                FOR UPDATE
              `,
              [
                normalizedIntegrationId,
                normalizedContractType,
                normalizedContractVersion
              ]
            );
            if (!Array.isArray(targetRows)) {
              throw new Error(
                'activatePlatformIntegrationContractVersion target query malformed'
              );
            }
            if (targetRows.length === 0) {
              return null;
            }
            const targetRecord = toPlatformIntegrationContractVersionRecord(
              targetRows[0]
            );
            if (!targetRecord) {
              throw new Error(
                'activatePlatformIntegrationContractVersion target row malformed'
              );
            }
            if (targetRecord.status === 'retired') {
              throw createPlatformIntegrationContractActivationBlockedError({
                integrationId: normalizedIntegrationId,
                contractType: normalizedContractType,
                contractVersion: normalizedContractVersion,
                reason: 'retired-version'
              });
            }
            if (targetRecord.status !== 'active') {
              await tx.query(
                `
                  UPDATE platform_integration_contract_versions
                  SET status = 'deprecated',
                      updated_by_user_id = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE integration_id = ?
                    AND contract_type = ?
                    AND status = 'active'
                    AND contract_version <> ?
                `,
                [
                  normalizePlatformIntegrationOptionalText(operatorUserId),
                  normalizedIntegrationId,
                  normalizedContractType,
                  normalizedContractVersion
                ]
              );
              await tx.query(
                `
                  UPDATE platform_integration_contract_versions
                  SET status = 'active',
                      updated_by_user_id = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE integration_id = ?
                    AND contract_type = ?
                    AND contract_version = ?
                `,
                [
                  normalizePlatformIntegrationOptionalText(operatorUserId)
                    || targetRecord.updatedByUserId,
                  normalizedIntegrationId,
                  normalizedContractType,
                  normalizedContractVersion
                ]
              );
            }
            const updatedRows = await tx.query(
              `
                SELECT contract_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       schema_ref,
                       schema_checksum,
                       status,
                       is_backward_compatible,
                       compatibility_notes,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_contract_versions
                WHERE integration_id = ?
                  AND contract_type = ?
                  AND contract_version = ?
                LIMIT 1
              `,
              [
                normalizedIntegrationId,
                normalizedContractType,
                normalizedContractVersion
              ]
            );
            const updatedRecord = toPlatformIntegrationContractVersionRecord(
              updatedRows?.[0] || null
            );
            if (!updatedRecord) {
              throw new Error('activatePlatformIntegrationContractVersion result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.contract.activated',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_contract',
                  targetId: `${normalizedIntegrationId}:${normalizedContractType}:${normalizedContractVersion}`,
                  result: 'success',
                  beforeState: {
                    status: targetRecord.status
                  },
                  afterState: {
                    status: updatedRecord.status
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration contract activation audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...updatedRecord,
              previousStatus: targetRecord.status,
              currentStatus: updatedRecord.status,
              switched: targetRecord.status !== updatedRecord.status,
              auditRecorded
            };
          })
      }),

    listPlatformIntegrationRecoveryQueueEntries: async ({
      integrationId,
      status = null,
      limit = 50
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      const normalizedStatus = status === null || status === undefined
        ? null
        : normalizePlatformIntegrationRecoveryStatus(status);
      const normalizedLimit = Number(limit);
      if (
        !isValidPlatformIntegrationId(normalizedIntegrationId)
        || (
          normalizedStatus !== null
          && !VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS.has(normalizedStatus)
        )
        || !Number.isInteger(normalizedLimit)
        || normalizedLimit < 1
        || normalizedLimit > MAX_PLATFORM_INTEGRATION_RECOVERY_LIST_LIMIT
      ) {
        throw new Error('listPlatformIntegrationRecoveryQueueEntries received invalid input');
      }
      const whereClauses = ['integration_id = ?'];
      const queryArgs = [normalizedIntegrationId];
      if (normalizedStatus !== null) {
        whereClauses.push('status = ?');
        queryArgs.push(normalizedStatus);
      }
      queryArgs.push(normalizedLimit);
      const rows = await dbClient.query(
        `
          SELECT recovery_id,
                 integration_id,
                 contract_type,
                 contract_version,
                 request_id,
                 traceparent,
                 idempotency_key,
                 attempt_count,
                 max_attempts,
                 next_retry_at,
                 last_attempt_at,
                 status,
                 failure_code,
                 failure_detail,
                 last_http_status,
                 retryable,
                 payload_snapshot,
                 response_snapshot,
                 created_by_user_id,
                 updated_by_user_id,
                 created_at,
                 updated_at
          FROM platform_integration_retry_recovery_queue
          WHERE ${whereClauses.join(' AND ')}
          ORDER BY created_at DESC, recovery_id DESC
          LIMIT ?
        `,
        queryArgs
      );
      if (!Array.isArray(rows)) {
        throw new Error('listPlatformIntegrationRecoveryQueueEntries result malformed');
      }
      const normalizedRows = rows.map((row) =>
        toPlatformIntegrationRecoveryQueueRecord(row)
      );
      if (normalizedRows.some((row) => !row)) {
        throw new Error('listPlatformIntegrationRecoveryQueueEntries result malformed');
      }
      return normalizedRows;
    },

    findPlatformIntegrationRecoveryQueueEntryByRecoveryId: async ({
      integrationId,
      recoveryId
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(recoveryId);
      if (
        !isValidPlatformIntegrationId(normalizedIntegrationId)
        || !normalizedRecoveryId
        || normalizedRecoveryId.length > MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH
      ) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT recovery_id,
                 integration_id,
                 contract_type,
                 contract_version,
                 request_id,
                 traceparent,
                 idempotency_key,
                 attempt_count,
                 max_attempts,
                 next_retry_at,
                 last_attempt_at,
                 status,
                 failure_code,
                 failure_detail,
                 last_http_status,
                 retryable,
                 payload_snapshot,
                 response_snapshot,
                 created_by_user_id,
                 updated_by_user_id,
                 created_at,
                 updated_at
          FROM platform_integration_retry_recovery_queue
          WHERE integration_id = ?
            AND recovery_id = ?
          LIMIT 1
        `,
        [
          normalizedIntegrationId,
          normalizedRecoveryId
        ]
      );
      if (!Array.isArray(rows)) {
        throw new Error('findPlatformIntegrationRecoveryQueueEntryByRecoveryId result malformed');
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRecord = toPlatformIntegrationRecoveryQueueRecord(rows[0]);
      if (!normalizedRecord) {
        throw new Error('findPlatformIntegrationRecoveryQueueEntryByRecoveryId result malformed');
      }
      return normalizedRecord;
    },

    upsertPlatformIntegrationRecoveryQueueEntry: async ({
      recoveryId = randomUUID(),
      integrationId,
      contractType,
      contractVersion,
      requestId,
      traceparent = null,
      idempotencyKey = '',
      attemptCount = 0,
      maxAttempts = 5,
      nextRetryAt = null,
      lastAttemptAt = null,
      status = 'pending',
      failureCode = null,
      failureDetail = null,
      lastHttpStatus = null,
      retryable = true,
      payloadSnapshot,
      responseSnapshot = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'upsertPlatformIntegrationRecoveryQueueEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(recoveryId);
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedContractType =
              normalizePlatformIntegrationContractType(contractType);
            const normalizedContractVersion =
              normalizePlatformIntegrationContractVersion(contractVersion);
            const normalizedRequestId = String(requestId || '').trim();
            const normalizedTraceparent =
              normalizePlatformIntegrationOptionalText(traceparent);
            const normalizedIdempotencyKey =
              normalizePlatformIntegrationRecoveryIdempotencyKey(idempotencyKey);
            const normalizedAttemptCount = Number(attemptCount);
            const normalizedMaxAttempts = Number(maxAttempts);
            const normalizedNextRetryAt = nextRetryAt === null || nextRetryAt === undefined
              ? null
              : new Date(nextRetryAt).toISOString();
            const normalizedLastAttemptAt = lastAttemptAt === null || lastAttemptAt === undefined
              ? null
              : new Date(lastAttemptAt).toISOString();
            const normalizedStatus = normalizePlatformIntegrationRecoveryStatus(status);
            const normalizedFailureCode = normalizePlatformIntegrationOptionalText(failureCode);
            const normalizedFailureDetail = normalizePlatformIntegrationOptionalText(
              failureDetail
            );
            const normalizedLastHttpStatus = lastHttpStatus === null || lastHttpStatus === undefined
              ? null
              : Number(lastHttpStatus);
            const normalizedPayloadSnapshot = normalizePlatformIntegrationJsonForStorage({
              value: payloadSnapshot
            });
            const normalizedResponseSnapshot = normalizePlatformIntegrationJsonForStorage({
              value: responseSnapshot
            });
            const normalizedOperatorUserId = normalizePlatformIntegrationOptionalText(
              operatorUserId
            );
            if (
              !normalizedRecoveryId
              || normalizedRecoveryId.length > MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH
              || !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
              || !normalizedContractVersion
              || normalizedContractVersion.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
              || !normalizedRequestId
              || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
              || (
                normalizedTraceparent !== null
                && normalizedTraceparent.length > MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH
              )
              || normalizedIdempotencyKey.length
                > MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH
              || !Number.isInteger(normalizedAttemptCount)
              || normalizedAttemptCount < 0
              || !Number.isInteger(normalizedMaxAttempts)
              || normalizedMaxAttempts < 1
              || normalizedMaxAttempts > 5
              || (
                normalizedNextRetryAt !== null
                && Number.isNaN(new Date(normalizedNextRetryAt).getTime())
              )
              || (
                normalizedLastAttemptAt !== null
                && Number.isNaN(new Date(normalizedLastAttemptAt).getTime())
              )
              || !VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS.has(normalizedStatus)
              || (
                normalizedFailureCode !== null
                && normalizedFailureCode.length > MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH
              )
              || (
                normalizedFailureDetail !== null
                && normalizedFailureDetail.length > MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH
              )
              || (
                normalizedLastHttpStatus !== null
                && (
                  !Number.isInteger(normalizedLastHttpStatus)
                  || normalizedLastHttpStatus < 100
                  || normalizedLastHttpStatus > 599
                )
              )
              || normalizedPayloadSnapshot === null
              || normalizedPayloadSnapshot === undefined
              || normalizedResponseSnapshot === undefined
            ) {
              throw new Error('upsertPlatformIntegrationRecoveryQueueEntry received invalid input');
            }
            const existingRows = await tx.query(
              `
                SELECT recovery_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       request_id,
                       traceparent,
                       idempotency_key,
                       attempt_count,
                       max_attempts,
                       next_retry_at,
                       last_attempt_at,
                       status,
                       failure_code,
                       failure_detail,
                       last_http_status,
                       retryable,
                       payload_snapshot,
                       response_snapshot,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_retry_recovery_queue
                WHERE integration_id = ?
                  AND contract_type = ?
                  AND contract_version = ?
                  AND request_id = ?
                  AND idempotency_key = ?
                LIMIT 1
                FOR UPDATE
              `,
              [
                normalizedIntegrationId,
                normalizedContractType,
                normalizedContractVersion,
                normalizedRequestId,
                normalizedIdempotencyKey
              ]
            );
            if (!Array.isArray(existingRows)) {
              throw new Error(
                'upsertPlatformIntegrationRecoveryQueueEntry existing query malformed'
              );
            }
            const existingRecord = existingRows.length > 0
              ? toPlatformIntegrationRecoveryQueueRecord(existingRows[0])
              : null;
            if (existingRows.length > 0 && !existingRecord) {
              throw new Error(
                'upsertPlatformIntegrationRecoveryQueueEntry existing row malformed'
              );
            }
            if (
              existingRecord
              && (
                existingRecord.status === 'succeeded'
                || existingRecord.status === 'replayed'
              )
            ) {
              return {
                ...existingRecord,
                inserted: false,
                auditRecorded: false
              };
            }
            let persistedRecoveryId = existingRecord?.recoveryId || normalizedRecoveryId;
            if (!existingRecord) {
              try {
                await tx.query(
                  `
                    INSERT INTO platform_integration_retry_recovery_queue (
                      recovery_id,
                      integration_id,
                      contract_type,
                      contract_version,
                      request_id,
                      traceparent,
                      idempotency_key,
                      attempt_count,
                      max_attempts,
                      next_retry_at,
                      last_attempt_at,
                      status,
                      failure_code,
                      failure_detail,
                      last_http_status,
                      retryable,
                      payload_snapshot,
                      response_snapshot,
                      created_by_user_id,
                      updated_by_user_id
                    )
                    VALUES (
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), CAST(? AS JSON), ?, ?
                    )
                  `,
                  [
                    persistedRecoveryId,
                    normalizedIntegrationId,
                    normalizedContractType,
                    normalizedContractVersion,
                    normalizedRequestId,
                    normalizedTraceparent,
                    normalizedIdempotencyKey,
                    normalizedAttemptCount,
                    normalizedMaxAttempts,
                    normalizedNextRetryAt,
                    normalizedLastAttemptAt,
                    normalizedStatus,
                    normalizedFailureCode,
                    normalizedFailureDetail,
                    normalizedLastHttpStatus,
                    retryable ? 1 : 0,
                    normalizedPayloadSnapshot,
                    normalizedResponseSnapshot,
                    normalizedOperatorUserId,
                    normalizedOperatorUserId
                  ]
                );
              } catch (error) {
                if (!isDuplicateEntryError(error)) {
                  throw error;
                }
              }
            }
            await tx.query(
              `
                UPDATE platform_integration_retry_recovery_queue
                SET attempt_count = ?,
                    max_attempts = ?,
                    next_retry_at = ?,
                    last_attempt_at = ?,
                    status = CASE
                      WHEN status IN ('succeeded', 'replayed') THEN status
                      ELSE ?
                    END,
                    failure_code = ?,
                    failure_detail = ?,
                    last_http_status = ?,
                    retryable = ?,
                    payload_snapshot = CAST(? AS JSON),
                    response_snapshot = CAST(? AS JSON),
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE integration_id = ?
                  AND contract_type = ?
                  AND contract_version = ?
                  AND request_id = ?
                  AND idempotency_key = ?
              `,
              [
                normalizedAttemptCount,
                normalizedMaxAttempts,
                normalizedNextRetryAt,
                normalizedLastAttemptAt,
                normalizedStatus,
                normalizedFailureCode,
                normalizedFailureDetail,
                normalizedLastHttpStatus,
                retryable ? 1 : 0,
                normalizedPayloadSnapshot,
                normalizedResponseSnapshot,
                normalizedOperatorUserId,
                normalizedIntegrationId,
                normalizedContractType,
                normalizedContractVersion,
                normalizedRequestId,
                normalizedIdempotencyKey
              ]
            );
            const persistedRows = await tx.query(
              `
                SELECT recovery_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       request_id,
                       traceparent,
                       idempotency_key,
                       attempt_count,
                       max_attempts,
                       next_retry_at,
                       last_attempt_at,
                       status,
                       failure_code,
                       failure_detail,
                       last_http_status,
                       retryable,
                       payload_snapshot,
                       response_snapshot,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_retry_recovery_queue
                WHERE integration_id = ?
                  AND contract_type = ?
                  AND contract_version = ?
                  AND request_id = ?
                  AND idempotency_key = ?
                LIMIT 1
              `,
              [
                normalizedIntegrationId,
                normalizedContractType,
                normalizedContractVersion,
                normalizedRequestId,
                normalizedIdempotencyKey
              ]
            );
            const persistedRecord = toPlatformIntegrationRecoveryQueueRecord(
              persistedRows?.[0] || null
            );
            if (!persistedRecord) {
              throw new Error('upsertPlatformIntegrationRecoveryQueueEntry result unavailable');
            }
            persistedRecoveryId = persistedRecord.recoveryId;
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.recovery.retry_scheduled',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_recovery',
                  targetId: persistedRecoveryId,
                  result: 'success',
                  beforeState: existingRecord
                    ? {
                      status: existingRecord.status,
                      attempt_count: existingRecord.attemptCount,
                      next_retry_at: existingRecord.nextRetryAt
                    }
                    : null,
                  afterState: {
                    status: persistedRecord.status,
                    attempt_count: persistedRecord.attemptCount,
                    next_retry_at: persistedRecord.nextRetryAt
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration recovery schedule audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...persistedRecord,
              inserted: !existingRecord,
              auditRecorded
            };
          })
      }),

    claimNextDuePlatformIntegrationRecoveryQueueEntry: async ({
      integrationId = null,
      now = new Date().toISOString(),
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'claimNextDuePlatformIntegrationRecoveryQueueEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedNow = new Date(now);
            if (Number.isNaN(normalizedNow.getTime())) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry received invalid now'
              );
            }
            const normalizedNowIso = normalizedNow.toISOString();
            const staleRetryingThresholdIso = new Date(
              normalizedNow.getTime() - DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS
            ).toISOString();
            const claimLeaseExpiresAtIso = new Date(
              normalizedNow.getTime() + DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS
            ).toISOString();
            const normalizedOperatorUserId = normalizePlatformIntegrationOptionalText(
              operatorUserId
            );
            const normalizedOperatorSessionId = normalizePlatformIntegrationOptionalText(
              operatorSessionId
            );
            const normalizedAuditContext = auditContext && typeof auditContext === 'object'
              ? auditContext
              : null;
            const auditRequestId = String(normalizedAuditContext?.requestId || '').trim()
              || 'request_id_unset';
            const auditTraceparent = normalizedAuditContext?.traceparent || null;
            const auditActorUserId = normalizePlatformIntegrationOptionalText(
              normalizedAuditContext?.actorUserId || normalizedOperatorUserId
            );
            const auditActorSessionId = normalizePlatformIntegrationOptionalText(
              normalizedAuditContext?.actorSessionId || normalizedOperatorSessionId
            );
            const normalizedIntegrationId = integrationId === null || integrationId === undefined
              ? null
              : normalizePlatformIntegrationId(integrationId);
            if (
              normalizedIntegrationId !== null
              && !isValidPlatformIntegrationId(normalizedIntegrationId)
            ) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry received invalid integrationId'
              );
            }
            const staleRetryingWhereClauses = [
              "status = 'retrying'",
              'attempt_count >= max_attempts',
              `(
                (next_retry_at IS NOT NULL AND next_retry_at <= ?)
                OR (
                  next_retry_at IS NULL
                  AND (last_attempt_at IS NULL OR last_attempt_at <= ?)
                )
              )`
            ];
            const staleRetryingArgs = [
              normalizedNowIso,
              staleRetryingThresholdIso
            ];
            if (normalizedIntegrationId !== null) {
              staleRetryingWhereClauses.push('integration_id = ?');
              staleRetryingArgs.push(normalizedIntegrationId);
            }
            const staleRetryingRows = await tx.query(
              `
                SELECT recovery_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       request_id,
                       traceparent,
                       idempotency_key,
                       attempt_count,
                       max_attempts,
                       next_retry_at,
                       last_attempt_at,
                       status,
                       failure_code,
                       failure_detail,
                       last_http_status,
                       retryable,
                       payload_snapshot,
                       response_snapshot,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_retry_recovery_queue
                WHERE ${staleRetryingWhereClauses.join(' AND ')}
                FOR UPDATE SKIP LOCKED
              `,
              staleRetryingArgs
            );
            if (!Array.isArray(staleRetryingRows)) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry stale retrying query malformed'
              );
            }
            const staleRetryingRecords = staleRetryingRows.map((row) =>
              toPlatformIntegrationRecoveryQueueRecord(row)
            );
            if (staleRetryingRecords.some((record) => !record)) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry stale retrying row malformed'
              );
            }
            if (staleRetryingRecords.length > 0) {
              const staleRecoveryIds = staleRetryingRecords.map((record) => record.recoveryId);
              await tx.query(
                `
                  UPDATE platform_integration_retry_recovery_queue
                  SET status = 'dlq',
                      next_retry_at = NULL,
                      updated_by_user_id = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE recovery_id IN (${buildSqlInPlaceholders(staleRecoveryIds.length)})
                `,
                [
                  normalizedOperatorUserId,
                  ...staleRecoveryIds
                ]
              );
              try {
                for (const staleRecord of staleRetryingRecords) {
                  await recordAuditEventWithQueryClient({
                    queryClient: tx,
                    domain: 'platform',
                    requestId: auditRequestId,
                    traceparent: auditTraceparent,
                    eventType: 'platform.integration.recovery.retry_exhausted',
                    actorUserId: auditActorUserId,
                    actorSessionId: auditActorSessionId,
                    targetType: 'integration_recovery',
                    targetId: staleRecord.recoveryId,
                    result: 'failed',
                    beforeState: {
                      status: staleRecord.status,
                      attempt_count: staleRecord.attemptCount,
                      max_attempts: staleRecord.maxAttempts,
                      next_retry_at: staleRecord.nextRetryAt,
                      last_attempt_at: staleRecord.lastAttemptAt
                    },
                    afterState: {
                      status: 'dlq',
                      attempt_count: staleRecord.attemptCount,
                      max_attempts: staleRecord.maxAttempts,
                      next_retry_at: null,
                      last_attempt_at: staleRecord.lastAttemptAt
                    },
                    metadata: {
                      exhausted_by: 'stale-retrying-claim-sweep'
                    }
                  });
                }
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration recovery claim sweep audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            const whereClauses = [
              'attempt_count < max_attempts',
              `(
                (status IN ('pending', 'replayed') AND (next_retry_at IS NULL OR next_retry_at <= ?))
                OR (
                  status = 'retrying'
                  AND (
                    (next_retry_at IS NOT NULL AND next_retry_at <= ?)
                    OR (
                      next_retry_at IS NULL
                      AND (last_attempt_at IS NULL OR last_attempt_at <= ?)
                    )
                  )
                )
              )`
            ];
            const queryArgs = [
              normalizedNowIso,
              normalizedNowIso,
              staleRetryingThresholdIso
            ];
            if (normalizedIntegrationId !== null) {
              whereClauses.push('integration_id = ?');
              queryArgs.push(normalizedIntegrationId);
            }
            const candidateRows = await tx.query(
              `
                SELECT recovery_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       request_id,
                       traceparent,
                       idempotency_key,
                       attempt_count,
                       max_attempts,
                       next_retry_at,
                       last_attempt_at,
                       status,
                       failure_code,
                       failure_detail,
                       last_http_status,
                       retryable,
                       payload_snapshot,
                       response_snapshot,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_retry_recovery_queue
                WHERE ${whereClauses.join(' AND ')}
                ORDER BY COALESCE(next_retry_at, created_at) ASC, created_at ASC, recovery_id ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
              `,
              queryArgs
            );
            if (!Array.isArray(candidateRows)) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry candidate query malformed'
              );
            }
            if (candidateRows.length === 0) {
              return null;
            }
            const candidateRecord = toPlatformIntegrationRecoveryQueueRecord(
              candidateRows[0]
            );
            if (!candidateRecord) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry candidate row malformed'
              );
            }
            const nextAttemptCount = Math.min(
              candidateRecord.maxAttempts,
              candidateRecord.attemptCount + 1
            );
            await tx.query(
              `
                UPDATE platform_integration_retry_recovery_queue
                SET status = 'retrying',
                    attempt_count = ?,
                    next_retry_at = ?,
                    last_attempt_at = ?,
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE recovery_id = ?
              `,
              [
                nextAttemptCount,
                claimLeaseExpiresAtIso,
                normalizedNowIso,
                normalizedOperatorUserId,
                candidateRecord.recoveryId
              ]
            );
            const claimedRows = await tx.query(
              `
                SELECT recovery_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       request_id,
                       traceparent,
                       idempotency_key,
                       attempt_count,
                       max_attempts,
                       next_retry_at,
                       last_attempt_at,
                       status,
                       failure_code,
                       failure_detail,
                       last_http_status,
                       retryable,
                       payload_snapshot,
                       response_snapshot,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_retry_recovery_queue
                WHERE recovery_id = ?
                LIMIT 1
              `,
              [candidateRecord.recoveryId]
            );
            const claimedRecord = toPlatformIntegrationRecoveryQueueRecord(
              claimedRows?.[0] || null
            );
            if (!claimedRecord) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry result unavailable'
              );
            }
            return {
              ...claimedRecord,
              previousStatus: candidateRecord.status,
              currentStatus: claimedRecord.status
            };
          })
      }),

    completePlatformIntegrationRecoveryQueueAttempt: async ({
      integrationId,
      recoveryId,
      succeeded = false,
      retryable = true,
      nextRetryAt = null,
      failureCode = null,
      failureDetail = null,
      lastHttpStatus = null,
      responseSnapshot = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'completePlatformIntegrationRecoveryQueueAttempt',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(recoveryId);
            const normalizedFailureCode = normalizePlatformIntegrationOptionalText(failureCode);
            const normalizedFailureDetail = normalizePlatformIntegrationOptionalText(
              failureDetail
            );
            const normalizedLastHttpStatus = lastHttpStatus === null || lastHttpStatus === undefined
              ? null
              : Number(lastHttpStatus);
            const normalizedResponseSnapshot = normalizePlatformIntegrationJsonForStorage({
              value: responseSnapshot
            });
            const normalizedNextRetryAt = nextRetryAt === null || nextRetryAt === undefined
              ? null
              : new Date(nextRetryAt).toISOString();
            const normalizedOperatorUserId = normalizePlatformIntegrationOptionalText(
              operatorUserId
            );
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !normalizedRecoveryId
              || normalizedRecoveryId.length > MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH
              || (
                normalizedFailureCode !== null
                && normalizedFailureCode.length > MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH
              )
              || (
                normalizedFailureDetail !== null
                && normalizedFailureDetail.length > MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH
              )
              || (
                normalizedLastHttpStatus !== null
                && (
                  !Number.isInteger(normalizedLastHttpStatus)
                  || normalizedLastHttpStatus < 100
                  || normalizedLastHttpStatus > 599
                )
              )
              || normalizedResponseSnapshot === undefined
              || (
                normalizedNextRetryAt !== null
                && Number.isNaN(new Date(normalizedNextRetryAt).getTime())
              )
            ) {
              throw new Error(
                'completePlatformIntegrationRecoveryQueueAttempt received invalid input'
              );
            }
            const existingRows = await tx.query(
              `
                SELECT recovery_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       request_id,
                       traceparent,
                       idempotency_key,
                       attempt_count,
                       max_attempts,
                       next_retry_at,
                       last_attempt_at,
                       status,
                       failure_code,
                       failure_detail,
                       last_http_status,
                       retryable,
                       payload_snapshot,
                       response_snapshot,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_retry_recovery_queue
                WHERE integration_id = ?
                  AND recovery_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [
                normalizedIntegrationId,
                normalizedRecoveryId
              ]
            );
            if (!Array.isArray(existingRows)) {
              throw new Error(
                'completePlatformIntegrationRecoveryQueueAttempt existing query malformed'
              );
            }
            if (existingRows.length === 0) {
              return null;
            }
            const existingRecord = toPlatformIntegrationRecoveryQueueRecord(
              existingRows[0]
            );
            if (!existingRecord) {
              throw new Error(
                'completePlatformIntegrationRecoveryQueueAttempt existing row malformed'
              );
            }
            let nextStatus = 'succeeded';
            let persistedRetryable = false;
            let persistedFailureCode = null;
            let persistedFailureDetail = null;
            let persistedLastHttpStatus = null;
            let persistedNextRetryAt = null;
            const completionNowIso = new Date().toISOString();
            if (!succeeded) {
              persistedRetryable = isPlatformIntegrationRecoveryFailureRetryable({
                retryable,
                lastHttpStatus: normalizedLastHttpStatus,
                failureCode: normalizedFailureCode,
                responseSnapshot: normalizedResponseSnapshot
              });
              persistedFailureCode = normalizedFailureCode;
              persistedFailureDetail = normalizedFailureDetail;
              persistedLastHttpStatus = normalizedLastHttpStatus;
              const retrySchedule = persistedRetryable
                ? computeRetrySchedule({
                  attemptCount: existingRecord.attemptCount,
                  maxAttempts: existingRecord.maxAttempts,
                  now: completionNowIso
                })
                : {
                  exhausted: true,
                  nextRetryAt: null
                };
              nextStatus = retrySchedule.exhausted ? 'dlq' : 'pending';
              persistedNextRetryAt = retrySchedule.exhausted
                ? null
                : (normalizedNextRetryAt || retrySchedule.nextRetryAt || completionNowIso);
            }
            await tx.query(
              `
                UPDATE platform_integration_retry_recovery_queue
                SET status = ?,
                    next_retry_at = ?,
                    failure_code = ?,
                    failure_detail = ?,
                    last_http_status = ?,
                    retryable = ?,
                    response_snapshot = CAST(? AS JSON),
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE integration_id = ?
                  AND recovery_id = ?
              `,
              [
                nextStatus,
                persistedNextRetryAt,
                persistedFailureCode,
                persistedFailureDetail,
                persistedLastHttpStatus,
                persistedRetryable ? 1 : 0,
                normalizedResponseSnapshot,
                normalizedOperatorUserId,
                normalizedIntegrationId,
                normalizedRecoveryId
              ]
            );
            const updatedRows = await tx.query(
              `
                SELECT recovery_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       request_id,
                       traceparent,
                       idempotency_key,
                       attempt_count,
                       max_attempts,
                       next_retry_at,
                       last_attempt_at,
                       status,
                       failure_code,
                       failure_detail,
                       last_http_status,
                       retryable,
                       payload_snapshot,
                       response_snapshot,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_retry_recovery_queue
                WHERE integration_id = ?
                  AND recovery_id = ?
                LIMIT 1
              `,
              [
                normalizedIntegrationId,
                normalizedRecoveryId
              ]
            );
            const updatedRecord = toPlatformIntegrationRecoveryQueueRecord(
              updatedRows?.[0] || null
            );
            if (!updatedRecord) {
              throw new Error(
                'completePlatformIntegrationRecoveryQueueAttempt result unavailable'
              );
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              const emitAuditEvent = async (eventType) =>
                recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType,
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_recovery',
                  targetId: normalizedRecoveryId,
                  result: updatedRecord.status === 'succeeded' ? 'success' : 'failed',
                  beforeState: {
                    status: existingRecord.status
                  },
                  afterState: {
                    status: updatedRecord.status,
                    attempt_count: updatedRecord.attemptCount,
                    next_retry_at: updatedRecord.nextRetryAt
                  }
                });
              try {
                if (updatedRecord.status === 'succeeded') {
                  await emitAuditEvent('platform.integration.recovery.reprocess_succeeded');
                } else {
                  await emitAuditEvent('platform.integration.recovery.reprocess_failed');
                  if (updatedRecord.status === 'dlq') {
                    await emitAuditEvent('platform.integration.recovery.retry_exhausted');
                  }
                }
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration recovery completion audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...updatedRecord,
              previousStatus: existingRecord.status,
              currentStatus: updatedRecord.status,
              exhausted: updatedRecord.status === 'dlq',
              auditRecorded
            };
          })
      }),

    replayPlatformIntegrationRecoveryQueueEntry: async ({
      integrationId,
      recoveryId,
      reason = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'replayPlatformIntegrationRecoveryQueueEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(recoveryId);
            const normalizedReason = normalizePlatformIntegrationOptionalText(reason);
            const normalizedOperatorUserId = normalizePlatformIntegrationOptionalText(
              operatorUserId
            );
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !normalizedRecoveryId
              || normalizedRecoveryId.length > MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH
              || (
                normalizedReason !== null
                && normalizedReason.length > MAX_PLATFORM_INTEGRATION_RECOVERY_REASON_LENGTH
              )
            ) {
              throw new Error('replayPlatformIntegrationRecoveryQueueEntry received invalid input');
            }
            const existingRows = await tx.query(
              `
                SELECT recovery_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       request_id,
                       traceparent,
                       idempotency_key,
                       attempt_count,
                       max_attempts,
                       next_retry_at,
                       last_attempt_at,
                       status,
                       failure_code,
                       failure_detail,
                       last_http_status,
                       retryable,
                       payload_snapshot,
                       response_snapshot,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_retry_recovery_queue
                WHERE integration_id = ?
                  AND recovery_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [
                normalizedIntegrationId,
                normalizedRecoveryId
              ]
            );
            if (!Array.isArray(existingRows)) {
              throw new Error(
                'replayPlatformIntegrationRecoveryQueueEntry existing query malformed'
              );
            }
            if (existingRows.length === 0) {
              return null;
            }
            const existingRecord = toPlatformIntegrationRecoveryQueueRecord(
              existingRows[0]
            );
            if (!existingRecord) {
              throw new Error(
                'replayPlatformIntegrationRecoveryQueueEntry existing row malformed'
              );
            }
            if (
              existingRecord.status !== 'failed'
              && existingRecord.status !== 'dlq'
            ) {
              throw createPlatformIntegrationRecoveryReplayConflictError({
                integrationId: normalizedIntegrationId,
                recoveryId: normalizedRecoveryId,
                previousStatus: existingRecord.status,
                requestedStatus: 'replayed'
              });
            }
            await tx.query(
              `
                UPDATE platform_integration_retry_recovery_queue
                SET status = 'replayed',
                    attempt_count = 0,
                    next_retry_at = CURRENT_TIMESTAMP(3),
                    last_attempt_at = NULL,
                    failure_code = NULL,
                    failure_detail = NULL,
                    last_http_status = NULL,
                    retryable = 1,
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE integration_id = ?
                  AND recovery_id = ?
              `,
              [
                normalizedOperatorUserId,
                normalizedIntegrationId,
                normalizedRecoveryId
              ]
            );
            const updatedRows = await tx.query(
              `
                SELECT recovery_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       request_id,
                       traceparent,
                       idempotency_key,
                       attempt_count,
                       max_attempts,
                       next_retry_at,
                       last_attempt_at,
                       status,
                       failure_code,
                       failure_detail,
                       last_http_status,
                       retryable,
                       payload_snapshot,
                       response_snapshot,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_retry_recovery_queue
                WHERE integration_id = ?
                  AND recovery_id = ?
                LIMIT 1
              `,
              [
                normalizedIntegrationId,
                normalizedRecoveryId
              ]
            );
            const updatedRecord = toPlatformIntegrationRecoveryQueueRecord(
              updatedRows?.[0] || null
            );
            if (!updatedRecord) {
              throw new Error(
                'replayPlatformIntegrationRecoveryQueueEntry result unavailable'
              );
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.recovery.replayed',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_recovery',
                  targetId: normalizedRecoveryId,
                  result: 'success',
                  beforeState: {
                    status: existingRecord.status
                  },
                  afterState: {
                    status: updatedRecord.status,
                    reason: normalizedReason
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration recovery replay audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...updatedRecord,
              previousStatus: existingRecord.status,
              currentStatus: updatedRecord.status,
              reason: normalizedReason,
              auditRecorded
            };
          })
      }),

    listPlatformRolePermissionGrants: async ({ roleId }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT permission_code
          FROM platform_role_permission_grants
          WHERE role_id = ?
          ORDER BY permission_code ASC
        `,
        [normalizedRoleId]
      );
      const normalizedPermissionCodeKeys = [];
      const seenPermissionCodeKeys = new Set();
      for (const row of Array.isArray(rows) ? rows : []) {
        const permissionCodeKey = normalizeStrictPlatformPermissionCodeFromGrantRow(
          row?.permission_code,
          'platform-role-permission-grants-invalid-permission-code'
        );
        if (seenPermissionCodeKeys.has(permissionCodeKey)) {
          throw createPlatformRolePermissionGrantDataError(
            'platform-role-permission-grants-duplicate-permission-code'
          );
        }
        seenPermissionCodeKeys.add(permissionCodeKey);
        normalizedPermissionCodeKeys.push(permissionCodeKey);
      }
      return normalizedPermissionCodeKeys;
    },

    listPlatformRolePermissionGrantsByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIds = [...new Set(
        (Array.isArray(roleIds) ? roleIds : [])
          .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
          .filter((roleId) => roleId.length > 0)
      )];
      if (normalizedRoleIds.length === 0) {
        return [];
      }
      const placeholders = buildSqlInPlaceholders(normalizedRoleIds.length);
      const rows = await dbClient.query(
        `
          SELECT role_id, permission_code
          FROM platform_role_permission_grants
          WHERE role_id IN (${placeholders})
          ORDER BY role_id ASC, permission_code ASC
        `,
        normalizedRoleIds
      );
      const grantsByRoleId = new Map();
      for (const roleId of normalizedRoleIds) {
        grantsByRoleId.set(roleId, []);
      }
      const seenGrantPermissionCodeKeysByRoleId = new Map(
        normalizedRoleIds.map((roleId) => [roleId, new Set()])
      );
      for (const row of Array.isArray(rows) ? rows : []) {
        const roleId = normalizeStrictRoleIdFromPlatformGrantRow(
          row?.role_id,
          'platform-role-permission-grants-invalid-role-id'
        );
        if (!grantsByRoleId.has(roleId)) {
          throw createPlatformRolePermissionGrantDataError(
            'platform-role-permission-grants-unexpected-role-id'
          );
        }
        const permissionCodeKey = normalizeStrictPlatformPermissionCodeFromGrantRow(
          row?.permission_code,
          'platform-role-permission-grants-invalid-permission-code'
        );
        const seenPermissionCodeKeys = seenGrantPermissionCodeKeysByRoleId.get(roleId);
        if (seenPermissionCodeKeys.has(permissionCodeKey)) {
          throw createPlatformRolePermissionGrantDataError(
            'platform-role-permission-grants-duplicate-permission-code'
          );
        }
        seenPermissionCodeKeys.add(permissionCodeKey);
        grantsByRoleId.get(roleId).push(permissionCodeKey);
      }
      return [...grantsByRoleId.entries()].map(([roleId, permissionCodes]) => ({
        roleId,
        permissionCodes: [...permissionCodes]
      }));
    },

    replacePlatformRolePermissionGrants: async ({
      roleId,
      permissionCodes = [],
      operatorUserId = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        throw new Error('replacePlatformRolePermissionGrants requires roleId');
      }
      const normalizedPermissionCodes = normalizePlatformPermissionCodes(permissionCodes);
      return executeWithDeadlockRetry({
        operation: 'replacePlatformRolePermissionGrants',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const roleRows = await tx.query(
              `
                SELECT role_id
                FROM platform_roles
                WHERE role_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedRoleId]
            );
            if (!roleRows?.[0]) {
              return null;
            }

            await tx.query(
              `
                DELETE FROM platform_role_permission_grants
                WHERE role_id = ?
              `,
              [normalizedRoleId]
            );

            for (const permissionCode of normalizedPermissionCodes) {
              await tx.query(
                `
                  INSERT INTO platform_role_permission_grants (
                    role_id,
                    permission_code,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedRoleId,
                  permissionCode,
                  operatorUserId ? String(operatorUserId) : null,
                  operatorUserId ? String(operatorUserId) : null
                ]
              );
            }

            const grantRows = await tx.query(
              `
                SELECT permission_code
                FROM platform_role_permission_grants
                WHERE role_id = ?
                ORDER BY permission_code ASC
              `,
              [normalizedRoleId]
            );
            const savedPermissionCodeKeys = [];
            const seenSavedPermissionCodeKeys = new Set();
            for (const row of Array.isArray(grantRows) ? grantRows : []) {
              const permissionCodeKey = normalizeStrictPlatformPermissionCodeFromGrantRow(
                row?.permission_code,
                'platform-role-permission-grants-invalid-permission-code'
              );
              if (seenSavedPermissionCodeKeys.has(permissionCodeKey)) {
                throw createPlatformRolePermissionGrantDataError(
                  'platform-role-permission-grants-duplicate-permission-code'
                );
              }
              seenSavedPermissionCodeKeys.add(permissionCodeKey);
              savedPermissionCodeKeys.push(permissionCodeKey);
            }
            return savedPermissionCodeKeys;
          })
      });
    },

    replacePlatformRolePermissionGrantsAndSyncSnapshots: async ({
      roleId,
      permissionCodes = [],
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null,
      maxAffectedUsers = DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        throw new Error('replacePlatformRolePermissionGrantsAndSyncSnapshots requires roleId');
      }
      const normalizedPermissionCodes = normalizePlatformPermissionCodes(permissionCodes);
      const normalizedMaxAffectedUsers = Math.max(
        1,
        Math.floor(Number(maxAffectedUsers || DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS))
      );
      return executeWithDeadlockRetry({
        operation: 'replacePlatformRolePermissionGrantsAndSyncSnapshots',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const roleRows = await tx.query(
              `
                SELECT role_id
                FROM platform_roles
                WHERE role_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedRoleId]
            );
            if (!roleRows?.[0]) {
              return null;
            }

            const affectedUserRows = await tx.query(
              `
                SELECT user_id
                FROM platform_user_roles
                WHERE role_id = ?
                ORDER BY user_id ASC
                FOR UPDATE
              `,
              [normalizedRoleId]
            );
            const affectedUserIds = [
              ...new Set(
                (Array.isArray(affectedUserRows) ? affectedUserRows : [])
                  .map((row) => String(row?.user_id || '').trim())
                  .filter((userId) => userId.length > 0)
              )
            ];
            if (affectedUserIds.length > normalizedMaxAffectedUsers) {
              const limitError = new Error('platform role permission affected users exceed limit');
              limitError.code = 'ERR_PLATFORM_ROLE_PERMISSION_AFFECTED_USERS_OVER_LIMIT';
              limitError.maxAffectedUsers = normalizedMaxAffectedUsers;
              limitError.affectedUsers = affectedUserIds.length;
              throw limitError;
            }
            const previousGrantRows = await tx.query(
              `
                SELECT permission_code
                FROM platform_role_permission_grants
                WHERE role_id = ?
                ORDER BY permission_code ASC
                FOR UPDATE
              `,
              [normalizedRoleId]
            );
            const previousPermissionCodes = [];
            const seenPreviousPermissionCodeKeys = new Set();
            for (const row of Array.isArray(previousGrantRows) ? previousGrantRows : []) {
              const permissionCodeKey = normalizeStrictPlatformPermissionCodeFromGrantRow(
                row?.permission_code,
                'platform-role-permission-grants-invalid-permission-code'
              );
              if (seenPreviousPermissionCodeKeys.has(permissionCodeKey)) {
                throw createPlatformRolePermissionGrantDataError(
                  'platform-role-permission-grants-duplicate-permission-code'
                );
              }
              seenPreviousPermissionCodeKeys.add(permissionCodeKey);
              previousPermissionCodes.push(permissionCodeKey);
            }

            await tx.query(
              `
                DELETE FROM platform_role_permission_grants
                WHERE role_id = ?
              `,
              [normalizedRoleId]
            );

            for (const permissionCode of normalizedPermissionCodes) {
              await tx.query(
                `
                  INSERT INTO platform_role_permission_grants (
                    role_id,
                    permission_code,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedRoleId,
                  permissionCode,
                  operatorUserId ? String(operatorUserId) : null,
                  operatorUserId ? String(operatorUserId) : null
                ]
              );
            }

            const grantCodesByRoleId = new Map();
            grantCodesByRoleId.set(normalizedRoleId, [...normalizedPermissionCodes]);

            for (const affectedUserId of affectedUserIds) {
              const roleRowsForUser = await tx.query(
                `
                  SELECT role_id, status
                  FROM platform_user_roles
                  WHERE user_id = ?
                  ORDER BY role_id ASC
                  FOR UPDATE
                `,
                [affectedUserId]
              );

              const normalizedRoleIdsForUser = [
                ...new Set(
                  (Array.isArray(roleRowsForUser) ? roleRowsForUser : [])
                    .map((row) => normalizePlatformRoleCatalogRoleId(row?.role_id))
                    .filter((candidateRoleId) => candidateRoleId.length > 0)
                )
              ];
              const missingGrantRoleIds = normalizedRoleIdsForUser.filter(
                (candidateRoleId) => !grantCodesByRoleId.has(candidateRoleId)
              );
              if (missingGrantRoleIds.length > 0) {
                const placeholders = buildSqlInPlaceholders(missingGrantRoleIds.length);
                const grantRows = await tx.query(
                  `
                    SELECT role_id, permission_code
                    FROM platform_role_permission_grants
                    WHERE role_id IN (${placeholders})
                    ORDER BY role_id ASC, permission_code ASC
                  `,
                  missingGrantRoleIds
                );
                for (const roleIdKey of missingGrantRoleIds) {
                  grantCodesByRoleId.set(roleIdKey, []);
                }
                const seenGrantPermissionCodeKeysByRoleId = new Map(
                  missingGrantRoleIds.map((roleIdKey) => [roleIdKey, new Set()])
                );
                for (const row of Array.isArray(grantRows) ? grantRows : []) {
                  const roleIdKey = normalizeStrictRoleIdFromPlatformGrantRow(
                    row?.role_id,
                    'platform-role-permission-grants-invalid-role-id'
                  );
                  if (!grantCodesByRoleId.has(roleIdKey)) {
                    throw createPlatformRolePermissionGrantDataError(
                      'platform-role-permission-grants-unexpected-role-id'
                    );
                  }
                  const permissionCodeKey = normalizeStrictPlatformPermissionCodeFromGrantRow(
                    row?.permission_code,
                    'platform-role-permission-grants-invalid-permission-code'
                  );
                  const seenPermissionCodeKeys = seenGrantPermissionCodeKeysByRoleId.get(
                    roleIdKey
                  );
                  if (seenPermissionCodeKeys.has(permissionCodeKey)) {
                    throw createPlatformRolePermissionGrantDataError(
                      'platform-role-permission-grants-duplicate-permission-code'
                    );
                  }
                  seenPermissionCodeKeys.add(permissionCodeKey);
                  grantCodesByRoleId.get(roleIdKey).push(permissionCodeKey);
                }
                for (const roleIdKey of missingGrantRoleIds) {
                  grantCodesByRoleId.set(roleIdKey, [...(grantCodesByRoleId.get(roleIdKey) || [])]);
                }
              }

              const nextRoles = (Array.isArray(roleRowsForUser) ? roleRowsForUser : [])
                .map((row) => {
                  const normalizedRoleIdForUser = normalizePlatformRoleCatalogRoleId(row?.role_id);
                  if (!normalizedRoleIdForUser) {
                    return null;
                  }
                  const permissionSnapshot = toPlatformPermissionSnapshotFromGrantCodes(
                    grantCodesByRoleId.get(normalizedRoleIdForUser) || []
                  );
                  return {
                    roleId: normalizedRoleIdForUser,
                    status: normalizePlatformRoleStatus(row?.status),
                    canViewUserManagement: permissionSnapshot.canViewUserManagement,
                    canOperateUserManagement: permissionSnapshot.canOperateUserManagement,
                    canViewTenantManagement: permissionSnapshot.canViewTenantManagement,
                    canOperateTenantManagement: permissionSnapshot.canOperateTenantManagement
                  };
                })
                .filter(Boolean);

              const syncResult = await replacePlatformRolesAndSyncSnapshotInTx({
                txClient: tx,
                userId: affectedUserId,
                roles: nextRoles
              });
              const syncReason = String(syncResult?.reason || 'unknown')
                .trim()
                .toLowerCase();
              if (syncReason !== 'ok') {
                const syncError = new Error(
                  `platform role permission sync failed: ${syncReason || 'unknown'}`
                );
                syncError.code = 'ERR_PLATFORM_ROLE_PERMISSION_SYNC_FAILED';
                syncError.syncReason = syncReason || 'unknown';
                throw syncError;
              }
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  tenantId: null,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.platform_role_permission_grants.updated',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'role_permission_grants',
                  targetId: normalizedRoleId,
                  result: 'success',
                  beforeState: {
                    permission_codes: [...previousPermissionCodes]
                  },
                  afterState: {
                    permission_codes: [...normalizedPermissionCodes]
                  },
                  metadata: {
                    affected_user_count: affectedUserIds.length
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform role permission grants audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }

            return {
              roleId: normalizedRoleId,
              permissionCodes: [...normalizedPermissionCodes],
              affectedUserIds: [...affectedUserIds],
              affectedUserCount: affectedUserIds.length,
              auditRecorded
            };
          })
      });
    },

    listTenantRolePermissionGrants: async ({ roleId }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT permission_code
          FROM tenant_role_permission_grants
          WHERE role_id = ?
          ORDER BY permission_code ASC
        `,
        [normalizedRoleId]
      );
      const normalizedPermissionCodeKeys = [];
      const seenPermissionCodeKeys = new Set();
      for (const row of Array.isArray(rows) ? rows : []) {
        const permissionCodeKey = normalizeStrictTenantPermissionCodeFromGrantRow(
          row?.permission_code,
          'tenant-role-permission-grants-invalid-permission-code'
        );
        if (seenPermissionCodeKeys.has(permissionCodeKey)) {
          throw createTenantRolePermissionGrantDataError(
            'tenant-role-permission-grants-duplicate-permission-code'
          );
        }
        seenPermissionCodeKeys.add(permissionCodeKey);
        normalizedPermissionCodeKeys.push(permissionCodeKey);
      }
      return normalizedPermissionCodeKeys;
    },

    listTenantRolePermissionGrantsByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIds = normalizeTenantUsershipRoleIds(roleIds);
      if (normalizedRoleIds.length === 0) {
        return [];
      }
      const placeholders = buildSqlInPlaceholders(normalizedRoleIds.length);
      const rows = await dbClient.query(
        `
          SELECT role_id, permission_code
          FROM tenant_role_permission_grants
          WHERE role_id IN (${placeholders})
          ORDER BY role_id ASC, permission_code ASC
        `,
        normalizedRoleIds
      );
      const grantsByRoleId = new Map();
      for (const roleId of normalizedRoleIds) {
        grantsByRoleId.set(roleId, []);
      }
      const seenGrantPermissionCodeKeysByRoleId = new Map(
        normalizedRoleIds.map((roleId) => [roleId, new Set()])
      );
      for (const row of Array.isArray(rows) ? rows : []) {
        const roleId = normalizeStrictRoleIdFromTenantGrantRow(
          row?.role_id,
          'tenant-role-permission-grants-invalid-role-id'
        );
        if (!roleId || !grantsByRoleId.has(roleId)) {
          throw createTenantRolePermissionGrantDataError(
            'tenant-role-permission-grants-invalid-role-id'
          );
        }
        const permissionCodeKey = normalizeStrictTenantPermissionCodeFromGrantRow(
          row?.permission_code,
          'tenant-role-permission-grants-invalid-permission-code'
        );
        const seenPermissionCodeKeys = seenGrantPermissionCodeKeysByRoleId.get(roleId);
        if (seenPermissionCodeKeys.has(permissionCodeKey)) {
          throw createTenantRolePermissionGrantDataError(
            'tenant-role-permission-grants-duplicate-permission-code'
          );
        }
        seenPermissionCodeKeys.add(permissionCodeKey);
        grantsByRoleId.get(roleId).push(permissionCodeKey);
      }
      return [...grantsByRoleId.entries()].map(([roleId, permissionCodes]) => ({
        roleId,
        permissionCodes: [...permissionCodes]
      }));
    },

    replaceTenantRolePermissionGrantsAndSyncSnapshots: async ({
      tenantId,
      roleId,
      permissionCodes = [],
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null,
      maxAffectedMemberships = DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS
    }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedTenantId || !normalizedRoleId) {
        throw new Error('replaceTenantRolePermissionGrantsAndSyncSnapshots requires tenantId and roleId');
      }
      const normalizedPermissionCodes = normalizeTenantPermissionCodes(permissionCodes)
        .sort((left, right) => left.localeCompare(right));
      const normalizedMaxAffectedMemberships = Math.max(
        1,
        Math.floor(
          Number(
            maxAffectedMemberships || DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS
          )
        )
      );
      return executeWithDeadlockRetry({
        operation: 'replaceTenantRolePermissionGrantsAndSyncSnapshots',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const roleRows = await tx.query(
              `
                SELECT role_id
                FROM platform_roles
                WHERE role_id = ?
                  AND scope = 'tenant'
                  AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedRoleId, normalizedTenantId]
            );
            if (!roleRows?.[0]) {
              return null;
            }

            const membershipRows = await tx.query(
              `
                SELECT ut.membership_id, ut.user_id
                FROM tenant_membership_roles mr
                JOIN tenant_memberships ut ON ut.membership_id = mr.membership_id
                WHERE mr.role_id = ?
                  AND ut.tenant_id = ?
                  AND ut.status IN ('active', 'enabled')
                ORDER BY ut.membership_id ASC
                FOR UPDATE
              `,
              [normalizedRoleId, normalizedTenantId]
            );
            const affectedMembershipIds = [];
            const affectedUserIds = new Set();
            for (const row of Array.isArray(membershipRows) ? membershipRows : []) {
              const membershipId =
                normalizeStrictTenantRolePermissionGrantIdentity(
                  row?.membership_id,
                  'tenant-role-permission-grants-invalid-membership-id'
                );
              if (affectedMembershipIds.includes(membershipId)) {
                continue;
              }
              affectedMembershipIds.push(membershipId);
              const userId = normalizeStrictTenantRolePermissionGrantIdentity(
                row?.user_id,
                'tenant-role-permission-grants-invalid-affected-user-id'
              );
              affectedUserIds.add(userId);
            }
            if (affectedMembershipIds.length > normalizedMaxAffectedMemberships) {
              const limitError = new Error(
                'tenant role permission affected memberships exceed limit'
              );
              limitError.code = 'ERR_TENANT_ROLE_PERMISSION_AFFECTED_MEMBERSHIPS_OVER_LIMIT';
              limitError.maxAffectedMemberships = normalizedMaxAffectedMemberships;
              limitError.affectedMemberships = affectedMembershipIds.length;
              throw limitError;
            }
            const previousGrantRows = await tx.query(
              `
                SELECT permission_code
                FROM tenant_role_permission_grants
                WHERE role_id = ?
                ORDER BY permission_code ASC
                FOR UPDATE
              `,
              [normalizedRoleId]
            );
            const previousPermissionCodes = [];
            const seenPreviousPermissionCodes = new Set();
            for (const row of Array.isArray(previousGrantRows) ? previousGrantRows : []) {
              const permissionCode = normalizeStrictTenantPermissionCodeFromGrantRow(
                row?.permission_code,
                'tenant-role-permission-grants-invalid-permission-code'
              );
              if (seenPreviousPermissionCodes.has(permissionCode)) {
                throw createTenantRolePermissionGrantDataError(
                  'tenant-role-permission-grants-duplicate-permission-code'
                );
              }
              seenPreviousPermissionCodes.add(permissionCode);
              previousPermissionCodes.push(permissionCode);
            }

            await tx.query(
              `
                DELETE FROM tenant_role_permission_grants
                WHERE role_id = ?
              `,
              [normalizedRoleId]
            );

            for (const permissionCode of normalizedPermissionCodes) {
              await tx.query(
                `
                  INSERT INTO tenant_role_permission_grants (
                    role_id,
                    permission_code,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedRoleId,
                  permissionCode,
                  operatorUserId ? String(operatorUserId) : null,
                  operatorUserId ? String(operatorUserId) : null
                ]
              );
            }

            for (const membershipId of affectedMembershipIds) {
              const syncResult = await syncTenantUsershipPermissionSnapshotInTx({
                txClient: tx,
                membershipId,
                tenantId: normalizedTenantId,
                revokeReason: 'tenant-role-permission-grants-changed'
              });
              const syncReason = String(syncResult?.reason || 'unknown')
                .trim()
                .toLowerCase();
              if (syncReason !== 'ok') {
                const syncError = new Error(
                  `tenant role permission sync failed: ${syncReason || 'unknown'}`
                );
                syncError.code = 'ERR_TENANT_ROLE_PERMISSION_SYNC_FAILED';
                syncError.syncReason = syncReason || 'unknown';
                throw syncError;
              }
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'tenant',
                  tenantId: normalizedTenantId,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.tenant_role_permission_grants.updated',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'role_permission_grants',
                  targetId: normalizedRoleId,
                  result: 'success',
                  beforeState: {
                    permission_codes: [...previousPermissionCodes]
                  },
                  afterState: {
                    permission_codes: [...normalizedPermissionCodes]
                  },
                  metadata: {
                    affected_user_count: affectedUserIds.size
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'tenant role permission grants audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }

            return {
              roleId: normalizedRoleId,
              permissionCodes: [...normalizedPermissionCodes],
              affectedUserIds: [...affectedUserIds],
              affectedUserCount: affectedUserIds.size,
              auditRecorded
            };
          })
      });
    },

    listUserIdsByPlatformRoleId: async ({ roleId }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT user_id
          FROM platform_user_roles
          WHERE role_id = ?
          ORDER BY user_id ASC
        `,
        [normalizedRoleId]
      );
      return (Array.isArray(rows) ? rows : [])
        .map((row) => String(row?.user_id || '').trim())
        .filter((userId) => userId.length > 0);
    },

    listPlatformRoleFactsByUserId: async ({ userId }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT role_id,
                 status,
                 can_view_user_management,
                 can_operate_user_management,
                 can_view_tenant_management,
                 can_operate_tenant_management
          FROM platform_user_roles
          WHERE user_id = ?
          ORDER BY role_id ASC
        `,
        [normalizedUserId]
      );
      return (Array.isArray(rows) ? rows : []).map((row) => ({
        roleId: String(row?.role_id || '').trim(),
        role_id: String(row?.role_id || '').trim(),
        status: String(row?.status || 'active').trim().toLowerCase() || 'active',
        permission: {
          canViewUserManagement: toBoolean(row?.can_view_user_management),
          canOperateUserManagement: toBoolean(row?.can_operate_user_management),
          canViewTenantManagement: toBoolean(row?.can_view_tenant_management),
          canOperateTenantManagement: toBoolean(row?.can_operate_tenant_management)
        }
      }));
    },

    createPlatformRoleCatalogEntry: async ({
      roleId,
      code,
      name,
      status = 'active',
      scope = 'platform',
      tenantId = null,
      isSystem = false,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      const normalizedCode = String(code || '').trim();
      const normalizedName = String(name || '').trim();
      const normalizedStatus = normalizePlatformRoleCatalogStatus(status);
      const normalizedScope = normalizePlatformRoleCatalogScope(scope);
      const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
        scope: normalizedScope,
        tenantId
      });
      if (
        !normalizedRoleId
        || !normalizedCode
        || !normalizedName
        || !VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)
        || !VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)
      ) {
        throw new Error('createPlatformRoleCatalogEntry received invalid input');
      }

      return executeWithDeadlockRetry({
        operation: 'createPlatformRoleCatalogEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            await tx.query(
              `
                INSERT INTO platform_roles (
                  role_id,
                  tenant_id,
                  code,
                  code_normalized,
                  name,
                  status,
                  scope,
                  is_system,
                  created_by_user_id,
                  updated_by_user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              `,
              [
                normalizedRoleId,
                normalizedTenantId,
                normalizedCode,
                normalizedCode.toLowerCase(),
                normalizedName,
                normalizedStatus,
                normalizedScope,
                Number(Boolean(isSystem)),
                operatorUserId ? String(operatorUserId) : null,
                operatorUserId ? String(operatorUserId) : null
              ]
            );
            const rows = await tx.query(
              `
                SELECT role_id,
                       tenant_id,
                       code,
                       name,
                       status,
                       scope,
                       is_system,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_roles
                WHERE role_id = ?
                LIMIT 1
              `,
              [normalizedRoleId]
            );
            const createdRole = toPlatformRoleCatalogRecord(rows?.[0] || null);
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
                  tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.role.catalog.created',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'role',
                  targetId: normalizedRoleId,
                  result: 'success',
                  beforeState: null,
                  afterState: {
                    role_id: normalizeAuditStringOrNull(createdRole?.roleId, 64) || normalizedRoleId,
                    code: normalizeAuditStringOrNull(createdRole?.code, 64) || normalizedCode,
                    name: normalizeAuditStringOrNull(createdRole?.name, 128) || normalizedName,
                    status: normalizePlatformRoleCatalogStatus(
                      createdRole?.status || normalizedStatus
                    ),
                    scope: normalizedScope,
                    tenant_id: normalizedScope === 'tenant' ? normalizedTenantId : null,
                    is_system: Boolean(createdRole?.isSystem ?? Boolean(isSystem))
                  },
                  metadata: {
                    scope: normalizedScope
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error('platform role create audit write failed');
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...createdRole,
              auditRecorded
            };
          })
      });
    },

    updatePlatformRoleCatalogEntry: async ({
      roleId,
      scope = 'platform',
      tenantId = null,
      code = undefined,
      name = undefined,
      status = undefined,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        throw new Error('updatePlatformRoleCatalogEntry requires roleId');
      }
      const normalizedScope = normalizePlatformRoleCatalogScope(scope);
      if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
        throw new Error('updatePlatformRoleCatalogEntry received unsupported scope');
      }
      const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
        scope: normalizedScope,
        tenantId
      });
      const whereClause = normalizedScope === 'tenant'
        ? 'role_id = ? AND scope = ? AND tenant_id = ?'
        : "role_id = ? AND scope = ? AND tenant_id = ''";
      const lookupArgs = normalizedScope === 'tenant'
        ? [normalizedRoleId, normalizedScope, normalizedTenantId]
        : [normalizedRoleId, normalizedScope];

      return executeWithDeadlockRetry({
        operation: 'updatePlatformRoleCatalogEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const rows = await tx.query(
              `
                SELECT role_id,
                       tenant_id,
                       code,
                       name,
                       status,
                       scope,
                       is_system,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_roles
                WHERE ${whereClause}
                LIMIT 1
                FOR UPDATE
              `,
              lookupArgs
            );
            const existing = toPlatformRoleCatalogRecord(rows?.[0] || null);
            if (!existing) {
              return null;
            }

            const nextCode = code === undefined
              ? existing.code
              : String(code || '').trim();
            const nextName = name === undefined
              ? existing.name
              : String(name || '').trim();
            const nextStatus = status === undefined
              ? existing.status
              : normalizePlatformRoleCatalogStatus(status);
            if (
              !nextCode
              || !nextName
              || !VALID_PLATFORM_ROLE_CATALOG_STATUS.has(nextStatus)
            ) {
              throw new Error('updatePlatformRoleCatalogEntry received invalid update payload');
            }

            await tx.query(
              `
                UPDATE platform_roles
                SET code = ?,
                    code_normalized = ?,
                    name = ?,
                    status = ?,
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE role_id = ?
              `,
              [
                nextCode,
                nextCode.toLowerCase(),
                nextName,
                nextStatus,
                operatorUserId ? String(operatorUserId) : existing.updatedByUserId,
                existing.roleId
              ]
            );

            const updatedRows = await tx.query(
              `
                SELECT role_id,
                       tenant_id,
                       code,
                       name,
                       status,
                       scope,
                       is_system,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_roles
                WHERE role_id = ?
                LIMIT 1
              `,
              [existing.roleId]
            );
            const updatedRole = toPlatformRoleCatalogRecord(updatedRows?.[0] || null);
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
                  tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.role.catalog.updated',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'role',
                  targetId: normalizedRoleId,
                  result: 'success',
                  beforeState: {
                    code: normalizeAuditStringOrNull(existing.code, 64),
                    name: normalizeAuditStringOrNull(existing.name, 128),
                    status: normalizePlatformRoleCatalogStatus(existing.status || 'active')
                  },
                  afterState: {
                    code: normalizeAuditStringOrNull(updatedRole?.code, 64),
                    name: normalizeAuditStringOrNull(updatedRole?.name, 128),
                    status: normalizePlatformRoleCatalogStatus(updatedRole?.status || 'active')
                  },
                  metadata: {
                    scope: normalizedScope,
                    changed_fields: [
                      ...new Set(Object.keys({
                        ...(code === undefined ? {} : { code: true }),
                        ...(name === undefined ? {} : { name: true }),
                        ...(status === undefined ? {} : { status: true })
                      }))
                    ]
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error('platform role update audit write failed');
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...updatedRole,
              auditRecorded
            };
          })
      });
    },

    deletePlatformRoleCatalogEntry: async ({
      roleId,
      scope = 'platform',
      tenantId = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        throw new Error('deletePlatformRoleCatalogEntry requires roleId');
      }
      const normalizedScope = normalizePlatformRoleCatalogScope(scope);
      if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
        throw new Error('deletePlatformRoleCatalogEntry received unsupported scope');
      }
      const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
        scope: normalizedScope,
        tenantId
      });
      const whereClause = normalizedScope === 'tenant'
        ? 'role_id = ? AND scope = ? AND tenant_id = ?'
        : "role_id = ? AND scope = ? AND tenant_id = ''";
      const lookupArgs = normalizedScope === 'tenant'
        ? [normalizedRoleId, normalizedScope, normalizedTenantId]
        : [normalizedRoleId, normalizedScope];

      return executeWithDeadlockRetry({
        operation: 'deletePlatformRoleCatalogEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const rows = await tx.query(
              `
                SELECT role_id,
                       tenant_id,
                       code,
                       name,
                       status,
                       scope,
                       is_system,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_roles
                WHERE ${whereClause}
                LIMIT 1
                FOR UPDATE
              `,
              lookupArgs
            );
            const existing = toPlatformRoleCatalogRecord(rows?.[0] || null);
            if (!existing) {
              return null;
            }

            await tx.query(
              `
                UPDATE platform_roles
                SET status = 'disabled',
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE role_id = ?
              `,
              [
                operatorUserId ? String(operatorUserId) : existing.updatedByUserId,
                existing.roleId
              ]
            );

            const updatedRows = await tx.query(
              `
                SELECT role_id,
                       tenant_id,
                       code,
                       name,
                       status,
                       scope,
                       is_system,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_roles
                WHERE role_id = ?
                LIMIT 1
              `,
              [existing.roleId]
            );
            const deletedRole = toPlatformRoleCatalogRecord(updatedRows?.[0] || null);
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
                  tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.role.catalog.deleted',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'role',
                  targetId: normalizedRoleId,
                  result: 'success',
                  beforeState: {
                    code: normalizeAuditStringOrNull(existing.code, 64),
                    name: normalizeAuditStringOrNull(existing.name, 128),
                    status: normalizePlatformRoleCatalogStatus(existing.status || 'disabled')
                  },
                  afterState: {
                    status: normalizePlatformRoleCatalogStatus(deletedRole?.status || 'disabled')
                  },
                  metadata: {
                    scope: normalizedScope
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error('platform role delete audit write failed');
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...deletedRole,
              auditRecorded
            };
          })
      });
    },

    createUserByPhone: async ({ phone, passwordHash, status = 'active' }) => {
      const normalizedPhone = String(phone || '').trim();
      const normalizedPasswordHash = String(passwordHash || '').trim();
      if (!normalizedPhone || !normalizedPasswordHash) {
        throw new Error('createUserByPhone requires phone and passwordHash');
      }
      const normalizedStatus = String(status || 'active').trim().toLowerCase() || 'active';
      const userId = randomUUID();
      try {
        await dbClient.query(
          `
            INSERT INTO iam_users (id, phone, password_hash, status, session_version)
            VALUES (?, ?, ?, ?, 1)
          `,
          [userId, normalizedPhone, normalizedPasswordHash, normalizedStatus]
        );
      } catch (error) {
        if (isDuplicateEntryError(error)) {
          return null;
        }
        throw error;
      }
      const rows = await dbClient.query(
        `
          SELECT id, phone, password_hash, status, session_version
          FROM iam_users
          WHERE id = ?
          LIMIT 1
        `,
        [userId]
      );
      return toUserRecord(rows[0]);
    },

    createOrganizationWithOwner: async ({
      orgId = randomUUID(),
      orgName,
      ownerDisplayName = null,
      ownerUserId,
      operatorUserId,
      operatorSessionId = null,
      auditContext = null
    }) =>
      executeWithDeadlockRetry({
        operation: 'createOrganizationWithOwner',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedOrgId = String(orgId || '').trim() || randomUUID();
            const normalizedOrgName = normalizeOrgName(orgName);
            const normalizedOwnerDisplayName = normalizeOptionalTenantUserProfileField({
              value: ownerDisplayName,
              maxLength: MAX_TENANT_USER_DISPLAY_NAME_LENGTH
            });
            const normalizedOwnerUserId = String(ownerUserId || '').trim();
            const normalizedOperatorUserId = String(operatorUserId || '').trim();
            if (
              !normalizedOrgName
              || !normalizedOwnerUserId
              || !normalizedOperatorUserId
            ) {
              throw new Error(
                'createOrganizationWithOwner requires orgName, ownerUserId, and operatorUserId'
              );
            }

            const insertOrgResult = await tx.query(
              `
                INSERT INTO tenants (id, name, owner_user_id, status, created_by_user_id)
                VALUES (?, ?, ?, 'active', ?)
              `,
              [
                normalizedOrgId,
                normalizedOrgName,
                normalizedOwnerUserId,
                normalizedOperatorUserId
              ]
            );
            if (Number(insertOrgResult?.affectedRows || 0) !== 1) {
              throw new Error('org-create-write-not-applied');
            }

            const normalizedTakeoverRoleId = toOwnerTransferTakeoverRoleId({
              orgId: normalizedOrgId
            });
            const normalizedTakeoverRoleCode = OWNER_TRANSFER_TAKEOVER_ROLE_CODE;
            const normalizedTakeoverRoleName = OWNER_TRANSFER_TAKEOVER_ROLE_NAME;
            const normalizedRequiredPermissionCodes = [
              ...OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES
            ];
            if (
              !normalizedTakeoverRoleId
              || !normalizedTakeoverRoleCode
              || !normalizedTakeoverRoleName
            ) {
              throw new Error('org-owner-takeover-role-invalid');
            }
            const ownerMembershipUpsertResult = await tx.query(
              `
                INSERT INTO tenant_memberships (
                  membership_id,
                  user_id,
                  tenant_id,
                  tenant_name,
                  status,
                  display_name,
                  department_name,
                  joined_at,
                  left_at
                )
                VALUES (?, ?, ?, ?, 'active', ?, NULL, CURRENT_TIMESTAMP(3), NULL)
                ON DUPLICATE KEY UPDATE
                  tenant_name = VALUES(tenant_name),
                  status = 'active',
                  display_name = CASE
                    WHEN VALUES(display_name) IS NULL THEN display_name
                    ELSE VALUES(display_name)
                  END,
                  left_at = NULL,
                  updated_at = CURRENT_TIMESTAMP(3)
              `,
              [
                randomUUID(),
                normalizedOwnerUserId,
                normalizedOrgId,
                normalizedOrgName,
                normalizedOwnerDisplayName
              ]
            );
            if (Number(ownerMembershipUpsertResult?.affectedRows || 0) <= 0) {
              throw new Error('org-owner-profile-write-not-applied');
            }

            let membershipRows = await tx.query(
              `
                SELECT membership_id,
                       user_id,
                       tenant_id,
                       status,
                       tenant_name,
                       can_view_user_management,
                       can_operate_user_management,
                       can_view_role_management,
                       can_operate_role_management,
                       joined_at,
                       left_at
                FROM tenant_memberships
                WHERE user_id = ? AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedOwnerUserId, normalizedOrgId]
            );
            let membershipRow = membershipRows?.[0] || null;
            if (!membershipRow) {
              throw new Error('org-owner-membership-missing');
            }
            const normalizedMembershipStatus = normalizeTenantUsershipStatusForRead(
              membershipRow.status
            );
            if (
              normalizedMembershipStatus !== 'active'
              && normalizedMembershipStatus !== 'disabled'
              && normalizedMembershipStatus !== 'left'
            ) {
              throw new Error('org-owner-membership-status-invalid');
            }
            if (normalizedMembershipStatus === 'left') {
              const previousMembershipId = String(
                membershipRow.membership_id || ''
              ).trim();
              await insertTenantUsershipHistoryTx({
                txClient: tx,
                row: {
                  ...membershipRow,
                  membership_id: previousMembershipId,
                  user_id: normalizedOwnerUserId,
                  tenant_id: normalizedOrgId
                },
                archivedReason: 'rejoin',
                archivedByUserId: normalizedOperatorUserId
              });
              await tx.query(
                `
                  DELETE FROM tenant_membership_roles
                  WHERE membership_id = ?
                `,
                [previousMembershipId]
              );
              const nextMembershipId = randomUUID();
              await tx.query(
                `
                  UPDATE tenant_memberships
                  SET membership_id = ?,
                      status = 'active',
                      can_view_user_management = 0,
                      can_operate_user_management = 0,
                      can_view_role_management = 0,
                      can_operate_role_management = 0,
                      display_name = CASE
                        WHEN ? IS NULL THEN display_name
                        ELSE ?
                      END,
                      joined_at = CURRENT_TIMESTAMP(3),
                      left_at = NULL,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE user_id = ? AND tenant_id = ?
                `,
                [
                  nextMembershipId,
                  normalizedOwnerDisplayName,
                  normalizedOwnerDisplayName,
                  normalizedOwnerUserId,
                  normalizedOrgId
                ]
              );
            } else if (normalizedMembershipStatus === 'disabled') {
              await tx.query(
                `
                  UPDATE tenant_memberships
                  SET status = 'active',
                      display_name = CASE
                        WHEN ? IS NULL THEN display_name
                        ELSE ?
                      END,
                      left_at = NULL,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE user_id = ? AND tenant_id = ?
                `,
                [
                  normalizedOwnerDisplayName,
                  normalizedOwnerDisplayName,
                  normalizedOwnerUserId,
                  normalizedOrgId
                ]
              );
            }
            membershipRows = await tx.query(
              `
                SELECT membership_id,
                       user_id,
                       tenant_id,
                       status,
                       tenant_name,
                       can_view_user_management,
                       can_operate_user_management,
                       can_view_role_management,
                       can_operate_role_management,
                       joined_at,
                       left_at
                FROM tenant_memberships
                WHERE user_id = ? AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedOwnerUserId, normalizedOrgId]
            );
            membershipRow = membershipRows?.[0] || null;
            const resolvedMembershipId = String(
              membershipRow?.membership_id || ''
            ).trim();
            if (
              !membershipRow
              || !resolvedMembershipId
              || String(membershipRow?.user_id || '').trim() !== normalizedOwnerUserId
            ) {
              throw new Error('org-owner-membership-resolution-failed');
            }

            await ensureTenantDomainAccessForUserTx({
              txClient: tx,
              userId: normalizedOwnerUserId,
              skipMembershipCheck: true
            });

            const createRoleInvalidError = () => {
              const roleInvalidError = new Error(
                'owner transfer takeover role definition invalid'
              );
              roleInvalidError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_INVALID';
              return roleInvalidError;
            };
            let roleRows = await tx.query(
              `
                SELECT role_id, tenant_id, code, status, scope
                FROM platform_roles
                WHERE role_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedTakeoverRoleId]
            );
            let roleRow = roleRows?.[0] || null;
            if (!roleRow) {
              try {
                await tx.query(
                  `
                    INSERT INTO platform_roles (
                      role_id,
                      tenant_id,
                      code,
                      code_normalized,
                      name,
                      status,
                      scope,
                      is_system,
                      created_by_user_id,
                      updated_by_user_id
                    )
                    VALUES (?, ?, ?, ?, ?, 'active', 'tenant', 1, ?, ?)
                  `,
                  [
                    normalizedTakeoverRoleId,
                    normalizedOrgId,
                    normalizedTakeoverRoleCode,
                    normalizedTakeoverRoleCode.toLowerCase(),
                    normalizedTakeoverRoleName,
                    normalizedOperatorUserId,
                    normalizedOperatorUserId
                  ]
                );
              } catch (error) {
                if (!isDuplicateEntryError(error)) {
                  throw error;
                }
                roleRows = await tx.query(
                  `
                    SELECT role_id, tenant_id, code, status, scope
                    FROM platform_roles
                    WHERE role_id = ?
                    LIMIT 1
                    FOR UPDATE
                  `,
                  [normalizedTakeoverRoleId]
                );
                roleRow = roleRows?.[0] || null;
                if (!roleRow) {
                  throw createRoleInvalidError();
                }
              }
            }
            if (!roleRow) {
              roleRow = {
                role_id: normalizedTakeoverRoleId,
                tenant_id: normalizedOrgId,
                code: normalizedTakeoverRoleCode,
                status: 'active',
                scope: 'tenant'
              };
            }
            const normalizedRoleScope = normalizePlatformRoleCatalogScope(
              roleRow.scope
            );
            const normalizedRoleTenantId = normalizePlatformRoleCatalogTenantId(
              roleRow.tenant_id
            );
            const normalizedRoleCode = normalizePlatformRoleCatalogCode(
              roleRow.code
            );
            if (
              normalizedRoleScope !== 'tenant'
              || normalizedRoleTenantId !== normalizedOrgId
            ) {
              throw createRoleInvalidError();
            }
            if (
              !normalizedRoleCode
              || normalizedRoleCode.toLowerCase() !== normalizedTakeoverRoleCode.toLowerCase()
            ) {
              throw createRoleInvalidError();
            }
            const normalizedRoleStatus = normalizePlatformRoleCatalogStatus(
              roleRow.status || 'disabled'
            );
            if (!isActiveLikeStatus(normalizedRoleStatus)) {
              await tx.query(
                `
                  UPDATE platform_roles
                  SET status = 'active',
                      updated_by_user_id = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE role_id = ?
                `,
                [normalizedOperatorUserId, normalizedTakeoverRoleId]
              );
            }

            const existingGrantRows = await tx.query(
              `
                SELECT permission_code
                FROM tenant_role_permission_grants
                WHERE role_id = ?
                ORDER BY permission_code ASC
                FOR UPDATE
              `,
              [normalizedTakeoverRoleId]
            );
            const normalizedGrantSet = new Set();
            for (const row of Array.isArray(existingGrantRows)
              ? existingGrantRows
              : []) {
              normalizedGrantSet.add(
                normalizeStrictTenantPermissionCodeFromGrantRow(
                  row?.permission_code,
                  'owner-transfer-takeover-role-grants-invalid'
                )
              );
            }
            for (const permissionCode of normalizedRequiredPermissionCodes) {
              if (normalizedGrantSet.has(permissionCode)) {
                continue;
              }
              await tx.query(
                `
                  INSERT INTO tenant_role_permission_grants (
                    role_id,
                    permission_code,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedTakeoverRoleId,
                  permissionCode,
                  normalizedOperatorUserId,
                  normalizedOperatorUserId
                ]
              );
              normalizedGrantSet.add(permissionCode);
            }

            const existingRoleIds = await listTenantUsershipRoleBindingsTx({
              txClient: tx,
              membershipId: resolvedMembershipId
            });
            const nextRoleIds = normalizeTenantUsershipRoleIds([
              ...existingRoleIds,
              normalizedTakeoverRoleId
            ]);
            if (nextRoleIds.length < 1) {
              const roleBindingError = new Error(
                'owner transfer takeover role binding invalid'
              );
              roleBindingError.code =
                'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_BINDINGS_INVALID';
              throw roleBindingError;
            }
            await tx.query(
              `
                DELETE FROM tenant_membership_roles
                WHERE membership_id = ?
              `,
              [resolvedMembershipId]
            );
            for (const roleId of nextRoleIds) {
              await tx.query(
                `
                  INSERT INTO tenant_membership_roles (
                    membership_id,
                    role_id,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  resolvedMembershipId,
                  roleId,
                  normalizedOperatorUserId,
                  normalizedOperatorUserId
                ]
              );
            }

            const syncResult = await syncTenantUsershipPermissionSnapshotInTx({
              txClient: tx,
              membershipId: resolvedMembershipId,
              tenantId: normalizedOrgId,
              roleIds: nextRoleIds,
              revokeReason: 'org-owner-bootstrap'
            });
            const syncReason = String(syncResult?.reason || 'unknown')
              .trim()
              .toLowerCase();
            if (syncReason !== 'ok') {
              const syncError = new Error(
                `owner transfer takeover sync failed: ${syncReason || 'unknown'}`
              );
              syncError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_SYNC_FAILED';
              syncError.syncReason = syncReason || 'unknown';
              throw syncError;
            }
            const effectivePermission = syncResult?.permission || {};
            if (
              !Boolean(effectivePermission.canViewUserManagement)
              || !Boolean(effectivePermission.canOperateUserManagement)
              || !Boolean(effectivePermission.canViewRoleManagement)
              || !Boolean(effectivePermission.canOperateRoleManagement)
            ) {
              const permissionInsufficientError = new Error(
                'owner transfer takeover permission insufficient'
              );
              permissionInsufficientError.code =
                'ERR_OWNER_TRANSFER_TAKEOVER_PERMISSION_INSUFFICIENT';
              throw permissionInsufficientError;
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'tenant',
                  tenantId: normalizedOrgId,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.org.create.succeeded',
                  actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'org',
                  targetId: normalizedOrgId,
                  result: 'success',
                  beforeState: null,
                  afterState: {
                    org_id: normalizedOrgId,
                    org_name: normalizeAuditStringOrNull(normalizedOrgName, 128),
                    owner_user_id: normalizedOwnerUserId
                  },
                  metadata: {
                    operator_user_id: normalizedOperatorUserId
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error('organization create audit write failed');
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }

            return {
              org_id: normalizedOrgId,
              owner_user_id: normalizedOwnerUserId,
              audit_recorded: auditRecorded
            };
          })
      }),

    findOrganizationById: async ({ orgId }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT id, name, owner_user_id, status, created_by_user_id
          FROM tenants
          WHERE BINARY id = ?
          LIMIT 1
        `,
        [normalizedOrgId]
      );
      const org = rows?.[0] || null;
      if (!org) {
        return null;
      }
      return {
        org_id: String(org.id || '').trim(),
        org_name: String(org.name || '').trim(),
        owner_user_id: String(org.owner_user_id || '').trim(),
        status: normalizeOrgStatus(org.status),
        created_by_user_id: org.created_by_user_id
          ? String(org.created_by_user_id).trim()
          : null
      };
    },

    acquireOwnerTransferLock: async ({
      orgId,
      timeoutSeconds = 0
    }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return false;
      }
      const lockName = toOwnerTransferLockName(normalizedOrgId);
      if (!lockName) {
        return false;
      }
      const rows = await dbClient.query(
        `
          SELECT GET_LOCK(?, ?) AS lock_acquired
        `,
        [
          lockName,
          normalizeOwnerTransferLockTimeoutSeconds(timeoutSeconds)
        ]
      );
      return Number(rows?.[0]?.lock_acquired || 0) === 1;
    },

    releaseOwnerTransferLock: async ({ orgId }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return false;
      }
      const lockName = toOwnerTransferLockName(normalizedOrgId);
      if (!lockName) {
        return false;
      }
      const rows = await dbClient.query(
        `
          SELECT RELEASE_LOCK(?) AS lock_released
        `,
        [lockName]
      );
      return Number(rows?.[0]?.lock_released || 0) === 1;
    },

    executeOwnerTransferTakeover: async ({
      requestId = 'request_id_unset',
      orgId,
      oldOwnerUserId,
      newOwnerUserId,
      operatorUserId = null,
      operatorSessionId = null,
      reason = null,
      takeoverRoleId = 'sys_admin',
      takeoverRoleCode = 'sys_admin',
      takeoverRoleName = '管理员',
      requiredPermissionCodes = [],
      auditContext = null
    } = {}) => {
      const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
      const normalizedOrgId = String(orgId || '').trim();
      const normalizedOldOwnerUserId = String(oldOwnerUserId || '').trim();
      const normalizedNewOwnerUserId = String(newOwnerUserId || '').trim();
      const normalizedOperatorUserId = operatorUserId === null || operatorUserId === undefined
        ? null
        : String(operatorUserId || '').trim() || null;
      const normalizedOperatorSessionId =
        operatorSessionId === null || operatorSessionId === undefined
          ? null
          : String(operatorSessionId || '').trim() || null;
      const normalizedReason = reason === null || reason === undefined
        ? null
        : String(reason || '').trim() || null;
      const normalizedTakeoverRoleId = normalizePlatformRoleCatalogRoleId(
        takeoverRoleId
      );
      const normalizedTakeoverRoleCode = String(takeoverRoleCode || '').trim();
      const normalizedTakeoverRoleName = String(takeoverRoleName || '').trim();
      const normalizedRequiredPermissionCodes = normalizeTenantPermissionCodes(
        requiredPermissionCodes
      );
      const missingRequiredPermissionCodes = [
        TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
        TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE
      ].filter(
        (permissionCode) =>
          !normalizedRequiredPermissionCodes.includes(permissionCode)
      );
      const hasUnsupportedRequiredPermissionCode = normalizedRequiredPermissionCodes.some(
        (permissionCode) =>
          !KNOWN_TENANT_PERMISSION_CODE_SET.has(permissionCode)
      );
      if (
        !normalizedOrgId
        || !normalizedOldOwnerUserId
        || !normalizedNewOwnerUserId
        || !normalizedTakeoverRoleId
        || !normalizedTakeoverRoleCode
        || !normalizedTakeoverRoleName
        || hasUnsupportedRequiredPermissionCode
        || missingRequiredPermissionCodes.length > 0
      ) {
        const invalidInputError = new Error(
          'executeOwnerTransferTakeover requires valid takeover payload'
        );
        invalidInputError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_INVALID_INPUT';
        throw invalidInputError;
      }

      return executeWithDeadlockRetry({
        operation: 'executeOwnerTransferTakeover',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const orgRows = await tx.query(
              `
                SELECT id, status, owner_user_id
                FROM tenants
                WHERE BINARY id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedOrgId]
            );
            const orgRow = orgRows?.[0] || null;
            if (!orgRow) {
              const orgNotFoundError = new Error(
                'owner transfer takeover organization not found'
              );
              orgNotFoundError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ORG_NOT_FOUND';
              throw orgNotFoundError;
            }

            const currentOwnerUserId = String(orgRow.owner_user_id || '').trim();
            const currentOrgStatus = normalizeOrgStatus(orgRow.status);
            if (!isActiveLikeStatus(currentOrgStatus)) {
              const orgInactiveError = new Error(
                'owner transfer takeover organization not active'
              );
              orgInactiveError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ORG_NOT_ACTIVE';
              throw orgInactiveError;
            }
            if (currentOwnerUserId !== normalizedOldOwnerUserId) {
              const preconditionFailedError = new Error(
                'owner transfer takeover precondition failed'
              );
              preconditionFailedError.code =
                'ERR_OWNER_TRANSFER_TAKEOVER_PRECONDITION_FAILED';
              throw preconditionFailedError;
            }
            if (normalizedNewOwnerUserId === normalizedOldOwnerUserId) {
              const sameOwnerError = new Error(
                'owner transfer takeover new owner equals current owner'
              );
              sameOwnerError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_SAME_OWNER';
              throw sameOwnerError;
            }

            const newOwnerRows = await tx.query(
              `
                SELECT id, status
                FROM iam_users
                WHERE BINARY id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedNewOwnerUserId]
            );
            const newOwnerRow = newOwnerRows?.[0] || null;
            if (!newOwnerRow) {
              const newOwnerNotFoundError = new Error(
                'owner transfer takeover new owner not found'
              );
              newOwnerNotFoundError.code =
                'ERR_OWNER_TRANSFER_TAKEOVER_NEW_OWNER_NOT_FOUND';
              throw newOwnerNotFoundError;
            }
            if (!isActiveLikeStatus(normalizeUserStatus(newOwnerRow.status))) {
              const newOwnerInactiveError = new Error(
                'owner transfer takeover new owner inactive'
              );
              newOwnerInactiveError.code =
                'ERR_OWNER_TRANSFER_TAKEOVER_NEW_OWNER_INACTIVE';
              throw newOwnerInactiveError;
            }

            const createRoleInvalidError = () => {
              const roleInvalidError = new Error(
                'owner transfer takeover role definition invalid'
              );
              roleInvalidError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_INVALID';
              return roleInvalidError;
            };

            let roleRows = await tx.query(
              `
                SELECT role_id, tenant_id, code, status, scope
                FROM platform_roles
                WHERE role_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedTakeoverRoleId]
            );
            let roleRow = roleRows?.[0] || null;
            if (!roleRow) {
              try {
                await tx.query(
                  `
                    INSERT INTO platform_roles (
                      role_id,
                      tenant_id,
                      code,
                      code_normalized,
                      name,
                      status,
                      scope,
                      is_system,
                      created_by_user_id,
                      updated_by_user_id
                    )
                    VALUES (?, ?, ?, ?, ?, 'active', 'tenant', 1, ?, ?)
                  `,
                  [
                    normalizedTakeoverRoleId,
                    normalizedOrgId,
                    normalizedTakeoverRoleCode,
                    normalizedTakeoverRoleCode.toLowerCase(),
                    normalizedTakeoverRoleName,
                    normalizedOperatorUserId,
                    normalizedOperatorUserId
                  ]
                );
              } catch (error) {
                if (!isDuplicateEntryError(error)) {
                  throw error;
                }
                roleRows = await tx.query(
                  `
                    SELECT role_id, tenant_id, code, status, scope
                    FROM platform_roles
                    WHERE role_id = ?
                    LIMIT 1
                    FOR UPDATE
                  `,
                  [normalizedTakeoverRoleId]
                );
                roleRow = roleRows?.[0] || null;
                if (!roleRow) {
                  throw createRoleInvalidError();
                }
              }
            }
            if (!roleRow) {
              roleRow = {
                role_id: normalizedTakeoverRoleId,
                tenant_id: normalizedOrgId,
                code: normalizedTakeoverRoleCode,
                status: 'active',
                scope: 'tenant'
              };
            }
            const normalizedRoleScope = normalizePlatformRoleCatalogScope(
              roleRow.scope
            );
            const normalizedRoleTenantId = normalizePlatformRoleCatalogTenantId(
              roleRow.tenant_id
            );
            const normalizedRoleCode = normalizePlatformRoleCatalogCode(
              roleRow.code
            );
            if (
              normalizedRoleScope !== 'tenant'
              || normalizedRoleTenantId !== normalizedOrgId
            ) {
              throw createRoleInvalidError();
            }
            if (
              !normalizedRoleCode
              || normalizedRoleCode.toLowerCase()
              !== normalizedTakeoverRoleCode.toLowerCase()
            ) {
              throw createRoleInvalidError();
            }
            const normalizedRoleStatus = normalizePlatformRoleCatalogStatus(
              roleRow.status || 'disabled'
            );
            if (!isActiveLikeStatus(normalizedRoleStatus)) {
              await tx.query(
                `
                  UPDATE platform_roles
                  SET status = 'active',
                      updated_by_user_id = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE role_id = ?
                `,
                [normalizedOperatorUserId, normalizedTakeoverRoleId]
              );
            }

            const existingGrantRows = await tx.query(
              `
                SELECT permission_code
                FROM tenant_role_permission_grants
                WHERE role_id = ?
                ORDER BY permission_code ASC
                FOR UPDATE
              `,
              [normalizedTakeoverRoleId]
            );
            const normalizedGrantSet = new Set();
            for (const row of Array.isArray(existingGrantRows)
              ? existingGrantRows
              : []) {
              normalizedGrantSet.add(
                normalizeStrictTenantPermissionCodeFromGrantRow(
                  row?.permission_code,
                  'owner-transfer-takeover-role-grants-invalid'
                )
              );
            }
            for (const permissionCode of normalizedRequiredPermissionCodes) {
              if (normalizedGrantSet.has(permissionCode)) {
                continue;
              }
              await tx.query(
                `
                  INSERT INTO tenant_role_permission_grants (
                    role_id,
                    permission_code,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedTakeoverRoleId,
                  permissionCode,
                  normalizedOperatorUserId,
                  normalizedOperatorUserId
                ]
              );
              normalizedGrantSet.add(permissionCode);
            }

            let membershipRows = await tx.query(
              `
                SELECT membership_id,
                       user_id,
                       tenant_id,
                       status,
                       tenant_name,
                       can_view_user_management,
                       can_operate_user_management,
                       can_view_role_management,
                       can_operate_role_management,
                       joined_at,
                       left_at
                FROM tenant_memberships
                WHERE user_id = ? AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedNewOwnerUserId, normalizedOrgId]
            );
            let membershipRow = membershipRows?.[0] || null;
            let resolvedMembershipId = String(
              membershipRow?.membership_id || ''
            ).trim();
            if (!membershipRow) {
              const createdMembershipId = randomUUID();
              let insertedMembership = null;
              try {
                insertedMembership = await tx.query(
                  `
                    INSERT INTO tenant_memberships (
                      membership_id,
                      user_id,
                      tenant_id,
                      tenant_name,
                      status,
                      joined_at,
                      left_at
                    )
                    VALUES (?, ?, ?, ?, 'active', CURRENT_TIMESTAMP(3), NULL)
                  `,
                  [
                    createdMembershipId,
                    normalizedNewOwnerUserId,
                    normalizedOrgId,
                    null
                  ]
                );
              } catch (error) {
                if (!isDuplicateEntryError(error)) {
                  throw error;
                }
              }
              if (
                insertedMembership
                && Number(insertedMembership?.affectedRows || 0) !== 1
              ) {
                const membershipCreateError = new Error(
                  'owner transfer takeover membership write not applied'
                );
                membershipCreateError.code =
                  'ERR_OWNER_TRANSFER_TAKEOVER_MEMBERSHIP_WRITE_NOT_APPLIED';
                throw membershipCreateError;
              }
              membershipRows = await tx.query(
                `
                  SELECT membership_id,
                         user_id,
                         tenant_id,
                         status,
                         tenant_name,
                         can_view_user_management,
                         can_operate_user_management,
                         can_view_role_management,
                         can_operate_role_management,
                         joined_at,
                         left_at
                  FROM tenant_memberships
                  WHERE user_id = ? AND tenant_id = ?
                  LIMIT 1
                  FOR UPDATE
                `,
                [normalizedNewOwnerUserId, normalizedOrgId]
              );
              membershipRow = membershipRows?.[0] || null;
            } else {
              const normalizedMembershipStatus = normalizeTenantUsershipStatusForRead(
                membershipRow.status
              );
              if (
                normalizedMembershipStatus !== 'active'
                && normalizedMembershipStatus !== 'disabled'
                && normalizedMembershipStatus !== 'left'
              ) {
                const membershipInvalidError = new Error(
                  'owner transfer takeover membership status invalid'
                );
                membershipInvalidError.code =
                  'ERR_OWNER_TRANSFER_TAKEOVER_MEMBERSHIP_INVALID';
                throw membershipInvalidError;
              }
              if (normalizedMembershipStatus === 'left') {
                const previousMembershipId = String(
                  membershipRow.membership_id || ''
                ).trim();
                await insertTenantUsershipHistoryTx({
                  txClient: tx,
                  row: {
                    ...membershipRow,
                    membership_id: previousMembershipId,
                    user_id: normalizedNewOwnerUserId,
                    tenant_id: normalizedOrgId
                  },
                  archivedReason: 'rejoin',
                  archivedByUserId: normalizedOperatorUserId
                });
                await tx.query(
                  `
                    DELETE FROM tenant_membership_roles
                    WHERE membership_id = ?
                  `,
                  [previousMembershipId]
                );
                const nextMembershipId = randomUUID();
                await tx.query(
                  `
                    UPDATE tenant_memberships
                    SET membership_id = ?,
                        status = 'active',
                        can_view_user_management = 0,
                        can_operate_user_management = 0,
                        can_view_role_management = 0,
                        can_operate_role_management = 0,
                        joined_at = CURRENT_TIMESTAMP(3),
                        left_at = NULL,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE user_id = ? AND tenant_id = ?
                  `,
                  [
                    nextMembershipId,
                    normalizedNewOwnerUserId,
                    normalizedOrgId
                  ]
                );
              } else if (normalizedMembershipStatus === 'disabled') {
                await tx.query(
                  `
                    UPDATE tenant_memberships
                    SET status = 'active',
                        left_at = NULL,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE user_id = ? AND tenant_id = ?
                  `,
                  [normalizedNewOwnerUserId, normalizedOrgId]
                );
              }
              membershipRows = await tx.query(
                `
                  SELECT membership_id,
                         user_id,
                         tenant_id,
                         status,
                         tenant_name,
                         can_view_user_management,
                         can_operate_user_management,
                         can_view_role_management,
                         can_operate_role_management,
                         joined_at,
                         left_at
                  FROM tenant_memberships
                  WHERE user_id = ? AND tenant_id = ?
                  LIMIT 1
                  FOR UPDATE
                `,
                [normalizedNewOwnerUserId, normalizedOrgId]
              );
              membershipRow = membershipRows?.[0] || null;
            }

            resolvedMembershipId = String(
              membershipRow?.membership_id || ''
            ).trim();
            if (
              !membershipRow
              || !resolvedMembershipId
              || String(membershipRow?.user_id || '').trim()
              !== normalizedNewOwnerUserId
            ) {
              const membershipResolveError = new Error(
                'owner transfer takeover membership resolution failed'
              );
              membershipResolveError.code =
                'ERR_OWNER_TRANSFER_TAKEOVER_MEMBERSHIP_INVALID';
              throw membershipResolveError;
            }

            await ensureTenantDomainAccessForUserTx({
              txClient: tx,
              userId: normalizedNewOwnerUserId,
              skipMembershipCheck: true
            });

            const ownerSwitchResult = await tx.query(
              `
                UPDATE tenants
                SET owner_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE BINARY id = ?
              `,
              [normalizedNewOwnerUserId, normalizedOrgId]
            );
            if (Number(ownerSwitchResult?.affectedRows || 0) !== 1) {
              const ownerSwitchError = new Error(
                'owner transfer takeover owner switch write not applied'
              );
              ownerSwitchError.code =
                'ERR_OWNER_TRANSFER_TAKEOVER_OWNER_SWITCH_NOT_APPLIED';
              throw ownerSwitchError;
            }

            const existingRoleIds = await listTenantUsershipRoleBindingsTx({
              txClient: tx,
              membershipId: resolvedMembershipId
            });
            const nextRoleIds = normalizeTenantUsershipRoleIds([
              ...existingRoleIds,
              normalizedTakeoverRoleId
            ]);
            if (nextRoleIds.length < 1) {
              const roleBindingError = new Error(
                'owner transfer takeover role binding invalid'
              );
              roleBindingError.code =
                'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_BINDINGS_INVALID';
              throw roleBindingError;
            }
            await tx.query(
              `
                DELETE FROM tenant_membership_roles
                WHERE membership_id = ?
              `,
              [resolvedMembershipId]
            );
            for (const roleId of nextRoleIds) {
              await tx.query(
                `
                  INSERT INTO tenant_membership_roles (
                    membership_id,
                    role_id,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  resolvedMembershipId,
                  roleId,
                  normalizedOperatorUserId,
                  normalizedOperatorUserId
                ]
              );
            }

            const syncResult = await syncTenantUsershipPermissionSnapshotInTx({
              txClient: tx,
              membershipId: resolvedMembershipId,
              tenantId: normalizedOrgId,
              roleIds: nextRoleIds,
              revokeReason: 'owner-transfer-takeover'
            });
            const syncReason = String(syncResult?.reason || 'unknown')
              .trim()
              .toLowerCase();
            if (syncReason !== 'ok') {
              const syncError = new Error(
                `owner transfer takeover sync failed: ${syncReason || 'unknown'}`
              );
              syncError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_SYNC_FAILED';
              syncError.syncReason = syncReason || 'unknown';
              throw syncError;
            }

            const effectivePermission = syncResult?.permission || {};
            if (
              !Boolean(effectivePermission.canViewUserManagement)
              || !Boolean(effectivePermission.canOperateUserManagement)
              || !Boolean(effectivePermission.canViewRoleManagement)
              || !Boolean(effectivePermission.canOperateRoleManagement)
            ) {
              const permissionInsufficientError = new Error(
                'owner transfer takeover permission insufficient'
              );
              permissionInsufficientError.code =
                'ERR_OWNER_TRANSFER_TAKEOVER_PERMISSION_INSUFFICIENT';
              throw permissionInsufficientError;
            }

            const resolvedPermissionCodes = [...normalizedGrantSet]
              .filter((permissionCode) =>
                KNOWN_TENANT_PERMISSION_CODE_SET.has(permissionCode)
              )
              .sort((left, right) => left.localeCompare(right));
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'tenant',
                  tenantId: normalizedOrgId,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.org.owner_transfer.executed',
                  actorUserId: auditContext.actorUserId,
                  actorSessionId: auditContext.actorSessionId,
                  targetType: 'org',
                  targetId: normalizedOrgId,
                  result: 'success',
                  beforeState: {
                    owner_user_id: normalizedOldOwnerUserId
                  },
                  afterState: {
                    owner_user_id: normalizedNewOwnerUserId
                  },
                  metadata: {
                    old_owner_user_id: normalizedOldOwnerUserId,
                    new_owner_user_id: normalizedNewOwnerUserId,
                    reason:
                      auditContext.reason === null || auditContext.reason === undefined
                        ? null
                        : String(auditContext.reason).trim() || null
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'owner transfer takeover audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              org_id: normalizedOrgId,
              old_owner_user_id: normalizedOldOwnerUserId,
              new_owner_user_id: normalizedNewOwnerUserId,
              membership_id: resolvedMembershipId,
              role_ids: nextRoleIds,
              permission_codes: resolvedPermissionCodes,
              audit_recorded: auditRecorded
            };
          })
      });
    },

    updateOrganizationStatus: async ({
      orgId,
      nextStatus,
      operatorUserId,
      auditContext = null
    }) =>
      executeWithDeadlockRetry({
        operation: 'updateOrganizationStatus',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedOrgId = String(orgId || '').trim();
            const normalizedNextStatus = normalizeOrgStatus(nextStatus);
            const normalizedOperatorUserId = String(operatorUserId || '').trim();
            if (
              !normalizedOrgId
              || !normalizedOperatorUserId
              || !VALID_ORG_STATUS.has(normalizedNextStatus)
            ) {
              throw new Error(
                'updateOrganizationStatus requires orgId, nextStatus, and operatorUserId'
              );
            }

            const orgRows = await tx.query(
              `
                SELECT id, status, owner_user_id
                FROM tenants
                WHERE BINARY id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedOrgId]
            );
            const org = orgRows?.[0] || null;
            if (!org) {
              return null;
            }

            const previousStatus = normalizeOrgStatus(org.status);
            let affectedMembershipCount = 0;
            let affectedRoleCount = 0;
            let affectedRoleBindingCount = 0;
            let revokedSessionCount = 0;
            let revokedRefreshTokenCount = 0;
            if (previousStatus !== normalizedNextStatus) {
              const updateResult = await tx.query(
                `
                  UPDATE tenants
                  SET status = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE BINARY id = ? AND status <> ?
                `,
                [normalizedNextStatus, normalizedOrgId, normalizedNextStatus]
              );
              if (Number(updateResult?.affectedRows || 0) !== 1) {
                throw new Error('org-status-write-not-applied');
              }

              if (normalizedNextStatus === 'disabled') {
                const affectedMembershipUserIds = new Set();
                const affectedUserIds = new Set();

                const tenantUsershipRows = await tx.query(
                  `
                    SELECT membership_id, user_id, status
                    FROM tenant_memberships
                    WHERE tenant_id = ?
                    FOR UPDATE
                  `,
                  [normalizedOrgId]
                );
                const activeTenantUsershipUserIds = (Array.isArray(tenantUsershipRows)
                  ? tenantUsershipRows
                  : [])
                  .filter((row) =>
                    isActiveLikeStatus(
                      normalizeTenantUsershipStatusForRead(row?.status)
                    )
                  )
                  .map((row) => String(row?.user_id || '').trim())
                  .filter((userId) => userId.length > 0);
                for (const activeTenantUsershipUserId of activeTenantUsershipUserIds) {
                  affectedMembershipUserIds.add(activeTenantUsershipUserId);
                  affectedUserIds.add(activeTenantUsershipUserId);
                }
                await tx.query(
                  `
                    UPDATE tenant_memberships
                    SET status = 'disabled',
                        can_view_user_management = 0,
                        can_operate_user_management = 0,
                        can_view_role_management = 0,
                        can_operate_role_management = 0,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE tenant_id = ?
                      AND status IN ('active', 'enabled')
                  `,
                  [normalizedOrgId]
                );
                const disableTenantRolesResult = await tx.query(
                  `
                    UPDATE platform_roles
                    SET status = 'disabled',
                        updated_by_user_id = ?,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE scope = 'tenant'
                      AND tenant_id = ?
                      AND status IN ('active', 'enabled')
                  `,
                  [normalizedOperatorUserId, normalizedOrgId]
                );
                const deleteTenantRoleBindingsResult = await tx.query(
                  `
                    DELETE amr
                    FROM tenant_membership_roles amr
                    INNER JOIN tenant_memberships ut
                      ON ut.membership_id = amr.membership_id
                    WHERE ut.tenant_id = ?
                  `,
                  [normalizedOrgId]
                );
                const ownerUserId = String(org.owner_user_id || '').trim();
                if (ownerUserId.length > 0) {
                  affectedUserIds.add(ownerUserId);
                }
                affectedMembershipCount = affectedMembershipUserIds.size;
                affectedRoleCount = Number(
                  disableTenantRolesResult?.affectedRows || 0
                );
                affectedRoleBindingCount = Number(
                  deleteTenantRoleBindingsResult?.affectedRows || 0
                );
                for (const affectedUserId of affectedUserIds) {
                  const revokeSessionsResult = await tx.query(
                    `
                      UPDATE auth_sessions
                      SET status = 'revoked',
                          revoked_reason = ?,
                          updated_at = CURRENT_TIMESTAMP(3)
                      WHERE user_id = ?
                        AND entry_domain = 'tenant'
                        AND active_tenant_id = ?
                        AND status = 'active'
                    `,
                    ['org-status-changed', affectedUserId, normalizedOrgId]
                  );
                  revokedSessionCount += Number(
                    revokeSessionsResult?.affectedRows || 0
                  );
                  const revokeRefreshTokensResult = await tx.query(
                    `
                      UPDATE auth_refresh_tokens
                      SET status = 'revoked',
                          updated_at = CURRENT_TIMESTAMP(3)
                      WHERE status = 'active'
                        AND session_id IN (
                          SELECT session_id
                          FROM auth_sessions
                          WHERE user_id = ?
                            AND entry_domain = 'tenant'
                            AND active_tenant_id = ?
                        )
                    `,
                    [affectedUserId, normalizedOrgId]
                  );
                  revokedRefreshTokenCount += Number(
                    revokeRefreshTokensResult?.affectedRows || 0
                  );
                  await removeTenantDomainAccessForUserTx({
                    txClient: tx,
                    userId: affectedUserId
                  });
                }
              }
            }

            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              const normalizedAuditReason =
                auditContext.reason === null || auditContext.reason === undefined
                  ? null
                  : String(auditContext.reason).trim() || null;
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'tenant',
                  tenantId: normalizedOrgId,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.org.status.updated',
                  actorUserId: auditContext.actorUserId,
                  actorSessionId: auditContext.actorSessionId,
                  targetType: 'org',
                  targetId: normalizedOrgId,
                  result: 'success',
                  beforeState: {
                    status: previousStatus
                  },
                  afterState: {
                    status: normalizedNextStatus
                  },
                  metadata: {
                    reason: normalizedAuditReason,
                    affected_membership_count: affectedMembershipCount,
                    affected_role_count: affectedRoleCount,
                    affected_role_binding_count: affectedRoleBindingCount,
                    revoked_session_count: revokedSessionCount,
                    revoked_refresh_token_count: revokedRefreshTokenCount
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error('organization status audit write failed');
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              org_id: normalizedOrgId,
              previous_status: previousStatus,
              current_status: normalizedNextStatus,
              affected_membership_count: affectedMembershipCount,
              affected_role_count: affectedRoleCount,
              affected_role_binding_count: affectedRoleBindingCount,
              revoked_session_count: revokedSessionCount,
              revoked_refresh_token_count: revokedRefreshTokenCount,
              audit_recorded: auditRecorded
            };
          })
      }),

    updatePlatformUserStatus: async ({
      userId,
      nextStatus,
      operatorUserId,
      auditContext = null
    }) =>
      executeWithDeadlockRetry({
        operation: 'updatePlatformUserStatus',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedUserId = String(userId || '').trim();
            const normalizedNextStatus = normalizeOrgStatus(nextStatus);
            const normalizedOperatorUserId = String(operatorUserId || '').trim();
            if (
              !normalizedUserId
              || !normalizedOperatorUserId
              || !VALID_PLATFORM_USER_STATUS.has(normalizedNextStatus)
            ) {
              throw new Error(
                'updatePlatformUserStatus requires userId, nextStatus, and operatorUserId'
              );
            }

            const userRows = await tx.query(
              `
                SELECT u.id AS user_id,
                       pu.status AS platform_status
                FROM iam_users u
                INNER JOIN platform_users pu
                  ON pu.user_id = u.id
                WHERE u.id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedUserId]
            );
            const user = userRows?.[0] || null;
            if (!user) {
              return null;
            }

            const previousStatus = normalizeOrgStatus(user.platform_status);
            if (!VALID_PLATFORM_USER_STATUS.has(previousStatus)) {
              throw new Error('platform-user-status-read-invalid');
            }
            let auditRecorded = false;
            if (previousStatus !== normalizedNextStatus) {
              const updateResult = await tx.query(
                `
                  UPDATE platform_users
                  SET status = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE user_id = ?
                    AND status <> ?
                `,
                [normalizedNextStatus, normalizedUserId, normalizedNextStatus]
              );
              if (Number(updateResult?.affectedRows || 0) !== 1) {
                throw new Error('platform-user-status-write-not-applied');
              }

              if (normalizedNextStatus === 'disabled') {
                await tx.query(
                  `
                    UPDATE auth_sessions
                    SET status = 'revoked',
                        revoked_reason = ?,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE user_id = ?
                      AND entry_domain = 'platform'
                      AND status = 'active'
                  `,
                  ['platform-user-status-changed', normalizedUserId]
                );
                await tx.query(
                  `
                    UPDATE auth_refresh_tokens
                    SET status = 'revoked',
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE status = 'active'
                      AND session_id IN (
                        SELECT session_id
                        FROM auth_sessions
                        WHERE user_id = ?
                          AND entry_domain = 'platform'
                      )
                  `,
                  [normalizedUserId]
                );
              }
            }

            if (auditContext && typeof auditContext === 'object') {
              const normalizedAuditReason =
                auditContext.reason === null || auditContext.reason === undefined
                  ? null
                  : String(auditContext.reason).trim() || null;
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  tenantId: null,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.platform.user.status.updated',
                  actorUserId: auditContext.actorUserId,
                  actorSessionId: auditContext.actorSessionId,
                  targetType: 'user',
                  targetId: normalizedUserId,
                  result: 'success',
                  beforeState: {
                    status: previousStatus
                  },
                  afterState: {
                    status: normalizedNextStatus
                  },
                  metadata: {
                    reason: normalizedAuditReason
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform user status audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }

            return {
              user_id: normalizedUserId,
              previous_status: previousStatus,
              current_status: normalizedNextStatus,
              audit_recorded: auditRecorded
            };
          })
      }),

    softDeleteUser: async ({
      userId,
      operatorUserId,
      auditContext = null
    }) =>
      executeWithDeadlockRetry({
        operation: 'softDeleteUser',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedUserId = String(userId || '').trim();
            const normalizedOperatorUserId = String(operatorUserId || '').trim();
            if (!normalizedUserId || !normalizedOperatorUserId) {
              throw new Error('softDeleteUser requires userId and operatorUserId');
            }

            const userRows = await tx.query(
              `
                SELECT id AS user_id, status
                FROM iam_users
                WHERE BINARY id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedUserId]
            );
            const user = userRows?.[0] || null;
            if (!user) {
              return null;
            }

            const previousStatus = normalizeUserStatus(user.status);
            if (!VALID_PLATFORM_USER_STATUS.has(previousStatus)) {
              throw new Error('platform-user-soft-delete-status-read-invalid');
            }

            let revokedSessionCount = 0;
            let revokedRefreshTokenCount = 0;
            if (previousStatus !== 'disabled') {
              const updateUserResult = await tx.query(
                `
                  UPDATE iam_users
                  SET status = 'disabled',
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE BINARY id = ?
                    AND status <> 'disabled'
                `,
                [normalizedUserId]
              );
              if (Number(updateUserResult?.affectedRows || 0) !== 1) {
                throw new Error('platform-user-soft-delete-write-not-applied');
              }
            }

            await tx.query(
              `
                UPDATE tenant_memberships
                SET status = 'disabled',
                    can_view_user_management = 0,
                    can_operate_user_management = 0,
                    can_view_role_management = 0,
                    can_operate_role_management = 0,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE user_id = ?
                  AND status IN ('active', 'enabled')
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                UPDATE platform_user_roles
                SET status = 'disabled',
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE user_id = ?
                  AND status IN ('active', 'enabled')
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                UPDATE platform_users
                SET status = 'disabled',
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE user_id = ?
                  AND status IN ('active', 'enabled')
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE amr
                FROM tenant_membership_roles amr
                INNER JOIN tenant_memberships ut
                  ON ut.membership_id = amr.membership_id
                WHERE ut.user_id = ?
              `,
              [normalizedUserId]
            );

            const revokeSessionsResult = await tx.query(
              `
                UPDATE auth_sessions
                SET status = 'revoked',
                    revoked_reason = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE user_id = ?
                  AND status = 'active'
              `,
              ['user-soft-deleted', normalizedUserId]
            );
            revokedSessionCount = Number(revokeSessionsResult?.affectedRows || 0);

            const revokeRefreshTokensResult = await tx.query(
              `
                UPDATE auth_refresh_tokens
                SET status = 'revoked',
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE user_id = ?
                  AND status = 'active'
              `,
              [normalizedUserId]
            );
            revokedRefreshTokenCount = Number(
              revokeRefreshTokensResult?.affectedRows || 0
            );

            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  tenantId: null,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.platform.user.soft_deleted',
                  actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
                  actorSessionId: auditContext.actorSessionId,
                  targetType: 'user',
                  targetId: normalizedUserId,
                  result: 'success',
                  beforeState: {
                    status: previousStatus
                  },
                  afterState: {
                    status: 'disabled'
                  },
                  metadata: {
                    revoked_session_count: revokedSessionCount,
                    revoked_refresh_token_count: revokedRefreshTokenCount
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform user soft-delete audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }

            return {
              user_id: normalizedUserId,
              previous_status: previousStatus,
              current_status: 'disabled',
              revoked_session_count: revokedSessionCount,
              revoked_refresh_token_count: revokedRefreshTokenCount,
              audit_recorded: auditRecorded
            };
          })
      }),

    deleteUserById: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { deleted: false };
      }
      return executeWithDeadlockRetry({
        operation: 'deleteUserById',
        onExhausted: 'return-fallback',
        fallbackResult: { deleted: false },
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            await tx.query(
              `
                DELETE FROM auth_refresh_tokens
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE FROM auth_sessions
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE FROM platform_user_roles
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE FROM platform_users
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE FROM tenant_memberships
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            const result = await tx.query(
              `
                DELETE FROM iam_users
                WHERE id = ?
              `,
              [normalizedUserId]
            );
            return { deleted: Number(result?.affectedRows || 0) > 0 };
          })
      });
    },

    createTenantUsershipForUser: async ({ userId, tenantId, tenantName = null }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('createTenantUsershipForUser requires userId and tenantId');
      }
      const normalizedTenantName = tenantName === null || tenantName === undefined
        ? null
        : String(tenantName).trim() || null;
      return executeWithDeadlockRetry({
        operation: 'createTenantUsershipForUser',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const userRows = await tx.query(
              `
                SELECT id
                FROM iam_users
                WHERE id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedUserId]
            );
            if (!Array.isArray(userRows) || userRows.length === 0) {
              return { created: false };
            }

            const existingRows = await tx.query(
              `
                SELECT membership_id,
                       user_id,
                       tenant_id,
                       tenant_name,
                       status,
                       display_name,
                       department_name,
                       can_view_user_management,
                       can_operate_user_management,
                       can_view_role_management,
                       can_operate_role_management,
                       joined_at,
                       left_at
                FROM tenant_memberships
                WHERE user_id = ? AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedUserId, normalizedTenantId]
            );
            const existing = existingRows?.[0] || null;
            if (!existing) {
              const membershipId = randomUUID();
              let result;
              try {
                result = await tx.query(
                  `
                    INSERT INTO tenant_memberships (
                      membership_id,
                      user_id,
                      tenant_id,
                      tenant_name,
                      status,
                      display_name,
                      department_name,
                      joined_at,
                      left_at
                    )
                    VALUES (?, ?, ?, ?, 'active', NULL, NULL, CURRENT_TIMESTAMP(3), NULL)
                  `,
                  [
                    membershipId,
                    normalizedUserId,
                    normalizedTenantId,
                    normalizedTenantName
                  ]
                );
              } catch (error) {
                if (isDuplicateEntryError(error)) {
                  return { created: false };
                }
                throw error;
              }
              return { created: Number(result?.affectedRows || 0) > 0 };
            }

            const existingStatus = normalizeTenantUsershipStatusForRead(existing.status);
            if (!VALID_TENANT_MEMBERSHIP_STATUS.has(existingStatus)) {
              throw new Error(
                'createTenantUsershipForUser encountered unsupported existing status'
              );
            }
            if (existingStatus !== 'left') {
              return { created: false };
            }

            const previousMembershipId = String(existing.membership_id || '').trim();
            await insertTenantUsershipHistoryTx({
              txClient: tx,
              row: {
                ...existing,
                membership_id: previousMembershipId,
                user_id: normalizedUserId,
                tenant_id: normalizedTenantId
              },
              archivedReason: 'rejoin',
              archivedByUserId: null
            });

            await tx.query(
              `
                DELETE FROM tenant_membership_roles
                WHERE membership_id = ?
              `,
              [previousMembershipId]
            );

            const nextMembershipId = randomUUID();
            const updateResult = await tx.query(
              `
                UPDATE tenant_memberships
                SET membership_id = ?,
                    tenant_name = ?,
                    status = 'active',
                    can_view_user_management = 0,
                    can_operate_user_management = 0,
                    can_view_role_management = 0,
                    can_operate_role_management = 0,
                    joined_at = CURRENT_TIMESTAMP(3),
                    left_at = NULL,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE user_id = ? AND tenant_id = ?
              `,
              [
                nextMembershipId,
                normalizedTenantName,
                normalizedUserId,
                normalizedTenantId
              ]
            );
            return { created: Number(updateResult?.affectedRows || 0) > 0 };
          })
      });
    },

    removeTenantUsershipForUser: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('removeTenantUsershipForUser requires userId and tenantId');
      }
      const result = await dbClient.query(
        `
          DELETE FROM tenant_memberships
          WHERE user_id = ? AND tenant_id = ?
        `,
        [normalizedUserId, normalizedTenantId]
      );
      return { removed: Number(result?.affectedRows || 0) > 0 };
    },

    removeTenantDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { removed: false };
      }
      const tenantCountRows = await runTenantUsershipQuery({
        sqlWithOrgGuard: `
          SELECT COUNT(*) AS tenant_count
          FROM tenant_memberships ut
          LEFT JOIN tenants o ON o.id = ut.tenant_id
          WHERE ut.user_id = ?
            AND ut.status IN ('active', 'enabled')
            AND o.status IN ('active', 'enabled')
        `,
        sqlWithoutOrgGuard: `
          SELECT COUNT(*) AS tenant_count
          FROM tenant_memberships ut
          WHERE ut.user_id = ?
            AND ut.status IN ('active', 'enabled')
        `,
        params: [normalizedUserId]
      });
      const tenantCount = Number(tenantCountRows?.[0]?.tenant_count || 0);
      return { removed: tenantCount <= 0 };
    },

    createSession: repositoryMethods.createSession,

    findSessionById: repositoryMethods.findSessionById,

    updateSessionContext: repositoryMethods.updateSessionContext,

    findDomainAccessByUserId: repositoryMethods.findDomainAccessByUserId,

    ensureDefaultDomainAccessForUser: repositoryMethods.ensureDefaultDomainAccessForUser,

    ensureTenantDomainAccessForUser: repositoryMethods.ensureTenantDomainAccessForUser,

    findTenantPermissionByUserAndTenantId: repositoryMethods.findTenantPermissionByUserAndTenantId,

    listTenantOptionsByUserId: repositoryMethods.listTenantOptionsByUserId,

    findTenantUsershipByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT ut.membership_id,
                 ut.user_id,
                 ut.tenant_id,
                 ut.tenant_name,
                 ut.status,
                 ut.display_name,
                 ut.department_name,
                 ut.joined_at,
                 ut.left_at,
                 u.phone
          FROM tenant_memberships ut
          LEFT JOIN iam_users u ON u.id = ut.user_id
          WHERE ut.user_id = ? AND ut.tenant_id = ?
          LIMIT 1
        `,
        [normalizedUserId, normalizedTenantId]
      );
      const row = rows?.[0];
      if (!row) {
        return null;
      }
      return {
        membership_id: String(row.membership_id || '').trim(),
        user_id: String(row.user_id || '').trim(),
        tenant_id: String(row.tenant_id || '').trim(),
        tenant_name: row.tenant_name ? String(row.tenant_name) : null,
        phone: String(row.phone || ''),
        status: normalizeTenantUsershipStatusForRead(row.status),
        display_name: resolveOptionalTenantUserProfileField(row.display_name),
        department_name: resolveOptionalTenantUserProfileField(
          row.department_name
        ),
        joined_at: row.joined_at ? new Date(row.joined_at).toISOString() : null,
        left_at: row.left_at ? new Date(row.left_at).toISOString() : null
      };
    },

    findTenantUsershipByMembershipIdAndTenantId: async ({
      membershipId,
      tenantId
    }) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedMembershipId || !normalizedTenantId) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT ut.membership_id,
                 ut.user_id,
                 ut.tenant_id,
                 ut.tenant_name,
                 ut.status,
                 ut.display_name,
                 ut.department_name,
                 ut.joined_at,
                 ut.left_at,
                 u.phone
          FROM tenant_memberships ut
          LEFT JOIN iam_users u ON u.id = ut.user_id
          WHERE ut.membership_id = ? AND ut.tenant_id = ?
          LIMIT 1
        `,
        [normalizedMembershipId, normalizedTenantId]
      );
      const row = rows?.[0] || null;
      if (!row) {
        return null;
      }
      return {
        membership_id: String(row.membership_id || '').trim(),
        user_id: String(row.user_id || '').trim(),
        tenant_id: String(row.tenant_id || '').trim(),
        tenant_name: row.tenant_name ? String(row.tenant_name) : null,
        phone: String(row.phone || ''),
        status: normalizeTenantUsershipStatusForRead(row.status),
        display_name: resolveOptionalTenantUserProfileField(row.display_name),
        department_name: resolveOptionalTenantUserProfileField(
          row.department_name
        ),
        joined_at: row.joined_at ? new Date(row.joined_at).toISOString() : null,
        left_at: row.left_at ? new Date(row.left_at).toISOString() : null
      };
    },

    listTenantUsershipRoleBindings: async ({
      membershipId,
      tenantId
    } = {}) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedMembershipId || !normalizedTenantId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT mr.role_id
          FROM tenant_membership_roles mr
          JOIN tenant_memberships ut ON ut.membership_id = mr.membership_id
          WHERE mr.membership_id = ?
            AND ut.tenant_id = ?
          ORDER BY mr.role_id ASC
        `,
        [normalizedMembershipId, normalizedTenantId]
      );
      const normalizedRoleIds = [];
      const seenRoleIds = new Set();
      for (const row of Array.isArray(rows) ? rows : []) {
        const normalizedRoleId = normalizeStrictTenantUsershipRoleIdFromBindingRow(
          row?.role_id,
          'tenant-membership-role-bindings-invalid-role-id'
        );
        if (seenRoleIds.has(normalizedRoleId)) {
          throw createTenantUsershipRoleBindingDataError(
            'tenant-membership-role-bindings-duplicate-role-id'
          );
        }
        seenRoleIds.add(normalizedRoleId);
        normalizedRoleIds.push(normalizedRoleId);
      }
      return normalizedRoleIds.sort((left, right) => left.localeCompare(right));
    },

    replaceTenantUsershipRoleBindingsAndSyncSnapshot: async ({
      tenantId,
      membershipId,
      roleIds = [],
      operatorUserId = null,
      auditContext = null
    } = {}) => {
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedMembershipId = String(membershipId || '').trim();
      if (!normalizedTenantId || !normalizedMembershipId) {
        throw new Error(
          'replaceTenantUsershipRoleBindingsAndSyncSnapshot requires tenantId and membershipId'
        );
      }
      const normalizedRoleIds = normalizeTenantUsershipRoleIds(roleIds);
      return executeWithDeadlockRetry({
        operation: 'replaceTenantUsershipRoleBindingsAndSyncSnapshot',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const membershipRows = await tx.query(
              `
                SELECT membership_id,
                       user_id,
                       tenant_id,
                       status
                FROM tenant_memberships
                WHERE membership_id = ? AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedMembershipId, normalizedTenantId]
            );
            const membershipRow = membershipRows?.[0] || null;
            if (!membershipRow) {
              return null;
            }
            const normalizedMembershipStatus = normalizeTenantUsershipStatusForRead(
              membershipRow.status
            );
            if (!isActiveLikeStatus(normalizedMembershipStatus)) {
              const membershipStatusError = new Error(
                'tenant usership role bindings membership not active'
              );
              membershipStatusError.code =
                'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_MEMBERSHIP_NOT_ACTIVE';
              throw membershipStatusError;
            }
            const normalizedAffectedUserId =
              normalizeStrictTenantUsershipRoleBindingIdentity(
                membershipRow?.user_id,
                'tenant-membership-role-bindings-invalid-affected-user-id'
              );
            if (normalizedRoleIds.length > 0) {
              const rolePlaceholders = buildSqlInPlaceholders(
                normalizedRoleIds.length
              );
              const roleRows = await tx.query(
                `
                  SELECT role_id, status, scope, tenant_id
                  FROM platform_roles
                  WHERE role_id IN (${rolePlaceholders})
                  FOR UPDATE
                `,
                normalizedRoleIds
              );
              const roleRowsByRoleId = new Map();
              for (const row of Array.isArray(roleRows) ? roleRows : []) {
                const resolvedRoleId = normalizePlatformRoleCatalogRoleId(
                  row?.role_id
                );
                if (!resolvedRoleId || roleRowsByRoleId.has(resolvedRoleId)) {
                  continue;
                }
                roleRowsByRoleId.set(resolvedRoleId, row);
              }
              for (const roleId of normalizedRoleIds) {
                const roleRow = roleRowsByRoleId.get(roleId) || null;
                const roleScope = normalizePlatformRoleCatalogScope(roleRow?.scope);
                const roleTenantId = normalizePlatformRoleCatalogTenantId(
                  roleRow?.tenant_id
                );
                let roleStatus = 'disabled';
                try {
                  roleStatus = normalizePlatformRoleCatalogStatus(
                    roleRow?.status || 'disabled'
                  );
                } catch (_error) {}
                if (
                  !roleRow
                  || roleScope !== 'tenant'
                  || roleTenantId !== normalizedTenantId
                  || !isActiveLikeStatus(roleStatus)
                ) {
                  const roleValidationError = new Error(
                    'tenant usership role bindings role invalid'
                  );
                  roleValidationError.code =
                    'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_ROLE_INVALID';
                  roleValidationError.roleId = roleId;
                  throw roleValidationError;
                }
              }
            }
            const previousRoleIds = await listTenantUsershipRoleBindingsTx({
              txClient: tx,
              membershipId: normalizedMembershipId
            });

            await tx.query(
              `
                DELETE FROM tenant_membership_roles
                WHERE membership_id = ?
              `,
              [normalizedMembershipId]
            );

            for (const roleId of normalizedRoleIds) {
              await tx.query(
                `
                  INSERT INTO tenant_membership_roles (
                    membership_id,
                    role_id,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedMembershipId,
                  roleId,
                  operatorUserId ? String(operatorUserId) : null,
                  operatorUserId ? String(operatorUserId) : null
                ]
              );
            }

            const syncResult = await syncTenantUsershipPermissionSnapshotInTx({
              txClient: tx,
              membershipId: normalizedMembershipId,
              tenantId: normalizedTenantId,
              roleIds: normalizedRoleIds,
              revokeReason: 'tenant-membership-role-bindings-changed'
            });
            const syncReason = String(syncResult?.reason || 'unknown')
              .trim()
              .toLowerCase();
            if (syncReason !== 'ok') {
              const syncError = new Error(
                `tenant usership role bindings sync failed: ${syncReason || 'unknown'}`
              );
              syncError.code = 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_SYNC_FAILED';
              syncError.syncReason = syncReason || 'unknown';
              throw syncError;
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'tenant',
                  tenantId: normalizedTenantId,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.tenant_membership_roles.updated',
                  actorUserId: auditContext.actorUserId,
                  actorSessionId: auditContext.actorSessionId,
                  targetType: 'membership_role_bindings',
                  targetId: normalizedMembershipId,
                  result: 'success',
                  beforeState: {
                    role_ids: previousRoleIds
                  },
                  afterState: {
                    role_ids: [...normalizedRoleIds]
                  },
                  metadata: {
                    affected_user_count: 1
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'tenant usership role bindings audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }

            return {
              membershipId: normalizedMembershipId,
              roleIds: [...normalizedRoleIds],
              affectedUserIds: [normalizedAffectedUserId],
              affectedUserCount: 1,
              auditRecorded
            };
          })
      });
    },

    listTenantUsersByTenantId: async ({ tenantId, page = 1, pageSize = 50 }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedTenantId) {
        return [];
      }
      const normalizedPage = Number.parseInt(String(page || '1'), 10);
      const normalizedPageSize = Number.parseInt(String(pageSize || '50'), 10);
      const resolvedPage = Number.isFinite(normalizedPage) && normalizedPage > 0
        ? normalizedPage
        : 1;
      const resolvedPageSize = Number.isFinite(normalizedPageSize) && normalizedPageSize > 0
        ? Math.min(normalizedPageSize, 200)
        : 50;
      const offset = (resolvedPage - 1) * resolvedPageSize;

      const rows = await dbClient.query(
        `
          SELECT ut.membership_id,
                 ut.user_id,
                 ut.tenant_id,
                 ut.tenant_name,
                 ut.status,
                 ut.display_name,
                 ut.department_name,
                 ut.joined_at,
                 ut.left_at,
                 u.phone
          FROM tenant_memberships ut
          LEFT JOIN iam_users u ON u.id = ut.user_id
          WHERE ut.tenant_id = ?
          ORDER BY ut.joined_at DESC, ut.membership_id DESC
          LIMIT ? OFFSET ?
        `,
        [normalizedTenantId, resolvedPageSize, offset]
      );
      return (Array.isArray(rows) ? rows : []).map((row) => ({
        membership_id: String(row.membership_id || '').trim(),
        user_id: String(row.user_id || '').trim(),
        tenant_id: String(row.tenant_id || '').trim(),
        tenant_name: row.tenant_name ? String(row.tenant_name) : null,
        phone: String(row.phone || ''),
        status: normalizeTenantUsershipStatusForRead(row.status),
        display_name: resolveOptionalTenantUserProfileField(row.display_name),
        department_name: resolveOptionalTenantUserProfileField(
          row.department_name
        ),
        joined_at: row.joined_at ? new Date(row.joined_at).toISOString() : null,
        left_at: row.left_at ? new Date(row.left_at).toISOString() : null
      }));
    },

    updateTenantUsershipProfile: async ({
      membershipId,
      tenantId,
      displayName,
      departmentNameProvided = false,
      departmentName = null,
      operatorUserId = null
    }) =>
      executeWithDeadlockRetry({
        operation: 'updateTenantUsershipProfile',
        onExhausted: 'throw',
        execute: async () => {
          const normalizedMembershipId = String(membershipId || '').trim();
          const normalizedTenantId = String(tenantId || '').trim();
          const normalizedDisplayName = normalizeOptionalTenantUserProfileField({
            value: displayName,
            maxLength: MAX_TENANT_USER_DISPLAY_NAME_LENGTH
          });
          const normalizedOperatorUserId = String(operatorUserId || '').trim() || null;
          if (
            !normalizedMembershipId
            || !normalizedTenantId
            || normalizedDisplayName === null
          ) {
            throw new Error(
              'updateTenantUsershipProfile requires membershipId, tenantId and displayName'
            );
          }

          const shouldUpdateDepartmentName = departmentNameProvided === true;
          let normalizedDepartmentName = null;
          if (shouldUpdateDepartmentName) {
            if (departmentName === null) {
              normalizedDepartmentName = null;
            } else {
              normalizedDepartmentName = normalizeOptionalTenantUserProfileField({
                value: departmentName,
                maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
              });
              if (normalizedDepartmentName === null) {
                throw new Error('updateTenantUsershipProfile departmentName is invalid');
              }
            }
          }

          return dbClient.inTransaction(async (tx) => {
            const membershipRows = await tx.query(
              `
                SELECT ut.membership_id,
                       ut.department_name,
                       u.phone
                FROM tenant_memberships ut
                LEFT JOIN iam_users u ON u.id = ut.user_id
                WHERE ut.membership_id = ? AND ut.tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedMembershipId, normalizedTenantId]
            );
            const membershipRow = membershipRows?.[0] || null;
            if (!membershipRow) {
              return null;
            }
            if (!isStrictMainlandPhone(membershipRow.phone)) {
              const dependencyError = new Error(
                'updateTenantUsershipProfile dependency unavailable: user-profile-missing'
              );
              dependencyError.code =
                'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
              throw dependencyError;
            }
            if (
              !shouldUpdateDepartmentName
              && !isStrictOptionalTenantUserProfileField({
                value: membershipRow.department_name,
                maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
              })
            ) {
              const dependencyError = new Error(
                'updateTenantUsershipProfile dependency unavailable: membership-profile-invalid'
              );
              dependencyError.code =
                'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
              throw dependencyError;
            }

            const updateResult = await tx.query(
              `
                UPDATE tenant_memberships
                SET display_name = ?,
                    department_name = CASE
                      WHEN ? = 1 THEN ?
                      ELSE department_name
                    END,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE membership_id = ? AND tenant_id = ?
              `,
              [
                normalizedDisplayName,
                shouldUpdateDepartmentName ? 1 : 0,
                shouldUpdateDepartmentName ? normalizedDepartmentName : null,
                normalizedMembershipId,
                normalizedTenantId
              ]
            );
            if (Number(updateResult?.affectedRows || 0) !== 1) {
              return null;
            }

            const rows = await tx.query(
              `
                SELECT ut.membership_id,
                       ut.user_id,
                       ut.tenant_id,
                       ut.tenant_name,
                       ut.status,
                       ut.display_name,
                       ut.department_name,
                       ut.joined_at,
                       ut.left_at,
                       u.phone
                FROM tenant_memberships ut
                LEFT JOIN iam_users u ON u.id = ut.user_id
                WHERE ut.membership_id = ? AND ut.tenant_id = ?
                LIMIT 1
              `,
              [normalizedMembershipId, normalizedTenantId]
            );
            const row = rows?.[0] || null;
            if (!row) {
              return null;
            }
            if (!isStrictMainlandPhone(row.phone)) {
              const dependencyError = new Error(
                'updateTenantUsershipProfile dependency unavailable: user-profile-missing'
              );
              dependencyError.code =
                'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
              throw dependencyError;
            }
            if (!isStrictOptionalTenantUserProfileField({
              value: row.department_name,
              maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
            })) {
              const dependencyError = new Error(
                'updateTenantUsershipProfile dependency unavailable: membership-profile-invalid'
              );
              dependencyError.code =
                'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
              throw dependencyError;
            }
            return {
              membership_id: String(row.membership_id || '').trim(),
              user_id: String(row.user_id || '').trim(),
              tenant_id: String(row.tenant_id || '').trim(),
              tenant_name: row.tenant_name ? String(row.tenant_name) : null,
              phone: String(row.phone || ''),
              status: normalizeTenantUsershipStatusForRead(row.status),
              display_name: resolveOptionalTenantUserProfileField(
                row.display_name
              ),
              department_name: resolveOptionalTenantUserProfileField(
                row.department_name
              ),
              joined_at: row.joined_at ? new Date(row.joined_at).toISOString() : null,
              left_at: row.left_at ? new Date(row.left_at).toISOString() : null,
              updated_by_user_id: normalizedOperatorUserId
            };
          });
        }
      }),

    updateTenantUsershipStatus: async ({
      membershipId,
      tenantId,
      nextStatus,
      operatorUserId,
      reason = null,
      auditContext = null
    }) =>
      executeWithDeadlockRetry({
        operation: 'updateTenantUsershipStatus',
        onExhausted: 'throw',
        execute: async () => {
          const normalizedMembershipId = String(membershipId || '').trim();
          const normalizedTenantId = String(tenantId || '').trim();
          const normalizedNextStatus = normalizeTenantUsershipStatusForRead(nextStatus);
          const normalizedOperatorUserId = String(operatorUserId || '').trim();
          const normalizedReason = reason === null || reason === undefined
            ? null
            : String(reason).trim() || null;
          if (
            !normalizedMembershipId
            || !normalizedTenantId
            || !normalizedOperatorUserId
            || !VALID_TENANT_MEMBERSHIP_STATUS.has(normalizedNextStatus)
          ) {
            throw new Error(
              'updateTenantUsershipStatus requires membershipId, tenantId, nextStatus and operatorUserId'
            );
          }
          return dbClient.inTransaction(async (tx) => {
            const rows = await tx.query(
              `
                SELECT membership_id,
                       user_id,
                       tenant_id,
                       tenant_name,
                       status,
                       can_view_user_management,
                       can_operate_user_management,
                       can_view_role_management,
                       can_operate_role_management,
                       joined_at,
                       left_at
                FROM tenant_memberships
                WHERE membership_id = ? AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedMembershipId, normalizedTenantId]
            );
            const row = rows?.[0] || null;
            if (!row) {
              return null;
            }
            const previousStatus = normalizeTenantUsershipStatusForRead(row.status);
            if (!VALID_TENANT_MEMBERSHIP_STATUS.has(previousStatus)) {
              throw new Error(
                'updateTenantUsershipStatus encountered unsupported existing status'
              );
            }
            let finalMembershipId = String(row.membership_id || '').trim() || normalizedMembershipId;
            let auditRecorded = false;
            if (previousStatus !== normalizedNextStatus) {
              if (previousStatus === 'left' && normalizedNextStatus === 'active') {
                await insertTenantUsershipHistoryTx({
                  txClient: tx,
                  row,
                  archivedReason: normalizedReason || 'reactivate',
                  archivedByUserId: normalizedOperatorUserId
                });
                await tx.query(
                  `
                    DELETE FROM tenant_membership_roles
                    WHERE membership_id = ?
                  `,
                  [normalizedMembershipId]
                );
                finalMembershipId = randomUUID();
                await tx.query(
                  `
                    UPDATE tenant_memberships
                    SET membership_id = ?,
                        status = 'active',
                        can_view_user_management = 0,
                        can_operate_user_management = 0,
                        can_view_role_management = 0,
                        can_operate_role_management = 0,
                        left_at = NULL,
                        joined_at = CURRENT_TIMESTAMP(3),
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE membership_id = ? AND tenant_id = ?
                  `,
                  [finalMembershipId, normalizedMembershipId, normalizedTenantId]
                );
              } else {
                if (normalizedNextStatus === 'left') {
                  await insertTenantUsershipHistoryTx({
                    txClient: tx,
                    row,
                    archivedReason: normalizedReason || 'left',
                    archivedByUserId: normalizedOperatorUserId
                  });
                  await tx.query(
                    `
                      DELETE FROM tenant_membership_roles
                      WHERE membership_id = ?
                    `,
                    [finalMembershipId]
                  );
                }
                await tx.query(
                  `
                    UPDATE tenant_memberships
                    SET status = ?,
                        can_view_user_management = CASE WHEN ? = 'left' THEN 0 ELSE can_view_user_management END,
                        can_operate_user_management = CASE WHEN ? = 'left' THEN 0 ELSE can_operate_user_management END,
                        can_view_role_management = CASE WHEN ? = 'left' THEN 0 ELSE can_view_role_management END,
                        can_operate_role_management = CASE WHEN ? = 'left' THEN 0 ELSE can_operate_role_management END,
                        left_at = CASE
                          WHEN ? = 'left' THEN CURRENT_TIMESTAMP(3)
                          WHEN ? = 'active' THEN NULL
                          ELSE left_at
                        END,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE membership_id = ? AND tenant_id = ?
                  `,
                  [
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    finalMembershipId,
                    normalizedTenantId
                  ]
                );
              }

              if (normalizedNextStatus === 'active') {
                await syncTenantUsershipPermissionSnapshotInTx({
                  txClient: tx,
                  membershipId: finalMembershipId,
                  tenantId: normalizedTenantId,
                  roleIds: previousStatus === 'left' ? [] : null,
                  revokeReason: 'tenant-membership-status-changed'
                });
                await ensureTenantDomainAccessForUserTx({
                  txClient: tx,
                  userId: row.user_id
                });
              } else {
                await tx.query(
                  `
                    UPDATE auth_sessions
                    SET status = 'revoked',
                        revoked_reason = ?,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE user_id = ?
                      AND entry_domain = 'tenant'
                      AND active_tenant_id = ?
                      AND status = 'active'
                  `,
                  [
                    'tenant-membership-status-changed',
                    row.user_id,
                    normalizedTenantId
                  ]
                );
                await tx.query(
                  `
                    UPDATE auth_refresh_tokens
                    SET status = 'revoked',
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE status = 'active'
                      AND session_id IN (
                        SELECT session_id
                        FROM auth_sessions
                        WHERE user_id = ?
                          AND entry_domain = 'tenant'
                          AND active_tenant_id = ?
                      )
                  `,
                  [row.user_id, normalizedTenantId]
                );
                await removeTenantDomainAccessForUserTx({
                  txClient: tx,
                  userId: row.user_id
                });
              }
            }
            if (auditContext && typeof auditContext === 'object') {
              const normalizedAuditReason =
                auditContext.reason === null || auditContext.reason === undefined
                  ? null
                  : String(auditContext.reason).trim() || null;
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'tenant',
                  tenantId: normalizedTenantId,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.tenant.user.status.updated',
                  actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
                  actorSessionId: auditContext.actorSessionId,
                  targetType: 'membership',
                  targetId: finalMembershipId,
                  result: 'success',
                  beforeState: {
                    status: previousStatus
                  },
                  afterState: {
                    status: normalizedNextStatus
                  },
                  metadata: {
                    tenant_id: normalizedTenantId,
                    membership_id: finalMembershipId,
                    target_user_id: String(row.user_id || '').trim() || null,
                    previous_status: previousStatus,
                    current_status: normalizedNextStatus,
                    reason: normalizedAuditReason
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error('tenant usership status audit write failed');
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }

            return {
              membership_id: finalMembershipId,
              user_id: String(row.user_id || '').trim(),
              tenant_id: String(row.tenant_id || '').trim(),
              previous_status: previousStatus,
              current_status: normalizedNextStatus,
              audit_recorded: auditRecorded
            };
          });
        }
      }),

    hasAnyTenantRelationshipByUserId: repositoryMethods.hasAnyTenantRelationshipByUserId,

    findPlatformPermissionByUserId: repositoryMethods.findPlatformPermissionByUserId,

    hasPlatformPermissionByUserId: repositoryMethods.hasPlatformPermissionByUserId,

    syncPlatformPermissionSnapshotByUserId: repositoryMethods.syncPlatformPermissionSnapshotByUserId,

    replacePlatformRolesAndSyncSnapshot: async ({ userId, roles = [] }) =>
      replacePlatformRolesAndSyncSnapshot({
        userId,
        roles
      }),

    getPlatformDeadlockMetrics: () =>
      Object.fromEntries(
        [...deadlockMetricsByOperation.entries()].map(([operation, metrics]) => {
          const rates = toDeadlockRates(metrics);
          return [
            operation,
            {
              deadlockCount: Number(metrics.deadlockCount),
              retrySuccessCount: Number(metrics.retrySuccessCount),
              finalFailureCount: Number(metrics.finalFailureCount),
              retrySuccessRate: Number(rates.retrySuccessRate),
              finalFailureRate: Number(rates.finalFailureRate)
            }
          ];
        })
      ),

    revokeSession: repositoryMethods.revokeSession,

    revokeAllUserSessions: repositoryMethods.revokeAllUserSessions,

    createRefreshToken: repositoryMethods.createRefreshToken,

    findRefreshTokenByHash: repositoryMethods.findRefreshTokenByHash,

    markRefreshTokenStatus: repositoryMethods.markRefreshTokenStatus,

    linkRefreshRotation: repositoryMethods.linkRefreshRotation,

    rotateRefreshToken: repositoryMethods.rotateRefreshToken,

    updateUserPasswordAndBumpSessionVersion:
      repositoryMethods.updateUserPasswordAndBumpSessionVersion,

    updateUserPasswordAndRevokeSessions:
      repositoryMethods.updateUserPasswordAndRevokeSessions
  };
};

module.exports = { createMySqlAuthStore };

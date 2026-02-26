'use strict';

const { createHash } = require('node:crypto');
const {
  CONTROL_CHAR_PATTERN,
  MAINLAND_PHONE_PATTERN,
  MAX_PLATFORM_INTEGRATION_ID_LENGTH,
  OWNER_TRANSFER_LOCK_NAME_PREFIX,
  OWNER_TRANSFER_LOCK_TIMEOUT_SECONDS_MAX,
  OWNER_TRANSFER_TAKEOVER_ROLE_ID_DIGEST_LENGTH,
  OWNER_TRANSFER_TAKEOVER_ROLE_ID_PREFIX,
  PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS,
  VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS,
  VALID_TENANT_MEMBERSHIP_STATUS
} = require('./shared-mysql-auth-store-runtime-domain-constraint-constants');

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

module.exports = {
  normalizeUserStatus,
  normalizeOrgName,
  normalizeOrgStatus,
  normalizeTenantUsershipStatus,
  normalizeTenantUsershipStatusForRead,
  normalizeOptionalTenantUserProfileField,
  resolveOptionalTenantUserProfileField,
  normalizeRequiredPlatformUserProfileField,
  normalizeOptionalPlatformUserProfileField,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogTenantId,
  normalizePlatformRoleCatalogTenantIdForScope,
  normalizePlatformRoleCatalogRoleId,
  toOwnerTransferTakeoverRoleId,
  normalizePlatformRoleCatalogCode,
  normalizePlatformIntegrationId,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationCode,
  normalizePlatformIntegrationCodeKey,
  escapeSqlLikePattern,
  normalizePlatformIntegrationDirection,
  normalizePlatformIntegrationLifecycleStatus,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationContractStatus,
  normalizePlatformIntegrationContractEvaluationResult,
  normalizePlatformIntegrationContractSchemaChecksum,
  normalizePlatformIntegrationRecoveryId,
  normalizePlatformIntegrationRecoveryStatus,
  normalizePlatformIntegrationFreezeId,
  normalizePlatformIntegrationFreezeStatus,
  normalizePlatformIntegrationRecoveryIdempotencyKey,
  PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN,
  normalizePlatformIntegrationOptionalText,
  normalizeStoreIsoTimestamp,
  normalizePlatformIntegrationTimeoutMs,
  normalizePlatformIntegrationJsonForStorage,
  createPlatformIntegrationContractActivationBlockedError,
  isPlatformIntegrationLifecycleTransitionAllowed,
  createPlatformIntegrationLifecycleConflictError,
  createPlatformIntegrationRecoveryReplayConflictError,
  createPlatformIntegrationFreezeActiveConflictError,
  createPlatformIntegrationFreezeReleaseConflictError,
  normalizeOwnerTransferLockTimeoutSeconds,
  toOwnerTransferLockName,
  DEFAULT_DEADLOCK_FALLBACK_RESULT,
  isStrictMainlandPhone,
  isStrictOptionalTenantUserProfileField
};

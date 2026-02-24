const { createHash, randomUUID } = require('node:crypto');
const { normalizeTraceparent } = require('../../common/trace-context');
const {
  isRetryableDeliveryFailure,
  computeRetrySchedule
} = require('../integration');
const {
  KNOWN_PLATFORM_PERMISSION_CODES,
  KNOWN_TENANT_PERMISSION_CODES,
  TENANT_MEMBER_ADMIN_VIEW_PERMISSION_CODE,
  TENANT_MEMBER_ADMIN_OPERATE_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE,
  toPlatformPermissionSnapshotFromCodes,
  toTenantPermissionSnapshotFromCodes
} = require('./permission-catalog');

const createInMemoryAuthStore = ({
  seedUsers = [],
  hashPassword,
  faultInjector = null
} = {}) => {
  const usersByPhone = new Map();
  const usersById = new Map();
  const sessionsById = new Map();
  const refreshTokensByHash = new Map();
  const domainsByUserId = new Map();
  const platformDomainKnownByUserId = new Set();
  const tenantsByUserId = new Map();
  const platformProfilesByUserId = new Map();
  const platformRolesByUserId = new Map();
  const platformPermissionsByUserId = new Map();
  const platformRoleCatalogById = new Map();
  const platformRoleCatalogCodeIndex = new Map();
  const platformIntegrationCatalogById = new Map();
  const platformIntegrationCatalogCodeIndex = new Map();
  const platformIntegrationContractVersionsByKey = new Map();
  const platformIntegrationContractChecksById = new Map();
  const platformIntegrationRecoveryQueueByRecoveryId = new Map();
  const platformIntegrationRecoveryDedupIndex = new Map();
  const platformIntegrationFreezeById = new Map();
  let nextPlatformIntegrationContractVersionId = 1;
  let nextPlatformIntegrationContractCheckId = 1;
  const platformRolePermissionGrantsByRoleId = new Map();
  const tenantRolePermissionGrantsByRoleId = new Map();
  const tenantMembershipRolesByMembershipId = new Map();
  const systemSensitiveConfigsByKey = new Map();
  const orgsById = new Map();
  const tenantMembershipHistoryByPair = new Map();
  const ownerTransferLocksByOrgId = new Map();
  const orgIdByName = new Map();
  const membershipsByOrgId = new Map();
  const auditEvents = [];
  const AUDIT_EVENT_ALLOWED_DOMAINS = new Set(['platform', 'tenant']);
  const AUDIT_EVENT_ALLOWED_RESULTS = new Set(['success', 'rejected', 'failed']);
  const AUDIT_EVENT_REDACTION_KEY_PATTERN =
    /(password|token|secret|credential|private[_-]?key|access[_-]?key|api[_-]?key|signing[_-]?key)/i;
  const AUDIT_EVENT_REDACTION_COUNT_KEY_PATTERN = /_count$/i;
  const MAX_AUDIT_QUERY_PAGE_SIZE = 200;
  const VALID_PLATFORM_ROLE_FACT_STATUS = new Set(['active', 'enabled', 'disabled']);
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
  const MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH = 128;
  const MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH = 128;
  const MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH = 128;
  const MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH = 65535;
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
  const VALID_ORG_STATUS = new Set(['active', 'disabled']);
  const VALID_PLATFORM_USER_STATUS = new Set(['active', 'disabled']);
  const VALID_SYSTEM_SENSITIVE_CONFIG_STATUS = new Set(['active', 'disabled']);
  const ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS = new Set(['auth.default_password']);
  const VALID_TENANT_MEMBERSHIP_STATUS = new Set(['active', 'disabled', 'left']);
  const MAX_ORG_NAME_LENGTH = 128;
  const MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH = 64;
  const MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH = 128;
  const OWNER_TRANSFER_TAKEOVER_ROLE_ID_PREFIX = 'sys_admin__';
  const OWNER_TRANSFER_TAKEOVER_ROLE_ID_DIGEST_LENGTH = 24;
  const OWNER_TRANSFER_TAKEOVER_ROLE_CODE = 'sys_admin';
  const OWNER_TRANSFER_TAKEOVER_ROLE_NAME = 'sys_admin';
  const OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES = Object.freeze([
    TENANT_MEMBER_ADMIN_VIEW_PERMISSION_CODE,
    TENANT_MEMBER_ADMIN_OPERATE_PERMISSION_CODE
  ]);
  const MAX_PLATFORM_ROLE_CODE_LENGTH = 64;
  const MAX_PLATFORM_ROLE_NAME_LENGTH = 128;
  const invokeFaultInjector = (hookName, payload = {}) => {
    if (!faultInjector || typeof faultInjector !== 'object') {
      return;
    }
    const hook = faultInjector[hookName];
    if (typeof hook === 'function') {
      hook(payload);
    }
  };
  const KNOWN_PLATFORM_PERMISSION_CODE_SET = new Set(KNOWN_PLATFORM_PERMISSION_CODES);
  const KNOWN_TENANT_PERMISSION_CODE_SET = new Set(KNOWN_TENANT_PERMISSION_CODES);
  const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
  const ROLE_ID_ADDRESSABLE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
  const MAINLAND_PHONE_PATTERN = /^1\d{10}$/;
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
  const cloneSystemSensitiveConfigRecord = (record = null) =>
    record
      ? {
        configKey: record.configKey,
        encryptedValue: record.encryptedValue,
        version: Number(record.version),
        previousVersion: Number(record.previousVersion || 0),
        status: record.status,
        updatedByUserId: record.updatedByUserId,
        updatedAt: record.updatedAt,
        createdByUserId: record.createdByUserId,
        createdAt: record.createdAt
      }
      : null;

  const isActiveLikeStatus = (status) => {
    const normalizedStatus = String(status || 'active').trim().toLowerCase();
    return normalizedStatus === 'active' || normalizedStatus === 'enabled';
  };
  const normalizeOrgStatus = (status) => {
    const normalizedStatus = String(status || 'active').trim().toLowerCase();
    if (normalizedStatus === 'enabled') {
      return 'active';
    }
    return normalizedStatus;
  };
  const normalizeTenantMembershipStatus = (status) => {
    const normalizedStatus = String(status ?? '').trim().toLowerCase();
    if (!normalizedStatus) {
      return 'active';
    }
    if (normalizedStatus === 'enabled') {
      return 'active';
    }
    return VALID_TENANT_MEMBERSHIP_STATUS.has(normalizedStatus)
      ? normalizedStatus
      : '';
  };
  const normalizeTenantMembershipStatusForRead = (status) => {
    const normalizedStatus = String(status ?? '').trim().toLowerCase();
    if (!normalizedStatus) {
      return '';
    }
    if (normalizedStatus === 'enabled') {
      return 'active';
    }
    return VALID_TENANT_MEMBERSHIP_STATUS.has(normalizedStatus)
      ? normalizedStatus
      : '';
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
  const normalizeOptionalTenantMemberProfileField = ({
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
  const resolveOptionalTenantMemberProfileField = (value) =>
    value === null || value === undefined
      ? null
      : value;
  const normalizeRequiredPlatformUserProfileField = ({
    value,
    maxLength,
    fieldName
  } = {}) => {
    const normalized = normalizeOptionalTenantMemberProfileField({
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
    const normalized = normalizeOptionalTenantMemberProfileField({
      value: trimmed,
      maxLength
    });
    if (!normalized) {
      throw new Error(`${fieldName} must be valid string`);
    }
    return normalized;
  };
  const isStrictOptionalTenantMemberProfileField = ({
    value,
    maxLength
  } = {}) => {
    const resolvedRawValue = resolveOptionalTenantMemberProfileField(value);
    if (resolvedRawValue === null) {
      return true;
    }
    if (typeof resolvedRawValue !== 'string') {
      return false;
    }
    const normalized = normalizeOptionalTenantMemberProfileField({
      value: resolvedRawValue,
      maxLength
    });
    return normalized !== null && normalized === resolvedRawValue;
  };
  const appendTenantMembershipHistory = ({
    membership = null,
    reason = null,
    operatorUserId = null
  } = {}) => {
    const normalizedTenantId = String(
      membership?.tenantId || membership?.tenant_id || ''
    ).trim();
    const normalizedUserId = String(
      membership?.userId || membership?.user_id || ''
    ).trim();
    if (!normalizedTenantId || !normalizedUserId) {
      return;
    }
    const pairKey = `${normalizedTenantId}::${normalizedUserId}`;
    const history = tenantMembershipHistoryByPair.get(pairKey) || [];
    history.push({
      membershipId: String(
        membership?.membershipId || membership?.membership_id || ''
      ).trim(),
      userId: normalizedUserId,
      tenantId: normalizedTenantId,
      tenantName:
        membership?.tenantName === null || membership?.tenantName === undefined
          ? null
          : String(membership.tenantName || '').trim() || null,
      status: normalizeTenantMembershipStatusForRead(membership?.status),
      archivedReason: reason ? String(reason).trim() : null,
      archivedByUserId:
        operatorUserId === null || operatorUserId === undefined
          ? null
          : String(operatorUserId).trim() || null,
      archivedAt: new Date().toISOString()
    });
    tenantMembershipHistoryByPair.set(pairKey, history);
  };
  const isTenantMembershipActiveForAuth = (tenantMembership) => {
    if (!isActiveLikeStatus(normalizeTenantMembershipStatusForRead(tenantMembership?.status))) {
      return false;
    }
    const tenantId = String(
      tenantMembership?.tenantId || tenantMembership?.tenant_id || ''
    ).trim();
    if (!tenantId) {
      return false;
    }
    const org = orgsById.get(tenantId);
    if (!org) {
      return orgsById.size === 0;
    }
    return isActiveLikeStatus(normalizeOrgStatus(org.status));
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
  const normalizePlatformRoleCatalogStatus = (status) => {
    const normalizedStatus = String(status || 'active').trim().toLowerCase();
    if (normalizedStatus === 'enabled') {
      return 'active';
    }
    if (!VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)) {
      throw new Error(`invalid platform role catalog status: ${normalizedStatus}`);
    }
    return normalizedStatus;
  };
  const normalizePlatformRoleCatalogScope = (scope) => {
    const normalizedScope = String(scope || 'platform').trim().toLowerCase();
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw new Error(`invalid platform role catalog scope: ${normalizedScope}`);
    }
    return normalizedScope;
  };
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
  const toPlatformRoleCatalogRoleIdKey = (roleId) =>
    normalizePlatformRoleCatalogRoleId(roleId).toLowerCase();
  const normalizePlatformRoleCatalogCode = (code) =>
    String(code || '').trim();
  const toPlatformRoleCatalogCodeKey = (code) =>
    normalizePlatformRoleCatalogCode(code).toLowerCase();
  const toPlatformRoleCatalogCodeIndexKey = ({
    scope = 'platform',
    tenantId = '',
    code = ''
  } = {}) =>
    [
      normalizePlatformRoleCatalogScope(scope),
      normalizePlatformRoleCatalogTenantIdForScope({ scope, tenantId }),
      toPlatformRoleCatalogCodeKey(code)
    ].join('::');
  const normalizePlatformIntegrationId = (integrationId) =>
    String(integrationId || '').trim().toLowerCase();
  const isValidPlatformIntegrationId = (integrationId) =>
    Boolean(integrationId) && integrationId.length <= MAX_PLATFORM_INTEGRATION_ID_LENGTH;
  const normalizePlatformIntegrationCode = (code) =>
    String(code || '').trim();
  const toPlatformIntegrationCodeKey = (code) =>
    normalizePlatformIntegrationCode(code).toLowerCase();
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
  const normalizePlatformIntegrationRecoveryIdempotencyKey = (idempotencyKey) =>
    idempotencyKey === null || idempotencyKey === undefined
      ? ''
      : String(idempotencyKey || '').trim();
  const PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN = /^[a-f0-9]{64}$/;
  const toPlatformIntegrationContractVersionKey = ({
    integrationId,
    contractType,
    contractVersion
  } = {}) =>
    [
      normalizePlatformIntegrationId(integrationId),
      normalizePlatformIntegrationContractType(contractType),
      normalizePlatformIntegrationContractVersion(contractVersion)
    ].join('::');
  const toPlatformIntegrationContractScopeKey = ({
    integrationId,
    contractType
  } = {}) =>
    [
      normalizePlatformIntegrationId(integrationId),
      normalizePlatformIntegrationContractType(contractType)
    ].join('::');
  const toPlatformIntegrationRecoveryDedupKey = ({
    integrationId,
    contractType,
    contractVersion,
    requestId,
    idempotencyKey
  } = {}) =>
    [
      normalizePlatformIntegrationId(integrationId),
      normalizePlatformIntegrationContractType(contractType),
      normalizePlatformIntegrationContractVersion(contractVersion),
      String(requestId || '').trim(),
      normalizePlatformIntegrationRecoveryIdempotencyKey(idempotencyKey)
    ].join('::');
  const normalizePlatformIntegrationOptionalText = (value) => {
    if (value === null || value === undefined) {
      return null;
    }
    const normalized = String(value).trim();
    return normalized.length > 0 ? normalized : null;
  };
  const normalizePlatformIntegrationTimeoutMs = (timeoutMs) => {
    if (timeoutMs === null || timeoutMs === undefined) {
      return PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS;
    }
    const parsed = Number(timeoutMs);
    return Number.isInteger(parsed) ? parsed : NaN;
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
        return JSON.parse(normalized);
      } catch (_error) {
        return undefined;
      }
    }
    if (typeof value === 'object') {
      return structuredClone(value);
    }
    return undefined;
  };
  const createDuplicatePlatformIntegrationCatalogEntryError = ({
    target = 'code'
  } = {}) => {
    const normalizedTarget = String(target || '').trim().toLowerCase();
    const resolvedTarget = normalizedTarget === 'integration_id'
      ? 'integration_id'
      : 'code';
    const error = new Error(
      resolvedTarget === 'integration_id'
        ? 'duplicate platform integration catalog integration_id'
        : 'duplicate platform integration catalog code'
    );
    error.code = 'ER_DUP_ENTRY';
    error.errno = 1062;
    error.conflictTarget = resolvedTarget;
    error.platformIntegrationCatalogConflictTarget = resolvedTarget;
    return error;
  };
  const createDuplicatePlatformIntegrationContractVersionError = () => {
    const error = new Error('duplicate platform integration contract version');
    error.code = 'ER_DUP_ENTRY';
    error.errno = 1062;
    error.conflictTarget = 'contract_version';
    error.platformIntegrationContractConflictTarget = 'contract_version';
    return error;
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
      return normalizedNextStatus === 'active' || normalizedNextStatus === 'retired';
    }
    if (normalizedPreviousStatus === 'active') {
      return normalizedNextStatus === 'paused' || normalizedNextStatus === 'retired';
    }
    if (normalizedPreviousStatus === 'paused') {
      return normalizedNextStatus === 'active' || normalizedNextStatus === 'retired';
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
    error.frozenAt = String(frozenAt || '').trim() || null;
    error.freezeReason = normalizePlatformIntegrationOptionalText(freezeReason) || null;
    return error;
  };
  const createPlatformIntegrationFreezeReleaseConflictError = () => {
    const error = new Error('platform integration freeze release conflict');
    error.code = 'ERR_PLATFORM_INTEGRATION_FREEZE_RELEASE_CONFLICT';
    return error;
  };
  const normalizePlatformPermissionCode = (permissionCode) =>
    String(permissionCode || '').trim();
  const toPlatformPermissionCodeKey = (permissionCode) =>
    normalizePlatformPermissionCode(permissionCode).toLowerCase();
  const createDuplicatePlatformRoleCatalogEntryError = ({ target = 'code' } = {}) => {
    const normalizedTarget = String(target || '').trim().toLowerCase();
    const resolvedTarget = normalizedTarget === 'role_id' ? 'role_id' : 'code';
    const error = new Error(
      resolvedTarget === 'role_id'
        ? 'duplicate platform role catalog role_id'
        : 'duplicate platform role catalog code'
    );
    error.code = 'ER_DUP_ENTRY';
    error.errno = 1062;
    error.conflictTarget = resolvedTarget;
    error.platformRoleCatalogConflictTarget = resolvedTarget;
    return error;
  };
  const toPlatformRoleCatalogRecord = (entry = {}) => ({
    roleId: String(entry.roleId || entry.role_id || '').trim(),
    tenantId: normalizePlatformRoleCatalogTenantIdForScope({
      scope: entry.scope,
      tenantId: entry.tenantId || entry.tenant_id
    }),
    code: String(entry.code || '').trim(),
    name: String(entry.name || '').trim(),
    status: normalizePlatformRoleCatalogStatus(entry.status),
    scope: normalizePlatformRoleCatalogScope(entry.scope),
    isSystem: Boolean(entry.isSystem ?? entry.is_system),
    createdByUserId: entry.createdByUserId || entry.created_by_user_id || null,
    updatedByUserId: entry.updatedByUserId || entry.updated_by_user_id || null,
    createdAt: entry.createdAt || entry.created_at || new Date().toISOString(),
    updatedAt: entry.updatedAt || entry.updated_at || new Date().toISOString()
  });
  const clonePlatformRoleCatalogRecord = (entry = null) =>
    entry
      ? {
        roleId: entry.roleId,
        tenantId: entry.tenantId,
        code: entry.code,
        name: entry.name,
        status: entry.status,
        scope: entry.scope,
        isSystem: entry.isSystem,
        createdByUserId: entry.createdByUserId,
        updatedByUserId: entry.updatedByUserId,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt
      }
      : null;
  const toPlatformIntegrationCatalogRecord = (entry = {}) => {
    const normalizedIntegrationId = normalizePlatformIntegrationId(
      entry.integrationId || entry.integration_id
    );
    const normalizedCode = normalizePlatformIntegrationCode(entry.code);
    const normalizedDirection = normalizePlatformIntegrationDirection(
      entry.direction
    );
    const normalizedLifecycleStatus = normalizePlatformIntegrationLifecycleStatus(
      entry.lifecycleStatus || entry.lifecycle_status || 'draft'
    );
    const normalizedProtocol = String(entry.protocol || '').trim();
    const normalizedAuthMode = String(entry.authMode || entry.auth_mode || '').trim();
    const normalizedName = String(entry.name || '').trim();
    const normalizedTimeoutMs = normalizePlatformIntegrationTimeoutMs(
      entry.timeoutMs ?? entry.timeout_ms
    );
    const normalizedEndpoint = normalizePlatformIntegrationOptionalText(entry.endpoint);
    const normalizedBaseUrl = normalizePlatformIntegrationOptionalText(
      entry.baseUrl || entry.base_url
    );
    const normalizedVersionStrategy = normalizePlatformIntegrationOptionalText(
      entry.versionStrategy || entry.version_strategy
    );
    const normalizedRunbookUrl = normalizePlatformIntegrationOptionalText(
      entry.runbookUrl || entry.runbook_url
    );
    const normalizedLifecycleReason = normalizePlatformIntegrationOptionalText(
      entry.lifecycleReason || entry.lifecycle_reason
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
        && normalizedLifecycleReason.length > MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH
      )
      || !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedLifecycleStatus)
      || !Number.isInteger(normalizedTimeoutMs)
      || normalizedTimeoutMs < 1
      || normalizedTimeoutMs > MAX_PLATFORM_INTEGRATION_TIMEOUT_MS
    ) {
      throw new Error('invalid platform integration catalog entry');
    }
    const normalizedRetryPolicy = normalizePlatformIntegrationJsonForStorage({
      value: entry.retryPolicy ?? entry.retry_policy
    });
    const normalizedIdempotencyPolicy = normalizePlatformIntegrationJsonForStorage({
      value: entry.idempotencyPolicy ?? entry.idempotency_policy
    });
    if (
      normalizedRetryPolicy === undefined
      || normalizedIdempotencyPolicy === undefined
    ) {
      throw new Error('invalid platform integration policy payload');
    }
    return {
      integrationId: normalizedIntegrationId,
      code: normalizedCode,
      codeNormalized: toPlatformIntegrationCodeKey(normalizedCode),
      name: normalizedName,
      direction: normalizedDirection,
      protocol: normalizedProtocol,
      authMode: normalizedAuthMode,
      endpoint: normalizedEndpoint,
      baseUrl: normalizedBaseUrl,
      timeoutMs: normalizedTimeoutMs,
      retryPolicy: normalizedRetryPolicy,
      idempotencyPolicy: normalizedIdempotencyPolicy,
      versionStrategy: normalizedVersionStrategy,
      runbookUrl: normalizedRunbookUrl,
      lifecycleStatus: normalizedLifecycleStatus,
      lifecycleReason: normalizedLifecycleReason,
      createdByUserId: normalizePlatformIntegrationOptionalText(
        entry.createdByUserId || entry.created_by_user_id
      ),
      updatedByUserId: normalizePlatformIntegrationOptionalText(
        entry.updatedByUserId || entry.updated_by_user_id
      ),
      createdAt:
        entry.createdAt || entry.created_at || new Date().toISOString(),
      updatedAt:
        entry.updatedAt || entry.updated_at || new Date().toISOString()
    };
  };
  const clonePlatformIntegrationCatalogRecord = (entry = null) =>
    entry
      ? {
        integrationId: entry.integrationId,
        code: entry.code,
        codeNormalized: entry.codeNormalized,
        name: entry.name,
        direction: entry.direction,
        protocol: entry.protocol,
        authMode: entry.authMode,
        endpoint: entry.endpoint,
        baseUrl: entry.baseUrl,
        timeoutMs: entry.timeoutMs,
        retryPolicy: entry.retryPolicy ? structuredClone(entry.retryPolicy) : null,
        idempotencyPolicy: entry.idempotencyPolicy
          ? structuredClone(entry.idempotencyPolicy)
          : null,
        versionStrategy: entry.versionStrategy,
        runbookUrl: entry.runbookUrl,
        lifecycleStatus: entry.lifecycleStatus,
        lifecycleReason: entry.lifecycleReason,
        createdByUserId: entry.createdByUserId,
        updatedByUserId: entry.updatedByUserId,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt
      }
      : null;
  const toPlatformIntegrationContractVersionRecord = (entry = {}) => {
    const normalizedIntegrationId = normalizePlatformIntegrationId(
      entry.integrationId || entry.integration_id
    );
    const normalizedContractType = normalizePlatformIntegrationContractType(
      entry.contractType || entry.contract_type
    );
    const normalizedContractVersion = normalizePlatformIntegrationContractVersion(
      entry.contractVersion || entry.contract_version
    );
    const normalizedSchemaRef = normalizePlatformIntegrationOptionalText(
      entry.schemaRef || entry.schema_ref
    );
    const normalizedSchemaChecksum = normalizePlatformIntegrationContractSchemaChecksum(
      entry.schemaChecksum || entry.schema_checksum
    );
    const normalizedStatus = normalizePlatformIntegrationContractStatus(
      entry.status || 'candidate'
    );
    const normalizedCompatibilityNotes = normalizePlatformIntegrationOptionalText(
      entry.compatibilityNotes || entry.compatibility_notes
    );
    if (
      !isValidPlatformIntegrationId(normalizedIntegrationId)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
      || !normalizedContractVersion
      || normalizedContractVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      || !normalizedSchemaRef
      || normalizedSchemaRef.length > MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_REF_LENGTH
      || !normalizedSchemaChecksum
      || normalizedSchemaChecksum.length
        > MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_CHECKSUM_LENGTH
      || !PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN.test(normalizedSchemaChecksum)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS.has(normalizedStatus)
      || (
        normalizedCompatibilityNotes !== null
        && normalizedCompatibilityNotes.length
          > MAX_PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_NOTES_LENGTH
      )
    ) {
      throw new Error('invalid platform integration contract version entry');
    }
    return {
      contractId: Number(entry.contractId || entry.contract_id || 0) || 0,
      integrationId: normalizedIntegrationId,
      contractType: normalizedContractType,
      contractVersion: normalizedContractVersion,
      schemaRef: normalizedSchemaRef,
      schemaChecksum: normalizedSchemaChecksum,
      status: normalizedStatus,
      isBackwardCompatible: Boolean(
        entry.isBackwardCompatible ?? entry.is_backward_compatible
      ),
      compatibilityNotes: normalizedCompatibilityNotes,
      createdByUserId: normalizePlatformIntegrationOptionalText(
        entry.createdByUserId || entry.created_by_user_id
      ),
      updatedByUserId: normalizePlatformIntegrationOptionalText(
        entry.updatedByUserId || entry.updated_by_user_id
      ),
      createdAt: entry.createdAt || entry.created_at || new Date().toISOString(),
      updatedAt: entry.updatedAt || entry.updated_at || new Date().toISOString()
    };
  };
  const clonePlatformIntegrationContractVersionRecord = (entry = null) =>
    entry
      ? {
        contractId: Number(entry.contractId),
        integrationId: entry.integrationId,
        contractType: entry.contractType,
        contractVersion: entry.contractVersion,
        schemaRef: entry.schemaRef,
        schemaChecksum: entry.schemaChecksum,
        status: entry.status,
        isBackwardCompatible: Boolean(entry.isBackwardCompatible),
        compatibilityNotes: entry.compatibilityNotes,
        createdByUserId: entry.createdByUserId,
        updatedByUserId: entry.updatedByUserId,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt
      }
      : null;
  const toPlatformIntegrationContractCompatibilityCheckRecord = (entry = {}) => {
    const normalizedIntegrationId = normalizePlatformIntegrationId(
      entry.integrationId || entry.integration_id
    );
    const normalizedContractType = normalizePlatformIntegrationContractType(
      entry.contractType || entry.contract_type
    );
    const normalizedBaselineVersion = normalizePlatformIntegrationContractVersion(
      entry.baselineVersion || entry.baseline_version
    );
    const normalizedCandidateVersion = normalizePlatformIntegrationContractVersion(
      entry.candidateVersion || entry.candidate_version
    );
    const normalizedEvaluationResult = normalizePlatformIntegrationContractEvaluationResult(
      entry.evaluationResult || entry.evaluation_result
    );
    const normalizedBreakingChangeCount = Number(
      entry.breakingChangeCount ?? entry.breaking_change_count
    );
    const normalizedRequestId = String(entry.requestId || entry.request_id || '').trim();
    const normalizedCheckedAt = String(entry.checkedAt || entry.checked_at || '').trim()
      || new Date().toISOString();
    const normalizedDiffSummary = normalizePlatformIntegrationJsonForStorage({
      value: entry.diffSummary ?? entry.diff_summary
    });
    if (
      !isValidPlatformIntegrationId(normalizedIntegrationId)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
      || !normalizedBaselineVersion
      || normalizedBaselineVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      || !normalizedCandidateVersion
      || normalizedCandidateVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT.has(normalizedEvaluationResult)
      || !Number.isInteger(normalizedBreakingChangeCount)
      || normalizedBreakingChangeCount < 0
      || !normalizedRequestId
      || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
      || normalizedDiffSummary === undefined
      || (
        normalizedDiffSummary !== null
        && JSON.stringify(normalizedDiffSummary).length
          > MAX_PLATFORM_INTEGRATION_CONTRACT_DIFF_SUMMARY_LENGTH
      )
    ) {
      throw new Error('invalid platform integration contract compatibility check entry');
    }
    return {
      checkId: Number(entry.checkId || entry.check_id || 0) || 0,
      integrationId: normalizedIntegrationId,
      contractType: normalizedContractType,
      baselineVersion: normalizedBaselineVersion,
      candidateVersion: normalizedCandidateVersion,
      evaluationResult: normalizedEvaluationResult,
      breakingChangeCount: normalizedBreakingChangeCount,
      diffSummary: normalizedDiffSummary,
      requestId: normalizedRequestId,
      checkedByUserId: normalizePlatformIntegrationOptionalText(
        entry.checkedByUserId || entry.checked_by_user_id
      ),
      checkedAt: normalizedCheckedAt
    };
  };
  const clonePlatformIntegrationContractCompatibilityCheckRecord = (entry = null) =>
    entry
      ? {
        checkId: Number(entry.checkId),
        integrationId: entry.integrationId,
        contractType: entry.contractType,
        baselineVersion: entry.baselineVersion,
        candidateVersion: entry.candidateVersion,
        evaluationResult: entry.evaluationResult,
        breakingChangeCount: Number(entry.breakingChangeCount),
        diffSummary: entry.diffSummary ? structuredClone(entry.diffSummary) : null,
        requestId: entry.requestId,
        checkedByUserId: entry.checkedByUserId,
        checkedAt: entry.checkedAt
      }
      : null;
  const toPlatformIntegrationRecoveryQueueRecord = (entry = {}) => {
    const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(
      entry.recoveryId || entry.recovery_id
    );
    const normalizedIntegrationId = normalizePlatformIntegrationId(
      entry.integrationId || entry.integration_id
    );
    const normalizedContractType = normalizePlatformIntegrationContractType(
      entry.contractType || entry.contract_type
    );
    const normalizedContractVersion = normalizePlatformIntegrationContractVersion(
      entry.contractVersion || entry.contract_version
    );
    const normalizedRequestId = String(
      entry.requestId || entry.request_id || ''
    ).trim();
    const normalizedTraceparent = normalizePlatformIntegrationOptionalText(
      entry.traceparent
    );
    const normalizedIdempotencyKey = normalizePlatformIntegrationRecoveryIdempotencyKey(
      entry.idempotencyKey ?? entry.idempotency_key
    );
    const normalizedAttemptCount = Number(
      entry.attemptCount ?? entry.attempt_count ?? 0
    );
    const normalizedMaxAttempts = Number(
      entry.maxAttempts ?? entry.max_attempts ?? 5
    );
    const normalizedStatus = normalizePlatformIntegrationRecoveryStatus(
      entry.status || 'pending'
    );
    const normalizedFailureCode = normalizePlatformIntegrationOptionalText(
      entry.failureCode || entry.failure_code
    );
    const normalizedFailureDetail = normalizePlatformIntegrationOptionalText(
      entry.failureDetail || entry.failure_detail
    );
    const normalizedLastHttpStatus =
      (entry.lastHttpStatus === undefined || entry.lastHttpStatus === null)
      && (entry.last_http_status === undefined || entry.last_http_status === null)
        ? null
        : Number(entry.lastHttpStatus ?? entry.last_http_status);
    const normalizedRetryable = Boolean(entry.retryable ?? true);
    const normalizedPayloadSnapshot = normalizePlatformIntegrationJsonForStorage({
      value: entry.payloadSnapshot ?? entry.payload_snapshot
    });
    const normalizedResponseSnapshot = normalizePlatformIntegrationJsonForStorage({
      value: entry.responseSnapshot ?? entry.response_snapshot
    });
    const normalizedNextRetryAtRaw = entry.nextRetryAt ?? entry.next_retry_at;
    const normalizedLastAttemptAtRaw = entry.lastAttemptAt ?? entry.last_attempt_at;
    const normalizedNextRetryAt =
      normalizedNextRetryAtRaw === null || normalizedNextRetryAtRaw === undefined
        ? null
        : new Date(normalizedNextRetryAtRaw).toISOString();
    const normalizedLastAttemptAt =
      normalizedLastAttemptAtRaw === null || normalizedLastAttemptAtRaw === undefined
        ? null
        : new Date(normalizedLastAttemptAtRaw).toISOString();
    const normalizedCreatedAt = String(
      entry.createdAt || entry.created_at || new Date().toISOString()
    ).trim();
    const normalizedUpdatedAt = String(
      entry.updatedAt || entry.updated_at || new Date().toISOString()
    ).trim();
    if (
      !normalizedRecoveryId
      || normalizedRecoveryId.length > MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH
      || !isValidPlatformIntegrationId(normalizedIntegrationId)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
      || !normalizedContractVersion
      || normalizedContractVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      || !normalizedRequestId
      || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
      || (
        normalizedTraceparent !== null
        && normalizedTraceparent.length > MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH
      )
      || normalizedIdempotencyKey.length > MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH
      || !Number.isInteger(normalizedAttemptCount)
      || normalizedAttemptCount < 0
      || !Number.isInteger(normalizedMaxAttempts)
      || normalizedMaxAttempts < 1
      || normalizedMaxAttempts > 5
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
      || normalizedPayloadSnapshot === undefined
      || normalizedPayloadSnapshot === null
      || normalizedResponseSnapshot === undefined
      || !normalizedCreatedAt
      || !normalizedUpdatedAt
      || (
        normalizedNextRetryAt !== null
        && Number.isNaN(new Date(normalizedNextRetryAt).getTime())
      )
      || (
        normalizedLastAttemptAt !== null
        && Number.isNaN(new Date(normalizedLastAttemptAt).getTime())
      )
    ) {
      throw new Error('invalid platform integration recovery queue entry');
    }
    return {
      recoveryId: normalizedRecoveryId,
      integrationId: normalizedIntegrationId,
      contractType: normalizedContractType,
      contractVersion: normalizedContractVersion,
      requestId: normalizedRequestId,
      traceparent: normalizedTraceparent,
      idempotencyKey: normalizedIdempotencyKey || null,
      attemptCount: normalizedAttemptCount,
      maxAttempts: normalizedMaxAttempts,
      nextRetryAt: normalizedNextRetryAt,
      lastAttemptAt: normalizedLastAttemptAt,
      status: normalizedStatus,
      failureCode: normalizedFailureCode,
      failureDetail: normalizedFailureDetail,
      lastHttpStatus: normalizedLastHttpStatus,
      retryable: normalizedRetryable,
      payloadSnapshot: normalizedPayloadSnapshot,
      responseSnapshot: normalizedResponseSnapshot,
      createdByUserId: normalizePlatformIntegrationOptionalText(
        entry.createdByUserId || entry.created_by_user_id
      ),
      updatedByUserId: normalizePlatformIntegrationOptionalText(
        entry.updatedByUserId || entry.updated_by_user_id
      ),
      createdAt: normalizedCreatedAt,
      updatedAt: normalizedUpdatedAt
    };
  };
  const clonePlatformIntegrationRecoveryQueueRecord = (entry = null) =>
    entry
      ? {
        recoveryId: entry.recoveryId,
        integrationId: entry.integrationId,
        contractType: entry.contractType,
        contractVersion: entry.contractVersion,
        requestId: entry.requestId,
        traceparent: entry.traceparent,
        idempotencyKey: entry.idempotencyKey,
        attemptCount: Number(entry.attemptCount),
        maxAttempts: Number(entry.maxAttempts),
        nextRetryAt: entry.nextRetryAt,
        lastAttemptAt: entry.lastAttemptAt,
        status: entry.status,
        failureCode: entry.failureCode,
        failureDetail: entry.failureDetail,
        lastHttpStatus: entry.lastHttpStatus,
        retryable: Boolean(entry.retryable),
        payloadSnapshot: entry.payloadSnapshot
          ? structuredClone(entry.payloadSnapshot)
          : null,
        responseSnapshot: entry.responseSnapshot
          ? structuredClone(entry.responseSnapshot)
          : null,
        createdByUserId: entry.createdByUserId,
        updatedByUserId: entry.updatedByUserId,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt
      }
      : null;
  const toPlatformIntegrationFreezeRecord = (entry = {}) => {
    const normalizedFreezeId = normalizePlatformIntegrationFreezeId(
      entry.freezeId || entry.freeze_id
    );
    const normalizedStatus = normalizePlatformIntegrationFreezeStatus(
      entry.status || 'active'
    );
    const normalizedFreezeReason = normalizePlatformIntegrationOptionalText(
      entry.freezeReason || entry.freeze_reason
    );
    const normalizedRollbackReason = normalizePlatformIntegrationOptionalText(
      entry.rollbackReason || entry.rollback_reason
    );
    const normalizedFrozenAt = String(
      entry.frozenAt || entry.frozen_at || new Date().toISOString()
    ).trim();
    const releasedAtRaw = entry.releasedAt ?? entry.released_at ?? null;
    const normalizedReleasedAt =
      releasedAtRaw === null || releasedAtRaw === undefined
        ? null
        : new Date(releasedAtRaw).toISOString();
    const normalizedRequestId = String(
      entry.requestId || entry.request_id || ''
    ).trim();
    const normalizedTraceparent = normalizePlatformIntegrationOptionalText(
      entry.traceparent
    );
    const normalizedCreatedAt = String(
      entry.createdAt || entry.created_at || new Date().toISOString()
    ).trim();
    const normalizedUpdatedAt = String(
      entry.updatedAt || entry.updated_at || new Date().toISOString()
    ).trim();
    const normalizedFrozenByUserId = normalizePlatformIntegrationOptionalText(
      entry.frozenByUserId || entry.frozen_by_user_id
    );
    const normalizedReleasedByUserId = normalizePlatformIntegrationOptionalText(
      entry.releasedByUserId || entry.released_by_user_id
    );
    if (
      !normalizedFreezeId
      || normalizedFreezeId.length > MAX_PLATFORM_INTEGRATION_FREEZE_ID_LENGTH
      || !VALID_PLATFORM_INTEGRATION_FREEZE_STATUS.has(normalizedStatus)
      || !normalizedFreezeReason
      || normalizedFreezeReason.length > MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH
      || (
        normalizedRollbackReason !== null
        && normalizedRollbackReason.length > MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH
      )
      || !normalizedFrozenAt
      || Number.isNaN(new Date(normalizedFrozenAt).getTime())
      || (
        normalizedReleasedAt !== null
        && Number.isNaN(new Date(normalizedReleasedAt).getTime())
      )
      || (
        normalizedStatus === 'active'
        && normalizedReleasedAt !== null
      )
      || (
        normalizedStatus === 'released'
        && normalizedReleasedAt === null
      )
      || (
        normalizedFrozenByUserId !== null
        && normalizedFrozenByUserId.length > MAX_OPERATOR_USER_ID_LENGTH
      )
      || (
        normalizedReleasedByUserId !== null
        && normalizedReleasedByUserId.length > MAX_OPERATOR_USER_ID_LENGTH
      )
      || !normalizedRequestId
      || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH
      || (
        normalizedTraceparent !== null
        && normalizedTraceparent.length > MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH
      )
      || !normalizedCreatedAt
      || Number.isNaN(new Date(normalizedCreatedAt).getTime())
      || !normalizedUpdatedAt
      || Number.isNaN(new Date(normalizedUpdatedAt).getTime())
    ) {
      throw new Error('invalid platform integration freeze entry');
    }
    return {
      freezeId: normalizedFreezeId,
      status: normalizedStatus,
      freezeReason: normalizedFreezeReason,
      rollbackReason: normalizedRollbackReason,
      frozenAt: normalizedFrozenAt,
      releasedAt: normalizedReleasedAt,
      frozenByUserId: normalizedFrozenByUserId,
      releasedByUserId: normalizedReleasedByUserId,
      requestId: normalizedRequestId,
      traceparent: normalizedTraceparent,
      createdAt: normalizedCreatedAt,
      updatedAt: normalizedUpdatedAt
    };
  };
  const clonePlatformIntegrationFreezeRecord = (entry = null) =>
    entry
      ? {
        freezeId: entry.freezeId,
        status: entry.status,
        freezeReason: entry.freezeReason,
        rollbackReason: entry.rollbackReason,
        frozenAt: entry.frozenAt,
        releasedAt: entry.releasedAt,
        frozenByUserId: entry.frozenByUserId,
        releasedByUserId: entry.releasedByUserId,
        requestId: entry.requestId,
        traceparent: entry.traceparent,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt
      }
      : null;

  const findPlatformRoleCatalogRecordStateByRoleId = (roleId) => {
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (!normalizedRoleId) {
      return null;
    }
    if (platformRoleCatalogById.has(normalizedRoleId)) {
      return {
        roleId: normalizedRoleId,
        record: platformRoleCatalogById.get(normalizedRoleId)
      };
    }
    const normalizedRoleIdKey = toPlatformRoleCatalogRoleIdKey(normalizedRoleId);
    for (const [existingRoleId, entry] of platformRoleCatalogById.entries()) {
      if (toPlatformRoleCatalogRoleIdKey(existingRoleId) !== normalizedRoleIdKey) {
        continue;
      }
      return {
        roleId: existingRoleId,
        record: entry
      };
    }
    return null;
  };
  const findPlatformIntegrationCatalogRecordStateByIntegrationId = (
    integrationId
  ) => {
    const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
    if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
      return null;
    }
    if (platformIntegrationCatalogById.has(normalizedIntegrationId)) {
      return {
        integrationId: normalizedIntegrationId,
        record: platformIntegrationCatalogById.get(normalizedIntegrationId)
      };
    }
    return null;
  };
  const findPlatformIntegrationContractVersionRecordState = ({
    integrationId,
    contractType,
    contractVersion
  } = {}) => {
    const contractKey = toPlatformIntegrationContractVersionKey({
      integrationId,
      contractType,
      contractVersion
    });
    if (!platformIntegrationContractVersionsByKey.has(contractKey)) {
      return null;
    }
    return {
      key: contractKey,
      record: platformIntegrationContractVersionsByKey.get(contractKey)
    };
  };
  const findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId = (
    recoveryId
  ) => {
    const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(recoveryId);
    if (!normalizedRecoveryId) {
      return null;
    }
    if (!platformIntegrationRecoveryQueueByRecoveryId.has(normalizedRecoveryId)) {
      return null;
    }
    return {
      recoveryId: normalizedRecoveryId,
      record: platformIntegrationRecoveryQueueByRecoveryId.get(normalizedRecoveryId)
    };
  };
  const findPlatformIntegrationRecoveryQueueRecordStateByDedupKey = ({
    integrationId,
    contractType,
    contractVersion,
    requestId,
    idempotencyKey
  } = {}) => {
    const dedupKey = toPlatformIntegrationRecoveryDedupKey({
      integrationId,
      contractType,
      contractVersion,
      requestId,
      idempotencyKey
    });
    const recoveryId = platformIntegrationRecoveryDedupIndex.get(dedupKey);
    if (!recoveryId) {
      return null;
    }
    return findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId(recoveryId);
  };
  const comparePlatformIntegrationFreezeRecords = (left, right) => {
    const leftFrozenAt = new Date(left?.frozenAt || 0).getTime();
    const rightFrozenAt = new Date(right?.frozenAt || 0).getTime();
    if (leftFrozenAt !== rightFrozenAt) {
      return rightFrozenAt - leftFrozenAt;
    }
    return String(right?.freezeId || '').localeCompare(String(left?.freezeId || ''));
  };
  const findActivePlatformIntegrationFreezeRecordState = () => {
    const activeEntries = [];
    for (const [freezeId, entry] of platformIntegrationFreezeById.entries()) {
      if (entry?.status !== 'active') {
        continue;
      }
      activeEntries.push({
        freezeId,
        record: entry
      });
    }
    if (activeEntries.length === 0) {
      return null;
    }
    activeEntries.sort((left, right) =>
      comparePlatformIntegrationFreezeRecords(left.record, right.record)
    );
    return activeEntries[0];
  };
  const findLatestPlatformIntegrationFreezeRecordState = () => {
    const entries = [];
    for (const [freezeId, record] of platformIntegrationFreezeById.entries()) {
      entries.push({
        freezeId,
        record
      });
    }
    if (entries.length === 0) {
      return null;
    }
    entries.sort((left, right) =>
      comparePlatformIntegrationFreezeRecords(left.record, right.record)
    );
    return entries[0];
  };
  const findActivePlatformIntegrationFreezeForWriteGate = () => {
    const activeState = findActivePlatformIntegrationFreezeRecordState();
    if (!activeState?.record) {
      return null;
    }
    const activeFreeze = toPlatformIntegrationFreezeRecord(activeState.record);
    if (!activeFreeze) {
      throw new Error('platform integration freeze gate state malformed');
    }
    return activeFreeze;
  };
  const assertPlatformIntegrationWriteAllowedByFreezeGate = () => {
    const activeFreeze = findActivePlatformIntegrationFreezeForWriteGate();
    if (!activeFreeze) {
      return;
    }
    throw createPlatformIntegrationFreezeActiveConflictError({
      freezeId: activeFreeze.freezeId,
      frozenAt: activeFreeze.frozenAt,
      freezeReason: activeFreeze.freezeReason
    });
  };

  const normalizePlatformPermission = (
    permission,
    fallbackScopeLabel = '平台权限快照（服务端）'
  ) => {
    if (!permission || typeof permission !== 'object') {
      return null;
    }
    return {
      scopeLabel: permission.scopeLabel || permission.scope_label || fallbackScopeLabel,
      canViewMemberAdmin: Boolean(
        permission.canViewMemberAdmin ?? permission.can_view_member_admin
      ),
      canOperateMemberAdmin: Boolean(
        permission.canOperateMemberAdmin ?? permission.can_operate_member_admin
      ),
      canViewBilling: Boolean(permission.canViewBilling ?? permission.can_view_billing),
      canOperateBilling: Boolean(
        permission.canOperateBilling ?? permission.can_operate_billing
      ),
      canViewSystemConfig: Boolean(
        permission.canViewSystemConfig ?? permission.can_view_system_config
      ),
      canOperateSystemConfig: Boolean(
        permission.canOperateSystemConfig ?? permission.can_operate_system_config
      )
    };
  };

  const mergePlatformPermission = (left, right) => {
    if (!left && !right) {
      return null;
    }
    if (!left) {
      return { ...right };
    }
    if (!right) {
      return { ...left };
    }
    return {
      scopeLabel: left.scopeLabel || right.scopeLabel || '平台权限快照（服务端）',
      canViewMemberAdmin:
        Boolean(left.canViewMemberAdmin) || Boolean(right.canViewMemberAdmin),
      canOperateMemberAdmin:
        Boolean(left.canOperateMemberAdmin) || Boolean(right.canOperateMemberAdmin),
      canViewBilling: Boolean(left.canViewBilling) || Boolean(right.canViewBilling),
      canOperateBilling:
        Boolean(left.canOperateBilling) || Boolean(right.canOperateBilling),
      canViewSystemConfig:
        Boolean(left.canViewSystemConfig) || Boolean(right.canViewSystemConfig),
      canOperateSystemConfig:
        Boolean(left.canOperateSystemConfig) || Boolean(right.canOperateSystemConfig)
    };
  };

  const buildEmptyPlatformPermission = (scopeLabel = '平台权限（角色并集）') => ({
    scopeLabel,
    canViewMemberAdmin: false,
    canOperateMemberAdmin: false,
    canViewBilling: false,
    canOperateBilling: false,
    canViewSystemConfig: false,
    canOperateSystemConfig: false
  });

  const normalizePlatformPermissionCodes = (permissionCodes = []) => {
    const deduped = new Map();
    for (const permissionCode of Array.isArray(permissionCodes) ? permissionCodes : []) {
      const normalizedCode = normalizePlatformPermissionCode(permissionCode);
      if (!normalizedCode) {
        continue;
      }
      const permissionCodeKey = toPlatformPermissionCodeKey(normalizedCode);
      deduped.set(permissionCodeKey, permissionCodeKey);
    }
    return [...deduped.values()];
  };

  const resolvePlatformPermissionFromGrantCodes = (permissionCodes = []) => {
    return {
      ...buildEmptyPlatformPermission(),
      ...toPlatformPermissionSnapshotFromCodes(
        normalizePlatformPermissionCodes(permissionCodes)
      )
    };
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

  const listPlatformRolePermissionGrantsForRoleId = (roleId) => {
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (!normalizedRoleId) {
      return [];
    }
    const normalizedPermissionCodeKeys = [];
    const seenPermissionCodeKeys = new Set();
    for (const permissionCode of platformRolePermissionGrantsByRoleId.get(normalizedRoleId) || []) {
      if (typeof permissionCode !== 'string') {
        throw createPlatformRolePermissionGrantDataError(
          'platform-role-permission-grants-invalid-permission-code'
        );
      }
      const normalizedPermissionCode = normalizePlatformPermissionCode(permissionCode);
      const permissionCodeKey = toPlatformPermissionCodeKey(normalizedPermissionCode);
      if (
        permissionCode !== normalizedPermissionCode
        || !normalizedPermissionCode
        || CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)
        || !KNOWN_PLATFORM_PERMISSION_CODE_SET.has(permissionCodeKey)
      ) {
        throw createPlatformRolePermissionGrantDataError(
          'platform-role-permission-grants-invalid-permission-code'
        );
      }
      if (seenPermissionCodeKeys.has(permissionCodeKey)) {
        throw createPlatformRolePermissionGrantDataError(
          'platform-role-permission-grants-duplicate-permission-code'
        );
      }
      seenPermissionCodeKeys.add(permissionCodeKey);
      normalizedPermissionCodeKeys.push(permissionCodeKey);
    }
    return normalizedPermissionCodeKeys.sort((left, right) => left.localeCompare(right));
  };

  const replacePlatformRolePermissionGrantsForRoleId = ({
    roleId,
    permissionCodes = []
  }) => {
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (!normalizedRoleId) {
      throw new Error('replacePlatformRolePermissionGrants requires roleId');
    }
    const normalizedPermissionCodes = normalizePlatformPermissionCodes(permissionCodes)
      .filter((permissionCode) =>
        KNOWN_PLATFORM_PERMISSION_CODES.includes(permissionCode)
      );
    platformRolePermissionGrantsByRoleId.set(
      normalizedRoleId,
      normalizedPermissionCodes
    );
    return listPlatformRolePermissionGrantsForRoleId(normalizedRoleId);
  };

  const normalizeTenantPermissionCode = (permissionCode) =>
    String(permissionCode || '').trim();
  const toTenantPermissionCodeKey = (permissionCode) =>
    normalizeTenantPermissionCode(permissionCode).toLowerCase();
  const normalizeTenantPermissionCodes = (permissionCodes = []) => {
    const deduped = new Map();
    for (const permissionCode of Array.isArray(permissionCodes) ? permissionCodes : []) {
      const normalizedCode = normalizeTenantPermissionCode(permissionCode);
      if (!normalizedCode) {
        continue;
      }
      const permissionCodeKey = toTenantPermissionCodeKey(normalizedCode);
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
    const permissionCodeKey = toTenantPermissionCodeKey(normalizedPermissionCode);
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
  const createTenantMembershipRoleBindingDataError = (
    reason = 'tenant-membership-role-bindings-invalid'
  ) => {
    const error = new Error('tenant membership role bindings invalid');
    error.code = 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_INVALID';
    error.reason = String(reason || 'tenant-membership-role-bindings-invalid')
      .trim()
      .toLowerCase();
    return error;
  };
  const normalizeStrictTenantMembershipRoleIdFromBindingRow = (
    roleId,
    reason = 'tenant-membership-role-bindings-invalid-role-id'
  ) => {
    if (typeof roleId !== 'string') {
      throw createTenantMembershipRoleBindingDataError(reason);
    }
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (
      roleId !== roleId.trim()
      || !normalizedRoleId
      || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
      || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
    ) {
      throw createTenantMembershipRoleBindingDataError(reason);
    }
    return normalizedRoleId;
  };
  const normalizeStrictTenantMembershipRoleBindingIdentity = (
    identityValue,
    reason = 'tenant-membership-role-bindings-invalid-identity'
  ) => {
    if (typeof identityValue !== 'string') {
      throw createTenantMembershipRoleBindingDataError(reason);
    }
    const normalizedIdentity = identityValue.trim();
    if (
      !normalizedIdentity
      || identityValue !== normalizedIdentity
      || CONTROL_CHAR_PATTERN.test(normalizedIdentity)
    ) {
      throw createTenantMembershipRoleBindingDataError(reason);
    }
    return normalizedIdentity;
  };
  const buildEmptyTenantPermission = (scopeLabel = '组织权限（角色并集）') => ({
    scopeLabel,
    canViewMemberAdmin: false,
    canOperateMemberAdmin: false,
    canViewBilling: false,
    canOperateBilling: false
  });
  const resolveTenantPermissionFromGrantCodes = (permissionCodes = []) => {
    return {
      ...buildEmptyTenantPermission(),
      ...toTenantPermissionSnapshotFromCodes(
        normalizeTenantPermissionCodes(permissionCodes)
      )
    };
  };
  const listTenantRolePermissionGrantsForRoleId = (roleId) => {
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (!normalizedRoleId) {
      return [];
    }
    const normalizedPermissionCodeKeys = [];
    const seenPermissionCodeKeys = new Set();
    for (const permissionCode of tenantRolePermissionGrantsByRoleId.get(normalizedRoleId) || []) {
      const permissionCodeKey = normalizeStrictTenantPermissionCodeFromGrantRow(
        permissionCode,
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
    return normalizedPermissionCodeKeys.sort((left, right) => left.localeCompare(right));
  };
  const replaceTenantRolePermissionGrantsForRoleId = ({
    roleId,
    permissionCodes = []
  }) => {
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (!normalizedRoleId) {
      throw new Error('replaceTenantRolePermissionGrants requires roleId');
    }
    const normalizedPermissionCodes = normalizeTenantPermissionCodes(permissionCodes)
      .filter((permissionCode) =>
        KNOWN_TENANT_PERMISSION_CODES.includes(permissionCode)
      );
    tenantRolePermissionGrantsByRoleId.set(
      normalizedRoleId,
      normalizedPermissionCodes
    );
    return listTenantRolePermissionGrantsForRoleId(normalizedRoleId);
  };

  const isSamePlatformPermission = (left, right) => {
    const normalizedLeft = left || buildEmptyPlatformPermission();
    const normalizedRight = right || buildEmptyPlatformPermission();
    return (
      Boolean(normalizedLeft.canViewMemberAdmin) === Boolean(normalizedRight.canViewMemberAdmin)
      && Boolean(normalizedLeft.canOperateMemberAdmin) === Boolean(normalizedRight.canOperateMemberAdmin)
      && Boolean(normalizedLeft.canViewBilling) === Boolean(normalizedRight.canViewBilling)
      && Boolean(normalizedLeft.canOperateBilling) === Boolean(normalizedRight.canOperateBilling)
      && Boolean(normalizedLeft.canViewSystemConfig) === Boolean(normalizedRight.canViewSystemConfig)
      && Boolean(normalizedLeft.canOperateSystemConfig)
        === Boolean(normalizedRight.canOperateSystemConfig)
    );
  };

  const normalizePlatformRole = (role) => {
    const roleId = String(role?.roleId || role?.role_id || '').trim();
    if (!roleId) {
      return null;
    }
    const permissionSource = role?.permission || role;
    const hasExplicitPermissionPayload = Boolean(
      role?.permission
      || permissionSource?.canViewMemberAdmin !== undefined
      || permissionSource?.can_view_member_admin !== undefined
      || permissionSource?.canOperateMemberAdmin !== undefined
      || permissionSource?.can_operate_member_admin !== undefined
      || permissionSource?.canViewBilling !== undefined
      || permissionSource?.can_view_billing !== undefined
      || permissionSource?.canOperateBilling !== undefined
      || permissionSource?.can_operate_billing !== undefined
    );
    const rolePermissionFromPayload = normalizePlatformPermission(
      permissionSource,
      '平台权限（角色并集）'
    );
    const rolePermissionFromGrants = resolvePlatformPermissionFromGrantCodes(
      listPlatformRolePermissionGrantsForRoleId(roleId)
    );
    return {
      roleId,
      status: normalizePlatformRoleStatus(role?.status),
      permission: hasExplicitPermissionPayload
        ? rolePermissionFromPayload
        : rolePermissionFromGrants
    };
  };

  const dedupePlatformRolesByRoleId = (roles = []) => {
    const dedupedByRoleId = new Map();
    for (const role of Array.isArray(roles) ? roles : []) {
      const roleId = String(role?.roleId || '').trim();
      const dedupeKey = roleId.toLowerCase();
      if (!dedupeKey) {
        continue;
      }
      dedupedByRoleId.set(dedupeKey, role);
    }
    return [...dedupedByRoleId.values()];
  };

  const mergePlatformPermissionFromRoles = (roles) => {
    let merged = null;
    const normalizedRoles = Array.isArray(roles) ? roles : [];
    for (const role of normalizedRoles) {
      if (!role || !isActiveLikeStatus(role.status)) {
        continue;
      }
      merged = mergePlatformPermission(merged, role.permission);
    }
    return merged;
  };

  const syncPlatformPermissionFromRoleFacts = ({
    userId,
    forceWhenNoRoleFacts = false
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId || !usersById.has(normalizedUserId)) {
      return {
        synced: false,
        reason: 'invalid-user-id',
        permission: null
      };
    }

    const roles = platformRolesByUserId.get(normalizedUserId) || [];
    if (roles.length === 0 && !forceWhenNoRoleFacts) {
      return {
        synced: false,
        reason: 'no-role-facts',
        permission: null
      };
    }

    let permission = mergePlatformPermissionFromRoles(roles);
    if (!permission) {
      permission = buildEmptyPlatformPermission();
    }
    platformPermissionsByUserId.set(normalizedUserId, { ...permission });

    return {
      synced: true,
      reason: 'ok',
      permission: { ...permission }
    };
  };

  const upsertPlatformRoleCatalogRecord = (entry = {}) => {
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(
      entry.roleId || entry.role_id
    );
    const normalizedCode = normalizePlatformRoleCatalogCode(entry.code);
    const normalizedName = String(entry.name || '').trim();
    const normalizedScope = normalizePlatformRoleCatalogScope(
      entry.scope || 'platform'
    );
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId: entry.tenantId || entry.tenant_id
    });
    if (!normalizedRoleId || !normalizedCode || !normalizedName) {
      throw new Error('platform role catalog entry requires roleId, code, and name');
    }
    const codeIndexKey = toPlatformRoleCatalogCodeIndexKey({
      scope: normalizedScope,
      tenantId: normalizedTenantId,
      code: normalizedCode
    });
    const existingState = findPlatformRoleCatalogRecordStateByRoleId(
      normalizedRoleId
    );
    const persistedRoleId = existingState?.roleId || normalizedRoleId;
    const existing = existingState?.record || null;
    const existingRoleIdForCode = platformRoleCatalogCodeIndex.get(codeIndexKey);
    if (
      existingRoleIdForCode
      && toPlatformRoleCatalogRoleIdKey(existingRoleIdForCode)
        !== toPlatformRoleCatalogRoleIdKey(persistedRoleId)
    ) {
      throw createDuplicatePlatformRoleCatalogEntryError({
        target: 'code'
      });
    }
    if (existing) {
      const existingCodeIndexKey = toPlatformRoleCatalogCodeIndexKey({
        scope: existing.scope,
        tenantId: existing.tenantId,
        code: existing.code
      });
      if (existingCodeIndexKey !== codeIndexKey) {
        platformRoleCatalogCodeIndex.delete(existingCodeIndexKey);
      }
    }

    const nowIso = new Date().toISOString();
    const merged = toPlatformRoleCatalogRecord({
      ...existing,
      ...entry,
      roleId: persistedRoleId,
      scope: normalizedScope,
      tenantId: normalizedTenantId,
      code: normalizedCode,
      name: normalizedName,
      createdAt: existing?.createdAt || entry.createdAt || nowIso,
      updatedAt: entry.updatedAt || nowIso
    });
    platformRoleCatalogById.set(persistedRoleId, merged);
    platformRoleCatalogCodeIndex.set(codeIndexKey, persistedRoleId);
    return clonePlatformRoleCatalogRecord(merged);
  };
  const upsertPlatformIntegrationCatalogRecord = (entry = {}) => {
    const normalizedIntegrationId = normalizePlatformIntegrationId(
      entry.integrationId || entry.integration_id
    );
    if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
      throw new Error('platform integration catalog entry requires integrationId');
    }
    const normalizedCode = normalizePlatformIntegrationCode(entry.code);
    if (!normalizedCode) {
      throw new Error('platform integration catalog entry requires code');
    }
    const codeKey = toPlatformIntegrationCodeKey(normalizedCode);
    const existingState = findPlatformIntegrationCatalogRecordStateByIntegrationId(
      normalizedIntegrationId
    );
    const existing = existingState?.record || null;
    const existingIntegrationIdForCode =
      platformIntegrationCatalogCodeIndex.get(codeKey);
    if (
      existingIntegrationIdForCode
      && normalizePlatformIntegrationId(existingIntegrationIdForCode)
        !== normalizedIntegrationId
    ) {
      throw createDuplicatePlatformIntegrationCatalogEntryError({
        target: 'code'
      });
    }
    if (existing && existing.codeNormalized !== codeKey) {
      platformIntegrationCatalogCodeIndex.delete(existing.codeNormalized);
    }
    const nowIso = new Date().toISOString();
    const merged = toPlatformIntegrationCatalogRecord({
      ...existing,
      ...entry,
      integrationId: normalizedIntegrationId,
      code: normalizedCode,
      createdAt: existing?.createdAt || entry.createdAt || nowIso,
      updatedAt: entry.updatedAt || nowIso
    });
    platformIntegrationCatalogById.set(normalizedIntegrationId, merged);
    platformIntegrationCatalogCodeIndex.set(codeKey, normalizedIntegrationId);
    return clonePlatformIntegrationCatalogRecord(merged);
  };
  const upsertPlatformIntegrationContractVersionRecord = (entry = {}) => {
    const normalizedIntegrationId = normalizePlatformIntegrationId(
      entry.integrationId || entry.integration_id
    );
    const normalizedContractType = normalizePlatformIntegrationContractType(
      entry.contractType || entry.contract_type
    );
    const normalizedContractVersion = normalizePlatformIntegrationContractVersion(
      entry.contractVersion || entry.contract_version
    );
    if (
      !isValidPlatformIntegrationId(normalizedIntegrationId)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
      || !normalizedContractVersion
      || normalizedContractVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
    ) {
      throw new Error('platform integration contract version entry requires identity fields');
    }
    const contractKey = toPlatformIntegrationContractVersionKey({
      integrationId: normalizedIntegrationId,
      contractType: normalizedContractType,
      contractVersion: normalizedContractVersion
    });
    const existing = platformIntegrationContractVersionsByKey.get(contractKey) || null;
    const nowIso = new Date().toISOString();
    const merged = toPlatformIntegrationContractVersionRecord({
      ...existing,
      ...entry,
      contractId:
        Number(existing?.contractId || entry.contractId || entry.contract_id || 0)
        || nextPlatformIntegrationContractVersionId,
      integrationId: normalizedIntegrationId,
      contractType: normalizedContractType,
      contractVersion: normalizedContractVersion,
      createdAt: existing?.createdAt || entry.createdAt || entry.created_at || nowIso,
      updatedAt: entry.updatedAt || entry.updated_at || nowIso
    });
    if (!existing) {
      nextPlatformIntegrationContractVersionId += 1;
    }
    platformIntegrationContractVersionsByKey.set(contractKey, merged);
    return clonePlatformIntegrationContractVersionRecord(merged);
  };
  const upsertPlatformIntegrationRecoveryQueueRecord = ({
    entry = {},
    preserveTerminalStatus = false
  } = {}) => {
    const normalizedRecord = toPlatformIntegrationRecoveryQueueRecord(entry);
    const dedupState = findPlatformIntegrationRecoveryQueueRecordStateByDedupKey({
      integrationId: normalizedRecord.integrationId,
      contractType: normalizedRecord.contractType,
      contractVersion: normalizedRecord.contractVersion,
      requestId: normalizedRecord.requestId,
      idempotencyKey: normalizedRecord.idempotencyKey
    });
    const recoveryIdState = findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId(
      normalizedRecord.recoveryId
    );
    if (
      dedupState
      && recoveryIdState
      && dedupState.recoveryId !== recoveryIdState.recoveryId
    ) {
      throw new Error('duplicate platform integration recovery queue entry');
    }
    if (!dedupState && recoveryIdState) {
      throw new Error('duplicate platform integration recovery queue entry');
    }
    const existingState = dedupState || null;
    const existing = existingState?.record || null;
    const nowIso = new Date().toISOString();
    const persistedRecoveryId = existingState?.recoveryId || normalizedRecord.recoveryId;
    const merged = toPlatformIntegrationRecoveryQueueRecord({
      ...existing,
      ...normalizedRecord,
      recoveryId: persistedRecoveryId,
      status:
        preserveTerminalStatus
        && (
          existing?.status === 'succeeded'
          || existing?.status === 'replayed'
        )
          ? existing.status
          : normalizedRecord.status,
      createdAt: existing?.createdAt || normalizedRecord.createdAt || nowIso,
      updatedAt: nowIso
    });
    if (existing) {
      const previousDedupKey = toPlatformIntegrationRecoveryDedupKey({
        integrationId: existing.integrationId,
        contractType: existing.contractType,
        contractVersion: existing.contractVersion,
        requestId: existing.requestId,
        idempotencyKey: existing.idempotencyKey
      });
      platformIntegrationRecoveryDedupIndex.delete(previousDedupKey);
    }
    platformIntegrationRecoveryQueueByRecoveryId.set(persistedRecoveryId, merged);
    const dedupKey = toPlatformIntegrationRecoveryDedupKey({
      integrationId: merged.integrationId,
      contractType: merged.contractType,
      contractVersion: merged.contractVersion,
      requestId: merged.requestId,
      idempotencyKey: merged.idempotencyKey
    });
    platformIntegrationRecoveryDedupIndex.set(dedupKey, persistedRecoveryId);
    return clonePlatformIntegrationRecoveryQueueRecord(merged);
  };
  const upsertPlatformIntegrationFreezeRecord = (entry = {}) => {
    const normalizedRecord = toPlatformIntegrationFreezeRecord(entry);
    const existing = platformIntegrationFreezeById.get(normalizedRecord.freezeId) || null;
    const nowIso = new Date().toISOString();
    const merged = toPlatformIntegrationFreezeRecord({
      ...existing,
      ...normalizedRecord,
      freezeId: normalizedRecord.freezeId,
      createdAt: existing?.createdAt || normalizedRecord.createdAt || nowIso,
      updatedAt: normalizedRecord.updatedAt || nowIso
    });
    platformIntegrationFreezeById.set(merged.freezeId, merged);
    return clonePlatformIntegrationFreezeRecord(merged);
  };

  upsertPlatformRoleCatalogRecord({
    roleId: 'sys_admin',
    code: 'sys_admin',
    name: '系统管理员',
    status: 'active',
    scope: 'platform',
    isSystem: true,
    createdByUserId: null,
    updatedByUserId: null
  });
  replacePlatformRolePermissionGrantsForRoleId({
    roleId: 'sys_admin',
    permissionCodes: KNOWN_PLATFORM_PERMISSION_CODES
  });

  for (const user of seedUsers) {
    const seedCreatedAtCandidate = user.createdAt || user.created_at || null;
    const seedCreatedAtDate = seedCreatedAtCandidate
      ? new Date(seedCreatedAtCandidate)
      : new Date();
    const resolvedCreatedAt = Number.isNaN(seedCreatedAtDate.getTime())
      ? new Date().toISOString()
      : seedCreatedAtDate.toISOString();
    const normalizedUser = {
      id: String(user.id),
      phone: user.phone,
      status: (user.status || 'active').toLowerCase(),
      sessionVersion: Number(user.sessionVersion || 1),
      passwordHash: user.passwordHash || hashPassword(user.password),
      createdAt: resolvedCreatedAt
    };

    usersByPhone.set(normalizedUser.phone, normalizedUser);
    usersById.set(normalizedUser.id, normalizedUser);

    const rawDomains = Array.isArray(user.domains) ? user.domains : ['platform', 'tenant'];
    const domainSet = new Set(
      rawDomains
        .map((domain) => String(domain || '').trim().toLowerCase())
        .filter((domain) => domain === 'platform' || domain === 'tenant')
    );
    domainsByUserId.set(normalizedUser.id, domainSet);
    if (domainSet.has('platform')) {
      platformDomainKnownByUserId.add(normalizedUser.id);
    }

    const rawTenants = Array.isArray(user.tenants) ? user.tenants : [];
    tenantsByUserId.set(
      normalizedUser.id,
      rawTenants
        .filter((tenant) => tenant && tenant.tenantId)
        .map((tenant) => ({
          membershipId: tenant.membershipId
            ? String(tenant.membershipId)
            : randomUUID(),
          tenantId: String(tenant.tenantId),
          tenantName: tenant.tenantName ? String(tenant.tenantName) : null,
          status: normalizeTenantMembershipStatus(tenant.status || 'active'),
          displayName: resolveOptionalTenantMemberProfileField(
            tenant.displayName ?? tenant.display_name ?? null
          ),
          departmentName: resolveOptionalTenantMemberProfileField(
            tenant.departmentName ?? tenant.department_name ?? null
          ),
          joinedAt: tenant.joinedAt || tenant.joined_at || new Date().toISOString(),
          leftAt: tenant.leftAt || tenant.left_at || null,
          permission: tenant.permission
            ? {
              scopeLabel: tenant.permission.scopeLabel || null,
              canViewMemberAdmin: Boolean(tenant.permission.canViewMemberAdmin),
              canOperateMemberAdmin: Boolean(tenant.permission.canOperateMemberAdmin),
              canViewBilling: Boolean(tenant.permission.canViewBilling),
              canOperateBilling: Boolean(tenant.permission.canOperateBilling)
            }
            : null
        }))
    );

    const rawPlatformProfile =
      (user.platformProfile && typeof user.platformProfile === 'object')
      || (user.platform_profile && typeof user.platform_profile === 'object')
        ? (user.platformProfile || user.platform_profile)
        : null;
    if (rawPlatformProfile) {
      const normalizedProfileName = normalizeOptionalTenantMemberProfileField({
        value: rawPlatformProfile.name,
        maxLength: MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH
      });
      const normalizedProfileDepartment = normalizeOptionalTenantMemberProfileField({
        value: rawPlatformProfile.department,
        maxLength: MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH
      });
      platformProfilesByUserId.set(normalizedUser.id, {
        name: normalizedProfileName,
        department: normalizedProfileDepartment
      });
    }

    const rawPlatformRoles = Array.isArray(user.platformRoles) ? user.platformRoles : [];
    const normalizedPlatformRoles = dedupePlatformRolesByRoleId(
      rawPlatformRoles
        .map((role) => normalizePlatformRole(role))
        .filter(Boolean)
    );
    platformRolesByUserId.set(normalizedUser.id, normalizedPlatformRoles);

    let platformPermission = normalizePlatformPermission(user.platformPermission);
    platformPermission = mergePlatformPermission(
      platformPermission,
      mergePlatformPermissionFromRoles(normalizedPlatformRoles)
    );

    if (platformPermission) {
      platformPermissionsByUserId.set(normalizedUser.id, { ...platformPermission });
    }
  }

  const clone = (value) => (value ? { ...value } : null);

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
    const dateValue = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(dateValue.getTime())) {
      return new Date().toISOString();
    }
    return dateValue.toISOString();
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

  const cloneJsonValue = (value) => {
    if (value === null || value === undefined) {
      return null;
    }
    try {
      return JSON.parse(JSON.stringify(value));
    } catch (_error) {
      return null;
    }
  };

  const toAuditEventRecord = (event = {}) => ({
    event_id: normalizeAuditStringOrNull(event.event_id, 64) || '',
    domain: normalizeAuditDomain(event.domain),
    tenant_id: normalizeAuditStringOrNull(event.tenant_id, 64),
    request_id: normalizeAuditStringOrNull(event.request_id, 128) || 'request_id_unset',
    traceparent: normalizeAuditTraceparentOrNull(event.traceparent),
    event_type: normalizeAuditStringOrNull(event.event_type, 128) || '',
    actor_user_id: normalizeAuditStringOrNull(event.actor_user_id, 64),
    actor_session_id: normalizeAuditStringOrNull(event.actor_session_id, 128),
    target_type: normalizeAuditStringOrNull(event.target_type, 64) || '',
    target_id: normalizeAuditStringOrNull(event.target_id, 128),
    result: normalizeAuditResult(event.result) || 'failed',
    before_state: safeParseJsonValue(cloneJsonValue(event.before_state)),
    after_state: safeParseJsonValue(cloneJsonValue(event.after_state)),
    metadata: safeParseJsonValue(cloneJsonValue(event.metadata)),
    occurred_at: normalizeAuditOccurredAt(event.occurred_at)
  });

  const bumpSessionVersionAndConvergeSessions = ({
    userId,
    passwordHash = null,
    reason = 'critical-state-changed',
    revokeRefreshTokens = true,
    revokeAuthSessions = true
  }) => {
    const user = usersById.get(String(userId));
    if (!user) {
      return null;
    }

    if (passwordHash !== null && passwordHash !== undefined) {
      user.passwordHash = passwordHash;
    }
    user.sessionVersion += 1;
    usersByPhone.set(user.phone, user);
    usersById.set(user.id, user);

    if (revokeAuthSessions) {
      for (const session of sessionsById.values()) {
        if (session.userId === String(userId) && session.status === 'active') {
          session.status = 'revoked';
          session.revokedReason = reason;
          session.updatedAt = Date.now();
        }
      }
    }

    if (revokeRefreshTokens) {
      for (const refreshRecord of refreshTokensByHash.values()) {
        if (refreshRecord.userId === String(userId) && refreshRecord.status === 'active') {
          refreshRecord.status = 'revoked';
          refreshRecord.updatedAt = Date.now();
        }
      }
    }

    return clone(user);
  };

  const revokeSessionsForUserByEntryDomain = ({
    userId,
    entryDomain,
    reason,
    activeTenantId = null
  }) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedEntryDomain = String(entryDomain || '').trim().toLowerCase();
    const normalizedActiveTenantId = activeTenantId === null || activeTenantId === undefined
      ? null
      : String(activeTenantId).trim() || null;
    if (!normalizedUserId) {
      return {
        revokedSessionCount: 0,
        revokedRefreshTokenCount: 0
      };
    }
    if (!normalizedEntryDomain) {
      return {
        revokedSessionCount: 0,
        revokedRefreshTokenCount: 0
      };
    }

    const revokedSessionIds = new Set();
    for (const session of sessionsById.values()) {
      if (
        session.userId === normalizedUserId
        && session.status === 'active'
        && String(session.entryDomain || '').trim().toLowerCase() === normalizedEntryDomain
        && (
          normalizedActiveTenantId === null
          || String(session.activeTenantId || '').trim() === normalizedActiveTenantId
        )
      ) {
        session.status = 'revoked';
        session.revokedReason = reason;
        session.updatedAt = Date.now();
        revokedSessionIds.add(String(session.sessionId || '').trim());
      }
    }

    if (revokedSessionIds.size === 0) {
      return {
        revokedSessionCount: 0,
        revokedRefreshTokenCount: 0
      };
    }

    let revokedRefreshTokenCount = 0;
    for (const refreshRecord of refreshTokensByHash.values()) {
      if (
        refreshRecord.status === 'active'
        && revokedSessionIds.has(String(refreshRecord.sessionId || '').trim())
      ) {
        refreshRecord.status = 'revoked';
        refreshRecord.updatedAt = Date.now();
        revokedRefreshTokenCount += 1;
      }
    }
    return {
      revokedSessionCount: revokedSessionIds.size,
      revokedRefreshTokenCount
    };
  };

  const revokePlatformSessionsForUser = ({
    userId,
    reason = 'platform-user-status-changed'
  }) =>
    revokeSessionsForUserByEntryDomain({
      userId,
      entryDomain: 'platform',
      reason
    });

  const revokeTenantSessionsForUser = ({
    userId,
    reason = 'org-status-changed',
    activeTenantId = null
  }) =>
    revokeSessionsForUserByEntryDomain({
      userId,
      entryDomain: 'tenant',
      reason,
      activeTenantId
    });

  const findTenantMembershipStateByMembershipId = (membershipId) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    if (!normalizedMembershipId) {
      return null;
    }
    for (const [userId, memberships] of tenantsByUserId.entries()) {
      for (const membership of Array.isArray(memberships) ? memberships : []) {
        if (String(membership?.membershipId || '').trim() !== normalizedMembershipId) {
          continue;
        }
        return {
          userId: String(userId || '').trim(),
          memberships,
          membership
        };
      }
    }
    return null;
  };

  const listTenantMembershipRoleBindingsForMembershipId = ({
    membershipId,
    tenantId = undefined
  } = {}) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    if (!normalizedMembershipId) {
      return [];
    }
    const membershipState = findTenantMembershipStateByMembershipId(normalizedMembershipId);
    if (!membershipState) {
      return [];
    }
    if (tenantId !== undefined && tenantId !== null) {
      const normalizedTenantId = String(tenantId || '').trim();
      const membershipTenantId = String(
        membershipState.membership?.tenantId || membershipState.membership?.tenant_id || ''
      ).trim();
      if (membershipTenantId !== normalizedTenantId) {
        return [];
      }
    }
    const normalizedRoleIds = [];
    const seenRoleIds = new Set();
    for (const rawRoleId of tenantMembershipRolesByMembershipId.get(normalizedMembershipId) || []) {
      const normalizedRoleId = normalizeStrictTenantMembershipRoleIdFromBindingRow(
        rawRoleId,
        'tenant-membership-role-bindings-invalid-role-id'
      );
      if (seenRoleIds.has(normalizedRoleId)) {
        throw createTenantMembershipRoleBindingDataError(
          'tenant-membership-role-bindings-duplicate-role-id'
        );
      }
      seenRoleIds.add(normalizedRoleId);
      normalizedRoleIds.push(normalizedRoleId);
    }
    return normalizedRoleIds.sort((left, right) => left.localeCompare(right));
  };

  const replaceTenantMembershipRoleBindingsForMembershipId = ({
    membershipId,
    roleIds = []
  } = {}) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    if (!normalizedMembershipId) {
      throw new Error('replaceTenantMembershipRoleBindings requires membershipId');
    }
    const normalizedRoleIds = [...new Set(
      (Array.isArray(roleIds) ? roleIds : [])
        .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
        .filter((roleId) => roleId.length > 0)
    )].sort((left, right) => left.localeCompare(right));
    tenantMembershipRolesByMembershipId.set(normalizedMembershipId, normalizedRoleIds);
    return listTenantMembershipRoleBindingsForMembershipId({
      membershipId: normalizedMembershipId
    });
  };

  const toTenantMembershipScopeLabel = (membership = null) => {
    const tenantId = String(
      membership?.tenantId || membership?.tenant_id || ''
    ).trim();
    const tenantName = membership?.tenantName === null || membership?.tenantName === undefined
      ? null
      : String(membership?.tenantName || '').trim() || null;
    return `组织权限（${tenantName || tenantId || '未知组织'}）`;
  };

  const resolveEffectiveTenantPermissionForMembership = ({
    membership = null,
    roleIds = []
  } = {}) => {
    const scopeLabel = toTenantMembershipScopeLabel(membership);
    if (!membership || !isTenantMembershipActiveForAuth(membership)) {
      return buildEmptyTenantPermission(scopeLabel);
    }
    const membershipTenantId = String(
      membership?.tenantId || membership?.tenant_id || ''
    ).trim();
    let mergedPermission = null;
    for (const roleId of Array.isArray(roleIds) ? roleIds : []) {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        continue;
      }
      const catalogEntry = findPlatformRoleCatalogRecordStateByRoleId(
        normalizedRoleId
      )?.record;
      if (!catalogEntry) {
        continue;
      }
      const normalizedCatalogScope = normalizePlatformRoleCatalogScope(catalogEntry.scope);
      const normalizedCatalogTenantId = normalizePlatformRoleCatalogTenantId(
        catalogEntry.tenantId
      );
      const normalizedCatalogStatus = normalizePlatformRoleCatalogStatus(
        catalogEntry.status
      );
      if (
        normalizedCatalogScope !== 'tenant'
        || normalizedCatalogTenantId !== membershipTenantId
        || !isActiveLikeStatus(normalizedCatalogStatus)
      ) {
        continue;
      }
      const rolePermission = resolveTenantPermissionFromGrantCodes(
        listTenantRolePermissionGrantsForRoleId(normalizedRoleId)
      );
      mergedPermission = mergePlatformPermission(mergedPermission, rolePermission);
    }
    if (!mergedPermission) {
      return buildEmptyTenantPermission(scopeLabel);
    }
    return {
      ...mergedPermission,
      scopeLabel
    };
  };

  const syncTenantMembershipPermissionSnapshot = ({
    membershipState = null,
    reason = 'tenant-membership-permission-changed',
    revokeSessions = true
  } = {}) => {
    const targetMembershipState = membershipState
      || null;
    if (
      !targetMembershipState
      || !targetMembershipState.membership
      || !targetMembershipState.memberships
    ) {
      return {
        synced: false,
        reason: 'membership-not-found',
        changed: false,
        permission: null,
        roleIds: []
      };
    }
    const membership = targetMembershipState.membership;
    const membershipId = String(membership.membershipId || '').trim();
    const tenantId = String(membership.tenantId || '').trim();
    const userId = String(targetMembershipState.userId || '').trim();
    const roleIds = listTenantMembershipRoleBindingsForMembershipId({
      membershipId,
      tenantId
    });
    const previousPermission = normalizePlatformPermission(
      membership.permission,
      toTenantMembershipScopeLabel(membership)
    ) || buildEmptyTenantPermission(toTenantMembershipScopeLabel(membership));
    const nextPermission = resolveEffectiveTenantPermissionForMembership({
      membership,
      roleIds
    });
    const changed = !isSamePlatformPermission(previousPermission, nextPermission);
    membership.permission = { ...nextPermission };
    if (revokeSessions && changed && userId && tenantId) {
      revokeTenantSessionsForUser({
        userId,
        reason,
        activeTenantId: tenantId
      });
    }
    return {
      synced: true,
      reason: 'ok',
      changed,
      permission: { ...nextPermission },
      roleIds: [...roleIds],
      userId,
      membershipId,
      tenantId
    };
  };

  const createForeignKeyConstraintError = () => {
    const error = new Error('Cannot delete or update a parent row: a foreign key constraint fails');
    error.code = 'ER_ROW_IS_REFERENCED_2';
    error.errno = 1451;
    return error;
  };

  const createDataTooLongError = () => {
    const error = new Error('Data too long for column');
    error.code = 'ER_DATA_TOO_LONG';
    error.errno = 1406;
    return error;
  };

  const hasOrgReferenceForUser = (userId) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return false;
    }

    for (const org of orgsById.values()) {
      if (
        String(org?.ownerUserId || '').trim() === normalizedUserId
        || String(org?.createdByUserId || '').trim() === normalizedUserId
      ) {
        return true;
      }
    }
    for (const memberships of membershipsByOrgId.values()) {
      if (!Array.isArray(memberships)) {
        continue;
      }
      if (
        memberships.some(
          (membership) => String(membership?.userId || '').trim() === normalizedUserId
        )
      ) {
        return true;
      }
    }
    return false;
  };

  const restoreMapFromSnapshot = (targetMap, snapshotMap) => {
    targetMap.clear();
    for (const [key, value] of snapshotMap.entries()) {
      targetMap.set(key, value);
    }
  };

  const restoreSetFromSnapshot = (targetSet, snapshotSet) => {
    targetSet.clear();
    for (const value of snapshotSet.values()) {
      targetSet.add(value);
    }
  };

  const restoreAuditEventsFromSnapshot = (snapshotEvents = []) => {
    auditEvents.length = 0;
    for (const event of snapshotEvents) {
      auditEvents.push(event);
    }
  };

  const persistAuditEvent = ({
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
      throw new Error('recordAuditEvent requires valid domain, result, eventType and targetType');
    }
    const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
    if (normalizedDomain === 'tenant' && !normalizedTenantId) {
      throw new Error('recordAuditEvent tenant domain requires tenantId');
    }
    const eventRecord = toAuditEventRecord({
      event_id: normalizeAuditStringOrNull(eventId, 64) || randomUUID(),
      domain: normalizedDomain,
      tenant_id: normalizedTenantId,
      request_id: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
      traceparent: normalizeAuditTraceparentOrNull(traceparent),
      event_type: normalizedEventType,
      actor_user_id: normalizeAuditStringOrNull(actorUserId, 64),
      actor_session_id: normalizeAuditStringOrNull(actorSessionId, 128),
      target_type: normalizedTargetType,
      target_id: normalizeAuditStringOrNull(targetId, 128),
      result: normalizedResult,
      before_state: sanitizeAuditState(beforeState),
      after_state: sanitizeAuditState(afterState),
      metadata: sanitizeAuditState(metadata),
      occurred_at: normalizeAuditOccurredAt(occurredAt)
    });
    auditEvents.push(eventRecord);
    if (auditEvents.length > 5000) {
      auditEvents.splice(0, auditEvents.length - 5000);
    }
    return toAuditEventRecord(eventRecord);
  };

  const normalizeDateTimeFilterToEpoch = ({
    value,
    fieldName
  } = {}) => {
    if (value === null || value === undefined) {
      return null;
    }
    const normalizedValue = String(value || '').trim();
    if (!normalizedValue) {
      return null;
    }
    const parsedDate = new Date(normalizedValue);
    if (Number.isNaN(parsedDate.getTime())) {
      throw new Error(`listPlatformUsers ${fieldName} must be valid datetime`);
    }
    return parsedDate.getTime();
  };

  const resolveLatestPlatformProfileByUserId = (userId) => {
    const profile = platformProfilesByUserId.get(String(userId || '').trim()) || null;
    if (profile && typeof profile === 'object') {
      return {
        name: normalizeOptionalTenantMemberProfileField({
          value: profile.name ?? null,
          maxLength: MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH
        }),
        department: normalizeOptionalTenantMemberProfileField({
          value: profile.department ?? null,
          maxLength: MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH
        })
      };
    }
    return {
      name: null,
      department: null
    };
  };
  const resolveLatestTenantMemberProfileByUserId = (userId) => {
    const memberships = Array.isArray(tenantsByUserId.get(userId))
      ? tenantsByUserId.get(userId)
      : [];
    if (memberships.length < 1) {
      return {
        name: null,
        department: null
      };
    }
    const sortedMemberships = [...memberships].sort((left, right) => {
      const leftJoinedAt = new Date(
        left?.joinedAt || left?.joined_at || 0
      ).getTime();
      const rightJoinedAt = new Date(
        right?.joinedAt || right?.joined_at || 0
      ).getTime();
      return rightJoinedAt - leftJoinedAt;
    });
    for (const membership of sortedMemberships) {
      const resolvedName = normalizeOptionalTenantMemberProfileField({
        value: membership?.displayName ?? membership?.display_name ?? null,
        maxLength: MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH
      });
      const resolvedDepartment = normalizeOptionalTenantMemberProfileField({
        value: membership?.departmentName ?? membership?.department_name ?? null,
        maxLength: MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH
      });
      if (resolvedName !== null || resolvedDepartment !== null) {
        return {
          name: resolvedName,
          department: resolvedDepartment
        };
      }
    }
    return {
      name: null,
      department: null
    };
  };

  const resolvePlatformUserReadModel = ({
    userId,
    userRecord
  } = {}) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedPhone = String(userRecord?.phone || '').trim();
    const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
    const platformStatus = userDomains.has('platform') ? 'active' : 'disabled';
    const profile = resolveLatestPlatformProfileByUserId(normalizedUserId);
    const createdAtRaw = userRecord?.createdAt ?? userRecord?.created_at ?? null;
    const createdAtDate = createdAtRaw ? new Date(createdAtRaw) : new Date();
    const createdAt = Number.isNaN(createdAtDate.getTime())
      ? new Date().toISOString()
      : createdAtDate.toISOString();
    const rawRoles = Array.isArray(platformRolesByUserId.get(normalizedUserId))
      ? platformRolesByUserId.get(normalizedUserId)
      : [];
    const roles = rawRoles
      .filter((role) => role && isActiveLikeStatus(role.status))
      .map((role) => {
        const normalizedRoleId = normalizePlatformRoleCatalogRoleId(role.roleId);
        if (!normalizedRoleId) {
          return null;
        }
        const roleCatalogEntry = findPlatformRoleCatalogRecordStateByRoleId(
          normalizedRoleId
        )?.record || null;
        const roleCode = roleCatalogEntry?.code === null || roleCatalogEntry?.code === undefined
          ? null
          : normalizeRequiredPlatformUserProfileField({
            value: roleCatalogEntry.code,
            maxLength: MAX_PLATFORM_ROLE_CODE_LENGTH,
            fieldName: 'role_code'
          });
        const roleName = roleCatalogEntry?.name === null || roleCatalogEntry?.name === undefined
          ? null
          : normalizeRequiredPlatformUserProfileField({
            value: roleCatalogEntry.name,
            maxLength: MAX_PLATFORM_ROLE_NAME_LENGTH,
            fieldName: 'role_name'
          });
        const normalizedRoleStatus = normalizePlatformRoleCatalogStatus(
          roleCatalogEntry?.status || 'disabled'
        );
        const roleStatus = VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedRoleStatus)
          ? normalizedRoleStatus
          : 'disabled';
        return {
          role_id: normalizedRoleId,
          code: roleCode,
          name: roleName,
          status: roleStatus
        };
      })
      .filter(Boolean)
      .sort((left, right) => String(left.role_id).localeCompare(String(right.role_id)));
    return {
      user_id: normalizedUserId,
      phone: normalizedPhone,
      name: profile.name,
      department: profile.department,
      status: platformStatus,
      created_at: createdAt,
      roles
    };
  };

  return {
    findUserByPhone: async (phone) => clone(usersByPhone.get(phone) || null),

    findUserById: async (userId) => clone(usersById.get(String(userId)) || null),

    updateUserPhone: async ({
      userId,
      phone
    } = {}) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedPhone = String(phone || '').trim();
      if (
        !normalizedUserId
        || !normalizedPhone
        || !MAINLAND_PHONE_PATTERN.test(normalizedPhone)
        || CONTROL_CHAR_PATTERN.test(normalizedPhone)
      ) {
        throw new Error('updateUserPhone requires valid userId and mainland phone');
      }

      const existingUser = usersById.get(normalizedUserId);
      if (!existingUser) {
        return {
          reason: 'invalid-user-id'
        };
      }
      if (String(existingUser.phone || '').trim() === normalizedPhone) {
        return {
          reason: 'no-op',
          user_id: normalizedUserId,
          phone: normalizedPhone
        };
      }

      const phoneOwner = usersByPhone.get(normalizedPhone);
      if (
        phoneOwner
        && String(phoneOwner.id || '').trim() !== normalizedUserId
      ) {
        return {
          reason: 'phone-conflict'
        };
      }

      usersByPhone.delete(String(existingUser.phone || '').trim());
      const updatedUser = {
        ...existingUser,
        phone: normalizedPhone
      };
      usersById.set(normalizedUserId, updatedUser);
      usersByPhone.set(normalizedPhone, updatedUser);
      return {
        reason: 'ok',
        user_id: normalizedUserId,
        phone: normalizedPhone
      };
    },

    listPlatformUsers: async ({
      page = 1,
      pageSize = 20,
      status = null,
      keyword = null,
      phone = null,
      name = null,
      createdAtStart = null,
      createdAtEnd = null
    } = {}) => {
      const resolvedPage = Number(page);
      const resolvedPageSize = Number(pageSize);
      if (
        !Number.isInteger(resolvedPage)
        || resolvedPage <= 0
        || !Number.isInteger(resolvedPageSize)
        || resolvedPageSize <= 0
      ) {
        throw new Error('listPlatformUsers requires positive integer page and pageSize');
      }
      const normalizedStatusFilter =
        status === null || status === undefined || String(status).trim() === ''
          ? null
          : normalizeOrgStatus(status);
      if (
        normalizedStatusFilter !== null
        && !VALID_PLATFORM_USER_STATUS.has(normalizedStatusFilter)
      ) {
        throw new Error('listPlatformUsers status filter must be active or disabled');
      }
      const normalizedKeyword = keyword === null || keyword === undefined
        ? ''
        : String(keyword).trim();
      const normalizedKeywordForMatch = normalizedKeyword.toLowerCase();
      if (CONTROL_CHAR_PATTERN.test(normalizedKeyword)) {
        throw new Error('listPlatformUsers keyword cannot contain control chars');
      }
      const normalizedPhoneFilter = phone === null || phone === undefined
        ? ''
        : String(phone).trim();
      if (CONTROL_CHAR_PATTERN.test(normalizedPhoneFilter)) {
        throw new Error('listPlatformUsers phone cannot contain control chars');
      }
      const normalizedNameFilter = name === null || name === undefined
        ? ''
        : String(name).trim();
      const normalizedNameFilterForMatch = normalizedNameFilter.toLowerCase();
      if (CONTROL_CHAR_PATTERN.test(normalizedNameFilter)) {
        throw new Error('listPlatformUsers name cannot contain control chars');
      }
      const createdAtStartEpoch = normalizeDateTimeFilterToEpoch({
        value: createdAtStart,
        fieldName: 'createdAtStart'
      });
      const createdAtEndEpoch = normalizeDateTimeFilterToEpoch({
        value: createdAtEnd,
        fieldName: 'createdAtEnd'
      });
      if (
        createdAtStartEpoch !== null
        && createdAtEndEpoch !== null
        && createdAtStartEpoch > createdAtEndEpoch
      ) {
        throw new Error('listPlatformUsers createdAtStart cannot be later than createdAtEnd');
      }

      const rows = [];
      for (const [userId, userRecord] of usersById.entries()) {
        if (!platformDomainKnownByUserId.has(userId)) {
          continue;
        }
        const resolvedUser = resolvePlatformUserReadModel({
          userId,
          userRecord
        });
        const platformStatus = resolvedUser.status;
        if (
          normalizedStatusFilter !== null
          && platformStatus !== normalizedStatusFilter
        ) {
          continue;
        }
        if (normalizedPhoneFilter && resolvedUser.phone !== normalizedPhoneFilter) {
          continue;
        }
        if (normalizedNameFilterForMatch) {
          const resolvedName = String(resolvedUser.name || '').toLowerCase();
          if (!resolvedName.includes(normalizedNameFilterForMatch)) {
            continue;
          }
        }
        const createdAtEpoch = new Date(resolvedUser.created_at).getTime();
        if (
          createdAtStartEpoch !== null
          && createdAtEpoch < createdAtStartEpoch
        ) {
          continue;
        }
        if (
          createdAtEndEpoch !== null
          && createdAtEpoch > createdAtEndEpoch
        ) {
          continue;
        }
        if (normalizedKeywordForMatch) {
          const userIdForMatch = String(userId).toLowerCase();
          const phoneForMatch = resolvedUser.phone.toLowerCase();
          const matched =
            userIdForMatch.includes(normalizedKeywordForMatch)
            || phoneForMatch.includes(normalizedKeywordForMatch);
          if (!matched) {
            continue;
          }
        }
        rows.push(resolvedUser);
      }

      rows.sort((left, right) =>
        String(left.user_id).localeCompare(String(right.user_id))
      );

      const total = rows.length;
      const offset = (resolvedPage - 1) * resolvedPageSize;
      return {
        total,
        items: rows.slice(offset, offset + resolvedPageSize)
      };
    },

    listPlatformOrgs: async ({
      page = 1,
      pageSize = 20,
      orgName = null,
      owner = null,
      status = null,
      createdAtStart = null,
      createdAtEnd = null
    } = {}) => {
      const resolvedPage = Number(page);
      const resolvedPageSize = Number(pageSize);
      if (
        !Number.isInteger(resolvedPage)
        || resolvedPage <= 0
        || !Number.isInteger(resolvedPageSize)
        || resolvedPageSize <= 0
      ) {
        throw new Error('listPlatformOrgs requires positive integer page and pageSize');
      }

      const normalizedOrgNameFilter = orgName === null || orgName === undefined
        ? ''
        : String(orgName).trim();
      if (CONTROL_CHAR_PATTERN.test(normalizedOrgNameFilter)) {
        throw new Error('listPlatformOrgs orgName cannot contain control chars');
      }

      const normalizedOwnerFilter = owner === null || owner === undefined
        ? ''
        : String(owner).trim();
      const normalizedOwnerFilterForMatch = normalizedOwnerFilter.toLowerCase();
      if (CONTROL_CHAR_PATTERN.test(normalizedOwnerFilter)) {
        throw new Error('listPlatformOrgs owner cannot contain control chars');
      }

      const normalizedStatusFilter =
        status === null || status === undefined || String(status).trim() === ''
          ? null
          : normalizeOrgStatus(status);
      if (
        normalizedStatusFilter !== null
        && !VALID_ORG_STATUS.has(normalizedStatusFilter)
      ) {
        throw new Error('listPlatformOrgs status filter must be active or disabled');
      }

      const createdAtStartEpoch = normalizeDateTimeFilterToEpoch({
        value: createdAtStart,
        fieldName: 'createdAtStart'
      });
      const createdAtEndEpoch = normalizeDateTimeFilterToEpoch({
        value: createdAtEnd,
        fieldName: 'createdAtEnd'
      });
      if (
        createdAtStartEpoch !== null
        && createdAtEndEpoch !== null
        && createdAtStartEpoch > createdAtEndEpoch
      ) {
        throw new Error('listPlatformOrgs createdAtStart cannot be later than createdAtEnd');
      }

      const rows = [];
      for (const org of orgsById.values()) {
        const orgId = String(org?.id || '').trim();
        const resolvedOrgName = String(org?.name || '').trim();
        const normalizedStatus = normalizeOrgStatus(org?.status);
        const ownerUserId = String(org?.ownerUserId || '').trim();
        const ownerUser = usersById.get(ownerUserId);
        const ownerPhone = String(ownerUser?.phone || '').trim();
        const ownerProfile = resolveLatestTenantMemberProfileByUserId(ownerUserId);
        const ownerName = ownerProfile.name;
        const createdAtRaw = org?.createdAt ?? org?.created_at ?? null;
        const createdAtDate = createdAtRaw ? new Date(createdAtRaw) : null;
        const createdAt = createdAtDate && !Number.isNaN(createdAtDate.getTime())
          ? createdAtDate.toISOString()
          : '';

        if (
          !orgId
          || !resolvedOrgName
          || !ownerUserId
          || !ownerPhone
          || !VALID_ORG_STATUS.has(normalizedStatus)
          || !createdAt
        ) {
          throw new Error('listPlatformOrgs returned invalid organization shape');
        }

        if (
          normalizedStatusFilter !== null
          && normalizedStatus !== normalizedStatusFilter
        ) {
          continue;
        }
        if (
          normalizedOrgNameFilter
          && !resolvedOrgName.toLowerCase().includes(normalizedOrgNameFilter.toLowerCase())
        ) {
          continue;
        }
        if (normalizedOwnerFilter) {
          const ownerNameForMatch = String(ownerName || '').toLowerCase();
          const ownerNameMatched = ownerNameForMatch.includes(normalizedOwnerFilterForMatch);
          const ownerPhoneMatched = ownerPhone === normalizedOwnerFilter;
          if (!ownerNameMatched && !ownerPhoneMatched) {
            continue;
          }
        }

        const createdAtEpoch = new Date(createdAt).getTime();
        if (
          createdAtStartEpoch !== null
          && createdAtEpoch < createdAtStartEpoch
        ) {
          continue;
        }
        if (
          createdAtEndEpoch !== null
          && createdAtEpoch > createdAtEndEpoch
        ) {
          continue;
        }

        rows.push({
          org_id: orgId,
          org_name: resolvedOrgName,
          owner_name: ownerName,
          owner_phone: ownerPhone,
          status: normalizedStatus,
          created_at: createdAt
        });
      }

      rows.sort((left, right) =>
        String(left.org_id).localeCompare(String(right.org_id))
      );

      const total = rows.length;
      const offset = (resolvedPage - 1) * resolvedPageSize;
      return {
        total,
        items: rows.slice(offset, offset + resolvedPageSize)
      };
    },

    getPlatformUserById: async ({ userId } = {}) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return null;
      }
      if (!platformDomainKnownByUserId.has(normalizedUserId)) {
        return null;
      }
      const userRecord = usersById.get(normalizedUserId);
      if (!userRecord) {
        return null;
      }
      return resolvePlatformUserReadModel({
        userId: normalizedUserId,
        userRecord
      });
    },

    upsertPlatformUserProfile: async ({
      userId,
      name,
      department = null
    } = {}) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId || !usersById.has(normalizedUserId)) {
        throw new Error('upsertPlatformUserProfile requires existing userId');
      }
      const normalizedName = normalizeRequiredPlatformUserProfileField({
        value: name,
        maxLength: MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH,
        fieldName: 'name'
      });
      const normalizedDepartment = normalizeOptionalPlatformUserProfileField({
        value: department,
        maxLength: MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH,
        fieldName: 'department'
      });
      const nextProfile = {
        name: normalizedName,
        department: normalizedDepartment
      };
      platformProfilesByUserId.set(normalizedUserId, nextProfile);
      return {
        user_id: normalizedUserId,
        ...nextProfile
      };
    },

    recordAuditEvent: async (payload = {}) =>
      persistAuditEvent(payload),

    listAuditEvents: async ({
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
        throw new Error('listAuditEvents requires valid domain');
      }
      const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
      if (normalizedDomain === 'tenant' && !normalizedTenantId) {
        throw new Error('listAuditEvents tenant domain requires tenantId');
      }
      const normalizedEventType = normalizeAuditStringOrNull(eventType, 128);
      const normalizedResult = normalizeAuditResult(result);
      const normalizedRequestId = normalizeAuditStringOrNull(requestId, 128);
      let normalizedTraceparent = null;
      if (traceparent !== null && traceparent !== undefined) {
        normalizedTraceparent = normalizeAuditTraceparentOrNull(traceparent);
        if (!normalizedTraceparent) {
          throw new Error('listAuditEvents requires valid traceparent');
        }
      }
      const normalizedActorUserId = normalizeAuditStringOrNull(actorUserId, 64);
      const normalizedTargetType = normalizeAuditStringOrNull(targetType, 64);
      const normalizedTargetId = normalizeAuditStringOrNull(targetId, 128);
      const fromDate = from ? new Date(from) : null;
      const toDate = to ? new Date(to) : null;
      if (
        fromDate && toDate
        && !Number.isNaN(fromDate.getTime())
        && !Number.isNaN(toDate.getTime())
        && fromDate.getTime() > toDate.getTime()
      ) {
        throw new Error('listAuditEvents requires from <= to');
      }
      const filtered = auditEvents.filter((event) => {
        if (normalizeAuditDomain(event.domain) !== normalizedDomain) {
          return false;
        }
        if (normalizedTenantId && normalizeAuditStringOrNull(event.tenant_id, 64) !== normalizedTenantId) {
          return false;
        }
        if (normalizedEventType && normalizeAuditStringOrNull(event.event_type, 128) !== normalizedEventType) {
          return false;
        }
        if (normalizedResult && normalizeAuditResult(event.result) !== normalizedResult) {
          return false;
        }
        if (normalizedRequestId && normalizeAuditStringOrNull(event.request_id, 128) !== normalizedRequestId) {
          return false;
        }
        if (
          normalizedTraceparent
          && normalizeAuditTraceparentOrNull(event.traceparent) !== normalizedTraceparent
        ) {
          return false;
        }
        if (normalizedActorUserId && normalizeAuditStringOrNull(event.actor_user_id, 64) !== normalizedActorUserId) {
          return false;
        }
        if (normalizedTargetType && normalizeAuditStringOrNull(event.target_type, 64) !== normalizedTargetType) {
          return false;
        }
        if (normalizedTargetId && normalizeAuditStringOrNull(event.target_id, 128) !== normalizedTargetId) {
          return false;
        }
        const occurredAt = new Date(event.occurred_at);
        if (fromDate && !Number.isNaN(fromDate.getTime()) && occurredAt < fromDate) {
          return false;
        }
        if (toDate && !Number.isNaN(toDate.getTime()) && occurredAt > toDate) {
          return false;
        }
        return true;
      });
      filtered.sort((left, right) => {
        const leftTime = new Date(left.occurred_at).getTime();
        const rightTime = new Date(right.occurred_at).getTime();
        if (rightTime !== leftTime) {
          return rightTime - leftTime;
        }
        return String(right.event_id || '').localeCompare(String(left.event_id || ''));
      });
      const total = filtered.length;
      const resolvedPage = Math.max(1, Math.floor(Number(page || 1)));
      const resolvedPageSize = Math.min(
        MAX_AUDIT_QUERY_PAGE_SIZE,
        Math.max(1, Math.floor(Number(pageSize || 50)))
      );
      const offset = (resolvedPage - 1) * resolvedPageSize;
      return {
        total,
        events: filtered
          .slice(offset, offset + resolvedPageSize)
          .map((event) => toAuditEventRecord(event))
      };
    },

    getSystemSensitiveConfig: async ({ configKey } = {}) => {
      const normalizedConfigKey = normalizeSystemSensitiveConfigKey(configKey);
      if (!normalizedConfigKey || !ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(normalizedConfigKey)) {
        return null;
      }
      return cloneSystemSensitiveConfigRecord(
        systemSensitiveConfigsByKey.get(normalizedConfigKey) || null
      );
    },

    upsertSystemSensitiveConfig: async ({
      configKey,
      encryptedValue,
      expectedVersion,
      updatedByUserId,
      status = 'active'
    } = {}) => {
      const normalizedConfigKey = normalizeSystemSensitiveConfigKey(configKey);
      if (!normalizedConfigKey || !ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(normalizedConfigKey)) {
        throw new Error('upsertSystemSensitiveConfig requires whitelisted configKey');
      }
      const normalizedEncryptedValue = String(encryptedValue || '').trim();
      if (
        !normalizedEncryptedValue
        || CONTROL_CHAR_PATTERN.test(normalizedEncryptedValue)
      ) {
        throw new Error('upsertSystemSensitiveConfig requires encryptedValue');
      }
      const normalizedUpdatedByUserId = String(updatedByUserId || '').trim();
      if (!normalizedUpdatedByUserId || !usersById.has(normalizedUpdatedByUserId)) {
        throw new Error('upsertSystemSensitiveConfig requires existing updatedByUserId');
      }
      const normalizedStatus = normalizeSystemSensitiveConfigStatus(status);
      if (!normalizedStatus) {
        throw new Error('upsertSystemSensitiveConfig received unsupported status');
      }
      const parsedExpectedVersion = Number(expectedVersion);
      if (
        !Number.isInteger(parsedExpectedVersion)
        || parsedExpectedVersion < 0
      ) {
        throw new Error('upsertSystemSensitiveConfig requires expectedVersion >= 0');
      }

      const existingRecord = systemSensitiveConfigsByKey.get(normalizedConfigKey) || null;
      const currentVersion = existingRecord ? Number(existingRecord.version || 0) : 0;
      if (parsedExpectedVersion !== currentVersion) {
        const conflictError = new Error('system sensitive config version conflict');
        conflictError.code = 'ERR_SYSTEM_SENSITIVE_CONFIG_VERSION_CONFLICT';
        conflictError.currentVersion = currentVersion;
        conflictError.expectedVersion = parsedExpectedVersion;
        conflictError.configKey = normalizedConfigKey;
        throw conflictError;
      }

      const nextVersion = currentVersion + 1;
      const nowIso = new Date().toISOString();
      const nextRecord = {
        configKey: normalizedConfigKey,
        encryptedValue: normalizedEncryptedValue,
        version: nextVersion,
        previousVersion: currentVersion,
        status: normalizedStatus,
        updatedByUserId: normalizedUpdatedByUserId,
        updatedAt: nowIso,
        createdByUserId: existingRecord?.createdByUserId || normalizedUpdatedByUserId,
        createdAt: existingRecord?.createdAt || nowIso
      };
      systemSensitiveConfigsByKey.set(normalizedConfigKey, nextRecord);
      return cloneSystemSensitiveConfigRecord(nextRecord);
    },

    createUserByPhone: async ({ phone, passwordHash, status = 'active' }) => {
      const normalizedPhone = String(phone || '').trim();
      const normalizedPasswordHash = String(passwordHash || '').trim();
      if (!normalizedPhone || !normalizedPasswordHash) {
        throw new Error('createUserByPhone requires phone and passwordHash');
      }
      if (usersByPhone.has(normalizedPhone)) {
        return null;
      }
      const normalizedStatus = String(status || 'active').trim().toLowerCase() || 'active';
      const user = {
        id: randomUUID(),
        phone: normalizedPhone,
        passwordHash: normalizedPasswordHash,
        status: normalizedStatus,
        sessionVersion: 1,
        createdAt: new Date().toISOString()
      };
      usersByPhone.set(normalizedPhone, user);
      usersById.set(user.id, user);
      if (!domainsByUserId.has(user.id)) {
        domainsByUserId.set(user.id, new Set());
      }
      if (!tenantsByUserId.has(user.id)) {
        tenantsByUserId.set(user.id, []);
      }
      return clone(user);
    },

    createOrganizationWithOwner: async ({
      orgId = randomUUID(),
      orgName,
      ownerDisplayName = null,
      ownerUserId,
      operatorUserId,
      operatorSessionId = null,
      auditContext = null
    }) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = {
        orgsById: structuredClone(orgsById),
        orgIdByName: structuredClone(orgIdByName),
        membershipsByOrgId: structuredClone(membershipsByOrgId),
        tenantsByUserId: structuredClone(tenantsByUserId),
        tenantMembershipRolesByMembershipId: structuredClone(
          tenantMembershipRolesByMembershipId
        ),
        tenantMembershipHistoryByPair: structuredClone(tenantMembershipHistoryByPair),
        domainsByUserId: structuredClone(domainsByUserId),
        platformRoleCatalogById: structuredClone(platformRoleCatalogById),
        platformRoleCatalogCodeIndex: structuredClone(platformRoleCatalogCodeIndex),
        tenantRolePermissionGrantsByRoleId: structuredClone(
          tenantRolePermissionGrantsByRoleId
        ),
        sessionsById: structuredClone(sessionsById),
        refreshTokensByHash: structuredClone(refreshTokensByHash),
        auditEvents: structuredClone(auditEvents)
      };
      try {
        const normalizedOrgId = String(orgId || '').trim() || randomUUID();
        const normalizedOrgName = String(orgName || '').trim();
        const normalizedOwnerDisplayName = normalizeOptionalTenantMemberProfileField({
          value: ownerDisplayName,
          maxLength: MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH
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
        if (!usersById.has(normalizedOwnerUserId) || !usersById.has(normalizedOperatorUserId)) {
          throw new Error('createOrganizationWithOwner requires existing owner and operator users');
        }
        if (normalizedOrgName.length > MAX_ORG_NAME_LENGTH) {
          throw createDataTooLongError();
        }

        const orgNameDedupeKey = normalizedOrgName.toLowerCase();
        if (orgIdByName.has(orgNameDedupeKey)) {
          const duplicateError = new Error('duplicate org name');
          duplicateError.code = 'ER_DUP_ENTRY';
          duplicateError.errno = 1062;
          throw duplicateError;
        }
        if (orgsById.has(normalizedOrgId)) {
          const duplicateError = new Error('duplicate org id');
          duplicateError.code = 'ER_DUP_ENTRY';
          duplicateError.errno = 1062;
          throw duplicateError;
        }

        const nowIso = new Date().toISOString();
        orgsById.set(normalizedOrgId, {
          id: normalizedOrgId,
          name: normalizedOrgName,
          ownerUserId: normalizedOwnerUserId,
          createdByUserId: normalizedOperatorUserId,
          status: 'active',
          createdAt: nowIso,
          updatedAt: nowIso
        });
        orgIdByName.set(orgNameDedupeKey, normalizedOrgId);
        membershipsByOrgId.set(normalizedOrgId, [
          {
            orgId: normalizedOrgId,
            userId: normalizedOwnerUserId,
            membershipRole: 'owner',
            status: 'active'
          }
        ]);
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

        const tenantMemberships = Array.isArray(tenantsByUserId.get(normalizedOwnerUserId))
          ? tenantsByUserId.get(normalizedOwnerUserId)
          : [];
        let membership = tenantMemberships.find(
          (tenant) => String(tenant?.tenantId || '').trim() === normalizedOrgId
        ) || null;
        if (!membership) {
          membership = {
            membershipId: randomUUID(),
            tenantId: normalizedOrgId,
            tenantName: normalizedOrgName,
            status: 'active',
            displayName: normalizedOwnerDisplayName,
            departmentName: null,
            joinedAt: nowIso,
            leftAt: null,
            permission: buildEmptyTenantPermission(
              `组织权限（${normalizedOrgName || normalizedOrgId}）`
            )
          };
          tenantMemberships.push(membership);
          tenantMembershipRolesByMembershipId.set(
            String(membership.membershipId || '').trim(),
            []
          );
        } else {
          const normalizedMembershipStatus = normalizeTenantMembershipStatusForRead(
            membership.status
          );
          if (
            normalizedMembershipStatus !== 'active'
            && normalizedMembershipStatus !== 'disabled'
            && normalizedMembershipStatus !== 'left'
          ) {
            throw new Error('org-owner-membership-status-invalid');
          }
          membership.tenantName = normalizedOrgName;
          if (normalizedMembershipStatus === 'left') {
            appendTenantMembershipHistory({
              membership: {
                ...membership,
                userId: normalizedOwnerUserId,
                tenantId: normalizedOrgId
              },
              reason: 'rejoin',
              operatorUserId: normalizedOperatorUserId
            });
            const previousMembershipId = String(
              membership.membershipId || ''
            ).trim();
            membership.membershipId = randomUUID();
            membership.status = 'active';
            membership.permission = buildEmptyTenantPermission(
              toTenantMembershipScopeLabel(membership)
            );
            membership.joinedAt = nowIso;
            membership.leftAt = null;
            if (previousMembershipId) {
              tenantMembershipRolesByMembershipId.delete(previousMembershipId);
            }
            tenantMembershipRolesByMembershipId.set(
              String(membership.membershipId || '').trim(),
              []
            );
          } else if (normalizedMembershipStatus === 'disabled') {
            membership.status = 'active';
            membership.leftAt = null;
          }
          if (normalizedOwnerDisplayName !== null) {
            membership.displayName = normalizedOwnerDisplayName;
          }
          if (!membership.joinedAt) {
            membership.joinedAt = nowIso;
          }
        }
        tenantsByUserId.set(normalizedOwnerUserId, tenantMemberships);

        const resolvedMembershipId = String(membership?.membershipId || '').trim();
        if (!resolvedMembershipId) {
          throw new Error('org-owner-membership-resolution-failed');
        }

        const userDomains = domainsByUserId.get(normalizedOwnerUserId) || new Set();
        userDomains.add('tenant');
        domainsByUserId.set(normalizedOwnerUserId, userDomains);

        const createRoleInvalidError = () => {
          const roleInvalidError = new Error(
            'owner transfer takeover role definition invalid'
          );
          roleInvalidError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_INVALID';
          return roleInvalidError;
        };
        let existingRole = findPlatformRoleCatalogRecordStateByRoleId(
          normalizedTakeoverRoleId
        )?.record || null;
        if (!existingRole) {
          try {
            upsertPlatformRoleCatalogRecord({
              roleId: normalizedTakeoverRoleId,
              code: normalizedTakeoverRoleCode,
              name: normalizedTakeoverRoleName,
              status: 'active',
              scope: 'tenant',
              tenantId: normalizedOrgId,
              isSystem: true,
              createdByUserId: normalizedOperatorUserId,
              updatedByUserId: normalizedOperatorUserId
            });
          } catch (error) {
            if (String(error?.code || '').trim().toUpperCase() === 'ER_DUP_ENTRY') {
              existingRole = findPlatformRoleCatalogRecordStateByRoleId(
                normalizedTakeoverRoleId
              )?.record || null;
              if (!existingRole) {
                throw createRoleInvalidError();
              }
            } else {
              throw error;
            }
          }
        }
        if (!existingRole) {
          existingRole = findPlatformRoleCatalogRecordStateByRoleId(
            normalizedTakeoverRoleId
          )?.record || null;
        }
        if (!existingRole) {
          throw createRoleInvalidError();
        }
        const normalizedRoleScope = normalizePlatformRoleCatalogScope(existingRole.scope);
        const normalizedRoleTenantId = normalizePlatformRoleCatalogTenantId(
          existingRole.tenantId
        );
        const normalizedRoleCode = normalizePlatformRoleCatalogCode(existingRole.code);
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
          existingRole.status || 'disabled'
        );
        if (!isActiveLikeStatus(normalizedRoleStatus)) {
          upsertPlatformRoleCatalogRecord({
            ...existingRole,
            roleId: normalizedTakeoverRoleId,
            status: 'active',
            updatedByUserId: normalizedOperatorUserId
          });
        }

        const grantCodes = new Set(
          listTenantRolePermissionGrantsForRoleId(normalizedTakeoverRoleId)
        );
        for (const permissionCode of normalizedRequiredPermissionCodes) {
          grantCodes.add(permissionCode);
        }
        replaceTenantRolePermissionGrantsForRoleId({
          roleId: normalizedTakeoverRoleId,
          permissionCodes: [...grantCodes]
        });

        const existingRoleIds = listTenantMembershipRoleBindingsForMembershipId({
          membershipId: resolvedMembershipId,
          tenantId: normalizedOrgId
        });
        const nextRoleIds = [...new Set([
          ...existingRoleIds,
          normalizedTakeoverRoleId
        ])].sort((left, right) => left.localeCompare(right));
        if (nextRoleIds.length < 1) {
          const roleBindingError = new Error(
            'owner transfer takeover role binding invalid'
          );
          roleBindingError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_BINDINGS_INVALID';
          throw roleBindingError;
        }
        replaceTenantMembershipRoleBindingsForMembershipId({
          membershipId: resolvedMembershipId,
          roleIds: nextRoleIds
        });

        const membershipState = findTenantMembershipStateByMembershipId(
          resolvedMembershipId
        );
        const syncResult = syncTenantMembershipPermissionSnapshot({
          membershipState,
          reason: 'org-owner-bootstrap'
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
          !Boolean(effectivePermission.canViewMemberAdmin)
          || !Boolean(effectivePermission.canOperateMemberAdmin)
        ) {
          const permissionInsufficientError = new Error(
            'owner transfer takeover permission insufficient'
          );
          permissionInsufficientError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_PERMISSION_INSUFFICIENT';
          throw permissionInsufficientError;
        }

        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
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
                org_name: normalizedOrgName,
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
      } catch (error) {
        restoreMapFromSnapshot(orgsById, snapshot.orgsById);
        restoreMapFromSnapshot(orgIdByName, snapshot.orgIdByName);
        restoreMapFromSnapshot(membershipsByOrgId, snapshot.membershipsByOrgId);
        restoreMapFromSnapshot(tenantsByUserId, snapshot.tenantsByUserId);
        restoreMapFromSnapshot(
          tenantMembershipRolesByMembershipId,
          snapshot.tenantMembershipRolesByMembershipId
        );
        restoreMapFromSnapshot(
          tenantMembershipHistoryByPair,
          snapshot.tenantMembershipHistoryByPair
        );
        restoreMapFromSnapshot(domainsByUserId, snapshot.domainsByUserId);
        restoreMapFromSnapshot(platformRoleCatalogById, snapshot.platformRoleCatalogById);
        restoreMapFromSnapshot(
          platformRoleCatalogCodeIndex,
          snapshot.platformRoleCatalogCodeIndex
        );
        restoreMapFromSnapshot(
          tenantRolePermissionGrantsByRoleId,
          snapshot.tenantRolePermissionGrantsByRoleId
        );
        restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
        restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
        restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        throw error;
      }
    },

    findOrganizationById: async ({ orgId }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return null;
      }
      const org = orgsById.get(normalizedOrgId);
      if (!org) {
        return null;
      }
      return {
        org_id: normalizedOrgId,
        org_name: String(org.name || '').trim(),
        owner_user_id: String(org.ownerUserId || '').trim(),
        status: normalizeOrgStatus(org.status),
        created_by_user_id: org.createdByUserId
          ? String(org.createdByUserId).trim()
          : null
      };
    },

    acquireOwnerTransferLock: async ({
      orgId,
      requestId,
      operatorUserId
    }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return false;
      }
      if (ownerTransferLocksByOrgId.has(normalizedOrgId)) {
        return false;
      }
      ownerTransferLocksByOrgId.set(normalizedOrgId, {
        request_id: String(requestId || '').trim() || 'request_id_unset',
        operator_user_id: String(operatorUserId || '').trim() || 'unknown',
        started_at: new Date().toISOString()
      });
      return true;
    },

    releaseOwnerTransferLock: async ({ orgId }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return false;
      }
      return ownerTransferLocksByOrgId.delete(normalizedOrgId);
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
      takeoverRoleName = 'sys_admin',
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
      const normalizedTakeoverRoleCode = normalizePlatformRoleCatalogCode(
        takeoverRoleCode
      );
      const normalizedTakeoverRoleName = String(takeoverRoleName || '').trim();
      const normalizedRequiredPermissionCodes = normalizeTenantPermissionCodes(
        requiredPermissionCodes
      );
      const missingRequiredPermissionCodes = [
        TENANT_MEMBER_ADMIN_VIEW_PERMISSION_CODE,
        TENANT_MEMBER_ADMIN_OPERATE_PERMISSION_CODE
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

      const snapshot = {
        orgsById: structuredClone(orgsById),
        tenantsByUserId: structuredClone(tenantsByUserId),
        domainsByUserId: structuredClone(domainsByUserId),
        platformRoleCatalogById: structuredClone(platformRoleCatalogById),
        platformRoleCatalogCodeIndex: structuredClone(platformRoleCatalogCodeIndex),
        tenantRolePermissionGrantsByRoleId: structuredClone(
          tenantRolePermissionGrantsByRoleId
        ),
        tenantMembershipRolesByMembershipId: structuredClone(
          tenantMembershipRolesByMembershipId
        ),
        tenantMembershipHistoryByPair: structuredClone(tenantMembershipHistoryByPair),
        sessionsById: structuredClone(sessionsById),
        refreshTokensByHash: structuredClone(refreshTokensByHash)
      };
      const restoreMap = (target, source) => {
        target.clear();
        for (const [key, value] of source.entries()) {
          target.set(key, value);
        }
      };

      try {
        const org = orgsById.get(normalizedOrgId) || null;
        if (!org) {
          const orgNotFoundError = new Error(
            'owner transfer takeover organization not found'
          );
          orgNotFoundError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ORG_NOT_FOUND';
          throw orgNotFoundError;
        }
        const currentOrgStatus = normalizeOrgStatus(org.status);
        const currentOwnerUserId = String(org.ownerUserId || '').trim();
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

        const newOwner = usersById.get(normalizedNewOwnerUserId) || null;
        if (!newOwner) {
          const newOwnerNotFoundError = new Error(
            'owner transfer takeover new owner not found'
          );
          newOwnerNotFoundError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_NEW_OWNER_NOT_FOUND';
          throw newOwnerNotFoundError;
        }
        if (
          !isActiveLikeStatus(
            String(newOwner?.status || '').trim().toLowerCase() || 'disabled'
          )
        ) {
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

        const existingRoleState = findPlatformRoleCatalogRecordStateByRoleId(
          normalizedTakeoverRoleId
        );
        const existingRole = existingRoleState?.record || null;
        if (!existingRole) {
          try {
            upsertPlatformRoleCatalogRecord({
              roleId: normalizedTakeoverRoleId,
              code: normalizedTakeoverRoleCode,
              name: normalizedTakeoverRoleName,
              status: 'active',
              scope: 'tenant',
              tenantId: normalizedOrgId,
              isSystem: true,
              createdByUserId: normalizedOperatorUserId,
              updatedByUserId: normalizedOperatorUserId
            });
          } catch (error) {
            if (String(error?.code || '').trim().toUpperCase() === 'ER_DUP_ENTRY') {
              throw createRoleInvalidError();
            }
            throw error;
          }
        } else {
          const roleScope = normalizePlatformRoleCatalogScope(existingRole.scope);
          const roleTenantId = normalizePlatformRoleCatalogTenantId(
            existingRole.tenantId
          );
          const roleCode = normalizePlatformRoleCatalogCode(existingRole.code);
          if (roleScope !== 'tenant' || roleTenantId !== normalizedOrgId) {
            throw createRoleInvalidError();
          }
          if (
            !roleCode
            || roleCode.toLowerCase() !== normalizedTakeoverRoleCode.toLowerCase()
          ) {
            throw createRoleInvalidError();
          }
          const roleStatus = normalizePlatformRoleCatalogStatus(
            existingRole.status || 'disabled'
          );
          if (!isActiveLikeStatus(roleStatus)) {
            upsertPlatformRoleCatalogRecord({
              ...existingRole,
              roleId: normalizedTakeoverRoleId,
              status: 'active',
              updatedByUserId: normalizedOperatorUserId
            });
          }
        }

        const grantCodes = new Set(
          listTenantRolePermissionGrantsForRoleId(normalizedTakeoverRoleId)
        );
        for (const permissionCode of normalizedRequiredPermissionCodes) {
          grantCodes.add(permissionCode);
        }
        replaceTenantRolePermissionGrantsForRoleId({
          roleId: normalizedTakeoverRoleId,
          permissionCodes: [...grantCodes]
        });

        org.ownerUserId = normalizedNewOwnerUserId;
        orgsById.set(normalizedOrgId, org);
        invokeFaultInjector('afterOwnerTransferTakeoverOwnerSwitch', {
          requestId: normalizedRequestId,
          orgId: normalizedOrgId,
          oldOwnerUserId: normalizedOldOwnerUserId,
          newOwnerUserId: normalizedNewOwnerUserId
        });

        const tenantMemberships = tenantsByUserId.get(normalizedNewOwnerUserId) || [];
        let membership = tenantMemberships.find(
          (item) => String(item?.tenantId || '').trim() === normalizedOrgId
        ) || null;
        if (!membership) {
          membership = {
            membershipId: randomUUID(),
            tenantId: normalizedOrgId,
            tenantName: null,
            status: 'active',
            displayName: null,
            departmentName: null,
            joinedAt: new Date().toISOString(),
            leftAt: null,
            permission: buildEmptyTenantPermission(
              `组织权限（${normalizedOrgId}）`
            )
          };
          tenantMemberships.push(membership);
          tenantMembershipRolesByMembershipId.set(
            String(membership.membershipId || '').trim(),
            []
          );
        } else {
          const normalizedMembershipStatus = normalizeTenantMembershipStatusForRead(
            membership.status
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
            appendTenantMembershipHistory({
              membership: {
                ...membership,
                userId: normalizedNewOwnerUserId,
                tenantId: normalizedOrgId
              },
              reason: 'rejoin',
              operatorUserId: normalizedOperatorUserId
            });
            const previousMembershipId = String(
              membership.membershipId || ''
            ).trim();
            membership.membershipId = randomUUID();
            membership.status = 'active';
            membership.leftAt = null;
            membership.joinedAt = new Date().toISOString();
            membership.permission = buildEmptyTenantPermission(
              toTenantMembershipScopeLabel(membership)
            );
            if (previousMembershipId) {
              tenantMembershipRolesByMembershipId.delete(previousMembershipId);
            }
            tenantMembershipRolesByMembershipId.set(
              String(membership.membershipId || '').trim(),
              []
            );
          } else if (normalizedMembershipStatus === 'disabled') {
            membership.status = 'active';
            membership.leftAt = null;
            membership.permission = buildEmptyTenantPermission(
              toTenantMembershipScopeLabel(membership)
            );
          }
        }
        tenantsByUserId.set(normalizedNewOwnerUserId, tenantMemberships);

        const membershipId = String(membership?.membershipId || '').trim();
        if (!membershipId) {
          const membershipResolveError = new Error(
            'owner transfer takeover membership resolution failed'
          );
          membershipResolveError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_MEMBERSHIP_INVALID';
          throw membershipResolveError;
        }

        const userDomains = domainsByUserId.get(normalizedNewOwnerUserId) || new Set();
        userDomains.add('tenant');
        domainsByUserId.set(normalizedNewOwnerUserId, userDomains);

        const existingRoleIds = listTenantMembershipRoleBindingsForMembershipId({
          membershipId,
          tenantId: normalizedOrgId
        });
        const nextRoleIds = [...new Set([
          ...existingRoleIds,
          normalizedTakeoverRoleId
        ])].sort((left, right) => left.localeCompare(right));
        if (nextRoleIds.length < 1) {
          const roleBindingError = new Error(
            'owner transfer takeover role binding invalid'
          );
          roleBindingError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_BINDINGS_INVALID';
          throw roleBindingError;
        }
        replaceTenantMembershipRoleBindingsForMembershipId({
          membershipId,
          roleIds: nextRoleIds
        });

        const membershipState = findTenantMembershipStateByMembershipId(
          membershipId
        );
        const syncResult = syncTenantMembershipPermissionSnapshot({
          membershipState,
          reason: 'owner-transfer-takeover'
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
        if (
          !Boolean(syncResult?.permission?.canViewMemberAdmin)
          || !Boolean(syncResult?.permission?.canOperateMemberAdmin)
        ) {
          const permissionInsufficientError = new Error(
            'owner transfer takeover permission insufficient'
          );
          permissionInsufficientError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_PERMISSION_INSUFFICIENT';
          throw permissionInsufficientError;
        }

        invokeFaultInjector('beforeOwnerTransferTakeoverCommit', {
          requestId: normalizedRequestId,
          orgId: normalizedOrgId,
          membershipId
        });

        let auditRecorded = false;
        if (auditContext && typeof auditContext === 'object') {
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedOrgId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.org.owner_transfer.executed',
              actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
              actorSessionId: auditContext.actorSessionId || normalizedOperatorSessionId,
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
          } catch (error) {
            const auditWriteError = new Error(
              'owner transfer takeover audit write failed'
            );
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }

        return {
          org_id: normalizedOrgId,
          old_owner_user_id: normalizedOldOwnerUserId,
          new_owner_user_id: normalizedNewOwnerUserId,
          membership_id: membershipId,
          role_ids: nextRoleIds,
          permission_codes: listTenantRolePermissionGrantsForRoleId(
            normalizedTakeoverRoleId
          ),
          audit_recorded: auditRecorded
        };
      } catch (error) {
        restoreMap(orgsById, snapshot.orgsById);
        restoreMap(tenantsByUserId, snapshot.tenantsByUserId);
        restoreMap(domainsByUserId, snapshot.domainsByUserId);
        restoreMap(platformRoleCatalogById, snapshot.platformRoleCatalogById);
        restoreMap(platformRoleCatalogCodeIndex, snapshot.platformRoleCatalogCodeIndex);
        restoreMap(
          tenantRolePermissionGrantsByRoleId,
          snapshot.tenantRolePermissionGrantsByRoleId
        );
        restoreMap(
          tenantMembershipRolesByMembershipId,
          snapshot.tenantMembershipRolesByMembershipId
        );
        restoreMap(
          tenantMembershipHistoryByPair,
          snapshot.tenantMembershipHistoryByPair
        );
        restoreMap(sessionsById, snapshot.sessionsById);
        restoreMap(refreshTokensByHash, snapshot.refreshTokensByHash);
        throw error;
      }
    },

    updateOrganizationStatus: async ({
      orgId,
      nextStatus,
      operatorUserId,
      auditContext = null
    }) => {
      const normalizedOrgId = String(orgId || '').trim();
      const normalizedOperatorUserId = String(operatorUserId || '').trim();
      const normalizedNextStatus = normalizeOrgStatus(nextStatus);
      if (
        !normalizedOrgId
        || !normalizedOperatorUserId
        || !VALID_ORG_STATUS.has(normalizedNextStatus)
      ) {
        throw new Error(
          'updateOrganizationStatus requires orgId, nextStatus, and operatorUserId'
        );
      }
      const existingOrg = orgsById.get(normalizedOrgId);
      if (!existingOrg) {
        return null;
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          orgsById: structuredClone(orgsById),
          membershipsByOrgId: structuredClone(membershipsByOrgId),
          tenantsByUserId: structuredClone(tenantsByUserId),
          tenantMembershipRolesByMembershipId: structuredClone(
            tenantMembershipRolesByMembershipId
          ),
          platformRoleCatalogById: structuredClone(platformRoleCatalogById),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          domainsByUserId: structuredClone(domainsByUserId),
          auditEvents: structuredClone(auditEvents)
        }
        : null;

      try {
        const previousStatus = normalizeOrgStatus(existingOrg.status);
        let affectedMembershipCount = 0;
        let affectedRoleCount = 0;
        let affectedRoleBindingCount = 0;
        let revokedSessionCount = 0;
        let revokedRefreshTokenCount = 0;
        if (previousStatus !== normalizedNextStatus) {
          existingOrg.status = normalizedNextStatus;
          existingOrg.updatedAt = Date.now();
          orgsById.set(normalizedOrgId, existingOrg);

          if (normalizedNextStatus === 'disabled') {
            const affectedMembershipUserIds = new Set();
            const affectedUserIds = new Set();
            const orgMemberships = membershipsByOrgId.get(normalizedOrgId) || [];
            for (const membership of orgMemberships) {
              const membershipUserId = String(membership?.userId || '').trim();
              if (
                !membershipUserId
                || !isActiveLikeStatus(normalizeOrgStatus(membership?.status))
              ) {
                continue;
              }
              membership.status = 'disabled';
              affectedMembershipUserIds.add(membershipUserId);
              affectedUserIds.add(membershipUserId);
            }

            const tenantMembershipIdsByOrg = new Set();
            for (const [userId, tenantMemberships] of tenantsByUserId.entries()) {
              const normalizedUserId = String(userId || '').trim();
              let hasMutation = false;
              for (const membership of Array.isArray(tenantMemberships) ? tenantMemberships : []) {
                const membershipTenantId = String(membership?.tenantId || '').trim();
                if (membershipTenantId !== normalizedOrgId) {
                  continue;
                }
                const membershipId = String(membership?.membershipId || '').trim();
                if (membershipId) {
                  tenantMembershipIdsByOrg.add(membershipId);
                }
                if (
                  !isActiveLikeStatus(
                    normalizeTenantMembershipStatusForRead(membership?.status)
                  )
                ) {
                  continue;
                }
                membership.status = 'disabled';
                membership.permission = buildEmptyTenantPermission(
                  toTenantMembershipScopeLabel(membership)
                );
                affectedMembershipUserIds.add(normalizedUserId);
                affectedUserIds.add(normalizedUserId);
                hasMutation = true;
              }
              if (hasMutation) {
                tenantsByUserId.set(normalizedUserId, tenantMemberships);
              }
            }

            for (const membershipId of tenantMembershipIdsByOrg) {
              const existingRoleIds = tenantMembershipRolesByMembershipId.get(membershipId) || [];
              affectedRoleBindingCount += existingRoleIds.length;
              tenantMembershipRolesByMembershipId.delete(membershipId);
            }

            for (const [roleId, roleCatalogEntry] of platformRoleCatalogById.entries()) {
              if (
                normalizePlatformRoleCatalogScope(roleCatalogEntry?.scope) !== 'tenant'
                || normalizePlatformRoleCatalogTenantId(roleCatalogEntry?.tenantId)
                  !== normalizedOrgId
              ) {
                continue;
              }
              if (
                !isActiveLikeStatus(
                  normalizePlatformRoleCatalogStatus(roleCatalogEntry?.status)
                )
              ) {
                continue;
              }
              roleCatalogEntry.status = 'disabled';
              roleCatalogEntry.updatedByUserId = normalizedOperatorUserId;
              roleCatalogEntry.updatedAt = new Date().toISOString();
              platformRoleCatalogById.set(roleId, roleCatalogEntry);
              affectedRoleCount += 1;
            }

            const ownerUserId = String(existingOrg.ownerUserId || '').trim();
            if (ownerUserId) {
              affectedUserIds.add(ownerUserId);
            }

            affectedMembershipCount = affectedMembershipUserIds.size;
            for (const userId of affectedUserIds) {
              const revoked = revokeTenantSessionsForUser({
                userId,
                reason: 'org-status-changed',
                activeTenantId: normalizedOrgId
              });
              revokedSessionCount += Number(revoked?.revokedSessionCount || 0);
              revokedRefreshTokenCount += Number(
                revoked?.revokedRefreshTokenCount || 0
              );

              const userDomains = domainsByUserId.get(userId) || new Set();
              const hasAnyActiveMembership = (tenantsByUserId.get(userId) || []).some(
                (membership) => isTenantMembershipActiveForAuth(membership)
              );
              if (!hasAnyActiveMembership) {
                userDomains.delete('tenant');
              }
              domainsByUserId.set(userId, userDomains);
            }
          }
        }
        let auditRecorded = false;
        if (shouldRecordAudit) {
          const normalizedAuditReason =
            auditContext.reason === null || auditContext.reason === undefined
              ? null
              : String(auditContext.reason).trim() || null;
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedOrgId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.org.status.updated',
              actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
              actorSessionId: auditContext.actorSessionId || null,
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
          } catch (error) {
            const auditWriteError = new Error('organization status audit write failed');
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(orgsById, snapshot.orgsById);
          restoreMapFromSnapshot(membershipsByOrgId, snapshot.membershipsByOrgId);
          restoreMapFromSnapshot(tenantsByUserId, snapshot.tenantsByUserId);
          restoreMapFromSnapshot(
            tenantMembershipRolesByMembershipId,
            snapshot.tenantMembershipRolesByMembershipId
          );
          restoreMapFromSnapshot(platformRoleCatalogById, snapshot.platformRoleCatalogById);
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreMapFromSnapshot(domainsByUserId, snapshot.domainsByUserId);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    updatePlatformUserStatus: async ({
      userId,
      nextStatus,
      operatorUserId,
      auditContext = null
    }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedOperatorUserId = String(operatorUserId || '').trim();
      const normalizedNextStatus = normalizeOrgStatus(nextStatus);
      if (
        !normalizedUserId
        || !normalizedOperatorUserId
        || !VALID_PLATFORM_USER_STATUS.has(normalizedNextStatus)
      ) {
        throw new Error(
          'updatePlatformUserStatus requires userId, nextStatus, and operatorUserId'
        );
      }
      const existingUser = usersById.get(normalizedUserId);
      if (
        !existingUser
        || !platformDomainKnownByUserId.has(normalizedUserId)
      ) {
        return null;
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          domainsByUserId: structuredClone(domainsByUserId),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
        const previousStatus = userDomains.has('platform') ? 'active' : 'disabled';
        if (previousStatus !== normalizedNextStatus) {
          if (normalizedNextStatus === 'active') {
            userDomains.add('platform');
          } else {
            userDomains.delete('platform');
            revokePlatformSessionsForUser({
              userId: normalizedUserId,
              reason: 'platform-user-status-changed'
            });
          }
          domainsByUserId.set(normalizedUserId, userDomains);
        }
        let auditRecorded = false;
        if (shouldRecordAudit) {
          const normalizedAuditReason =
            auditContext.reason === null || auditContext.reason === undefined
              ? null
              : String(auditContext.reason).trim() || null;
          try {
            persistAuditEvent({
              domain: 'platform',
              tenantId: null,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.platform.user.status.updated',
              actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
              actorSessionId: auditContext.actorSessionId || null,
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
          } catch (error) {
            const auditWriteError = new Error('platform user status audit write failed');
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }

        return {
          user_id: normalizedUserId,
          previous_status: previousStatus,
          current_status: normalizedNextStatus,
          audit_recorded: auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(domainsByUserId, snapshot.domainsByUserId);
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    softDeleteUser: async ({
      userId,
      operatorUserId,
      auditContext = null
    }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedOperatorUserId = String(operatorUserId || '').trim();
      if (!normalizedUserId || !normalizedOperatorUserId) {
        throw new Error('softDeleteUser requires userId and operatorUserId');
      }
      const existingUser = usersById.get(normalizedUserId);
      if (!existingUser) {
        return null;
      }
      const previousStatus = normalizeOrgStatus(existingUser.status);
      if (!VALID_PLATFORM_USER_STATUS.has(previousStatus)) {
        throw new Error('platform-user-soft-delete-status-read-invalid');
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          usersById: structuredClone(usersById),
          usersByPhone: structuredClone(usersByPhone),
          domainsByUserId: structuredClone(domainsByUserId),
          platformDomainKnownByUserId: structuredClone(platformDomainKnownByUserId),
          tenantsByUserId: structuredClone(tenantsByUserId),
          membershipsByOrgId: structuredClone(membershipsByOrgId),
          tenantMembershipRolesByMembershipId: structuredClone(
            tenantMembershipRolesByMembershipId
          ),
          platformRolesByUserId: structuredClone(platformRolesByUserId),
          platformPermissionsByUserId: structuredClone(platformPermissionsByUserId),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        let revokedSessionCount = 0;
        let revokedRefreshTokenCount = 0;
        if (previousStatus !== 'disabled') {
          const disabledUser = {
            ...existingUser,
            status: 'disabled'
          };
          usersById.set(normalizedUserId, disabledUser);
          usersByPhone.set(disabledUser.phone, disabledUser);
        }

        domainsByUserId.set(normalizedUserId, new Set());
        platformDomainKnownByUserId.delete(normalizedUserId);

        const memberships = tenantsByUserId.get(normalizedUserId) || [];
        const updatedMemberships = [];
        for (const membership of memberships) {
          const normalizedMembershipStatus = normalizeTenantMembershipStatusForRead(
            membership?.status
          );
          const normalizedMembership = {
            ...membership,
            status: isActiveLikeStatus(normalizedMembershipStatus)
              ? 'disabled'
              : normalizedMembershipStatus || 'disabled'
          };
          const membershipId = String(
            membership?.membershipId || membership?.membership_id || ''
          ).trim();
          if (membershipId) {
            tenantMembershipRolesByMembershipId.delete(membershipId);
          }
          updatedMemberships.push(normalizedMembership);
        }
        tenantsByUserId.set(normalizedUserId, updatedMemberships);

        for (const [orgId, orgMemberships] of membershipsByOrgId.entries()) {
          const nextOrgMemberships = [];
          for (const orgMembership of Array.isArray(orgMemberships)
            ? orgMemberships
            : []) {
            if (String(orgMembership?.userId || '').trim() !== normalizedUserId) {
              nextOrgMemberships.push(orgMembership);
              continue;
            }
            const normalizedOrgMembershipStatus = normalizeTenantMembershipStatusForRead(
              orgMembership?.status
            );
            nextOrgMemberships.push({
              ...orgMembership,
              status: isActiveLikeStatus(normalizedOrgMembershipStatus)
                ? 'disabled'
                : normalizedOrgMembershipStatus || 'disabled'
            });
          }
          membershipsByOrgId.set(orgId, nextOrgMemberships);
        }

        const platformRoles = platformRolesByUserId.get(normalizedUserId) || [];
        platformRolesByUserId.set(
          normalizedUserId,
          platformRoles.map((role) => ({
            ...role,
            status: isActiveLikeStatus(role?.status) ? 'disabled' : normalizeOrgStatus(role?.status)
          }))
        );
        platformPermissionsByUserId.set(
          normalizedUserId,
          buildEmptyPlatformPermission()
        );

        for (const session of sessionsById.values()) {
          if (
            session.userId === normalizedUserId
            && session.status === 'active'
          ) {
            session.status = 'revoked';
            session.revokedReason = 'user-soft-deleted';
            session.updatedAt = Date.now();
            revokedSessionCount += 1;
          }
        }
        for (const refreshRecord of refreshTokensByHash.values()) {
          if (
            refreshRecord.userId === normalizedUserId
            && refreshRecord.status === 'active'
          ) {
            refreshRecord.status = 'revoked';
            refreshRecord.updatedAt = Date.now();
            revokedRefreshTokenCount += 1;
          }
        }

        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              tenantId: null,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.platform.user.soft_deleted',
              actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
              actorSessionId: auditContext.actorSessionId || null,
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
          } catch (error) {
            const auditWriteError = new Error('platform user soft-delete audit write failed');
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }

        return {
          user_id: normalizedUserId,
          previous_status: previousStatus,
          current_status: 'disabled',
          revoked_session_count: revokedSessionCount,
          revoked_refresh_token_count: revokedRefreshTokenCount,
          audit_recorded: auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(usersById, snapshot.usersById);
          restoreMapFromSnapshot(usersByPhone, snapshot.usersByPhone);
          restoreMapFromSnapshot(domainsByUserId, snapshot.domainsByUserId);
          restoreSetFromSnapshot(
            platformDomainKnownByUserId,
            snapshot.platformDomainKnownByUserId
          );
          restoreMapFromSnapshot(tenantsByUserId, snapshot.tenantsByUserId);
          restoreMapFromSnapshot(membershipsByOrgId, snapshot.membershipsByOrgId);
          restoreMapFromSnapshot(
            tenantMembershipRolesByMembershipId,
            snapshot.tenantMembershipRolesByMembershipId
          );
          restoreMapFromSnapshot(platformRolesByUserId, snapshot.platformRolesByUserId);
          restoreMapFromSnapshot(
            platformPermissionsByUserId,
            snapshot.platformPermissionsByUserId
          );
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    deleteUserById: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { deleted: false };
      }
      const existingUser = usersById.get(normalizedUserId);
      if (!existingUser) {
        return { deleted: false };
      }
      if (hasOrgReferenceForUser(normalizedUserId)) {
        throw createForeignKeyConstraintError();
      }

      usersById.delete(normalizedUserId);
      usersByPhone.delete(String(existingUser.phone || ''));
      domainsByUserId.delete(normalizedUserId);
      platformDomainKnownByUserId.delete(normalizedUserId);
      for (const membership of tenantsByUserId.get(normalizedUserId) || []) {
        const membershipId = String(membership?.membershipId || '').trim();
        if (!membershipId) {
          continue;
        }
        tenantMembershipRolesByMembershipId.delete(membershipId);
      }
      tenantsByUserId.delete(normalizedUserId);
      platformRolesByUserId.delete(normalizedUserId);
      platformPermissionsByUserId.delete(normalizedUserId);

      for (const [sessionId, session] of sessionsById.entries()) {
        if (session.userId === normalizedUserId) {
          sessionsById.delete(sessionId);
        }
      }
      for (const [tokenHash, refreshToken] of refreshTokensByHash.entries()) {
        if (refreshToken.userId === normalizedUserId) {
          refreshTokensByHash.delete(tokenHash);
        }
      }

      return { deleted: true };
    },

    createTenantMembershipForUser: async ({ userId, tenantId, tenantName = null }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('createTenantMembershipForUser requires userId and tenantId');
      }
      if (!usersById.has(normalizedUserId)) {
        return { created: false };
      }
      const normalizedTenantName = tenantName === null || tenantName === undefined
        ? null
        : String(tenantName).trim() || null;

      const tenantMemberships = tenantsByUserId.get(normalizedUserId) || [];
      const existingMembership = tenantMemberships.find(
        (tenant) => String(tenant?.tenantId || '').trim() === normalizedTenantId
      );
      if (existingMembership) {
        const currentStatus = normalizeTenantMembershipStatusForRead(existingMembership.status);
        if (!VALID_TENANT_MEMBERSHIP_STATUS.has(currentStatus)) {
          throw new Error('createTenantMembershipForUser encountered unsupported existing status');
        }
        if (currentStatus !== 'left') {
          return { created: false };
        }
        appendTenantMembershipHistory({
          membership: {
            ...existingMembership,
            userId: normalizedUserId,
            tenantId: normalizedTenantId
          },
          reason: 'rejoin',
          operatorUserId: null
        });
        const previousMembershipId = String(existingMembership.membershipId || '').trim();
        existingMembership.membershipId = randomUUID();
        existingMembership.tenantName = normalizedTenantName;
        existingMembership.status = 'active';
        existingMembership.leftAt = null;
        existingMembership.joinedAt = new Date().toISOString();
        existingMembership.permission = {
          scopeLabel: `组织权限（${normalizedTenantName || normalizedTenantId}）`,
          canViewMemberAdmin: false,
          canOperateMemberAdmin: false,
          canViewBilling: false,
          canOperateBilling: false
        };
        if (previousMembershipId) {
          tenantMembershipRolesByMembershipId.delete(previousMembershipId);
        }
        tenantMembershipRolesByMembershipId.set(
          String(existingMembership.membershipId || '').trim(),
          []
        );
        tenantsByUserId.set(normalizedUserId, tenantMemberships);
        return { created: true };
      }

      const membershipId = randomUUID();
      tenantMemberships.push({
        membershipId,
        tenantId: normalizedTenantId,
        tenantName: normalizedTenantName,
        status: 'active',
        displayName: null,
        departmentName: null,
        joinedAt: new Date().toISOString(),
        leftAt: null,
        permission: {
          scopeLabel: `组织权限（${normalizedTenantName || normalizedTenantId}）`,
          canViewMemberAdmin: false,
          canOperateMemberAdmin: false,
          canViewBilling: false,
          canOperateBilling: false
        }
      });
      tenantMembershipRolesByMembershipId.set(membershipId, []);
      tenantsByUserId.set(normalizedUserId, tenantMemberships);
      return { created: true };
    },

    removeTenantMembershipForUser: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('removeTenantMembershipForUser requires userId and tenantId');
      }
      const tenantMemberships = tenantsByUserId.get(normalizedUserId);
      if (!Array.isArray(tenantMemberships) || tenantMemberships.length === 0) {
        return { removed: false };
      }
      const retainedMemberships = tenantMemberships.filter(
        (tenant) => String(tenant?.tenantId || '').trim() !== normalizedTenantId
      );
      const removed = retainedMemberships.length !== tenantMemberships.length;
      if (removed) {
        for (const membership of tenantMemberships) {
          if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
            continue;
          }
          const membershipId = String(membership?.membershipId || '').trim();
          if (!membershipId) {
            continue;
          }
          tenantMembershipRolesByMembershipId.delete(membershipId);
        }
        tenantsByUserId.set(normalizedUserId, retainedMemberships);
      }
      return { removed };
    },

    removeTenantDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { removed: false };
      }
      const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
      if (!userDomains.has('tenant')) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { removed: false };
      }
      const hasActiveTenantMembership = (tenantsByUserId.get(normalizedUserId) || []).some(
        (tenant) => isTenantMembershipActiveForAuth(tenant)
      );
      if (hasActiveTenantMembership) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { removed: false };
      }
      userDomains.delete('tenant');
      domainsByUserId.set(normalizedUserId, userDomains);
      return { removed: true };
    },

    createSession: async ({ sessionId, userId, sessionVersion, entryDomain = 'platform', activeTenantId = null }) => {
      sessionsById.set(sessionId, {
        sessionId,
        userId: String(userId),
        sessionVersion: Number(sessionVersion),
        entryDomain: String(entryDomain || 'platform').toLowerCase(),
        activeTenantId: activeTenantId ? String(activeTenantId) : null,
        status: 'active',
        revokedReason: null,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
    },

    findSessionById: async (sessionId) => clone(sessionsById.get(sessionId) || null),

    updateSessionContext: async ({ sessionId, entryDomain, activeTenantId }) => {
      const session = sessionsById.get(sessionId);
      if (!session) {
        return false;
      }

      if (entryDomain !== undefined) {
        session.entryDomain = String(entryDomain || 'platform').toLowerCase();
      }
      if (activeTenantId !== undefined) {
        session.activeTenantId = activeTenantId ? String(activeTenantId) : null;
      }
      session.updatedAt = Date.now();
      sessionsById.set(sessionId, session);
      return true;
    },

    findDomainAccessByUserId: async (userId) => {
      const userDomains = domainsByUserId.get(String(userId)) || new Set();
      return {
        platform: userDomains.has('platform'),
        tenant: userDomains.has('tenant')
      };
    },

    ensureDefaultDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId);
      const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
      if (userDomains.has('platform')) {
        domainsByUserId.set(normalizedUserId, userDomains);
        platformDomainKnownByUserId.add(normalizedUserId);
        return { inserted: false };
      }
      if (platformDomainKnownByUserId.has(normalizedUserId)) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { inserted: false };
      }
      userDomains.add('platform');
      domainsByUserId.set(normalizedUserId, userDomains);
      platformDomainKnownByUserId.add(normalizedUserId);
      return { inserted: true };
    },

    ensureTenantDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId);
      const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
      if (userDomains.has('tenant')) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { inserted: false };
      }

      const hasActiveTenantMembership = (tenantsByUserId.get(normalizedUserId) || []).some(
        (tenant) => isTenantMembershipActiveForAuth(tenant)
      );
      if (!hasActiveTenantMembership) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { inserted: false };
      }

      userDomains.add('tenant');
      domainsByUserId.set(normalizedUserId, userDomains);
      return { inserted: true };
    },

    listTenantOptionsByUserId: async (userId) =>
      (tenantsByUserId.get(String(userId)) || [])
        .filter((tenant) => isTenantMembershipActiveForAuth(tenant))
        .map((tenant) => ({ ...tenant })),

    findTenantMembershipByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        return null;
      }
      const membership = (tenantsByUserId.get(normalizedUserId) || []).find(
        (item) => String(item?.tenantId || '').trim() === normalizedTenantId
      );
      if (!membership) {
        return null;
      }
      const user = usersById.get(normalizedUserId);
      return {
        membership_id: String(membership.membershipId || '').trim(),
        user_id: normalizedUserId,
        tenant_id: normalizedTenantId,
        tenant_name: membership.tenantName ? String(membership.tenantName) : null,
        phone: user?.phone ? String(user.phone) : '',
        status: normalizeTenantMembershipStatusForRead(membership.status),
        display_name: resolveOptionalTenantMemberProfileField(membership.displayName),
        department_name: resolveOptionalTenantMemberProfileField(
          membership.departmentName
        ),
        joined_at: membership.joinedAt || null,
        left_at: membership.leftAt || null
      };
    },

    findTenantMembershipByMembershipIdAndTenantId: async ({
      membershipId,
      tenantId
    }) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedMembershipId || !normalizedTenantId) {
        return null;
      }
      const membershipState = findTenantMembershipStateByMembershipId(
        normalizedMembershipId
      );
      if (!membershipState) {
        return null;
      }
      const membership = membershipState.membership;
      if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
        return null;
      }
      const resolvedUserId = String(membershipState.userId || '').trim();
      const user = usersById.get(resolvedUserId);
      return {
        membership_id: normalizedMembershipId,
        user_id: resolvedUserId,
        tenant_id: normalizedTenantId,
        tenant_name: membership?.tenantName ? String(membership.tenantName) : null,
        phone: user?.phone ? String(user.phone) : '',
        status: normalizeTenantMembershipStatusForRead(membership?.status),
        display_name: resolveOptionalTenantMemberProfileField(
          membership?.displayName
        ),
        department_name: resolveOptionalTenantMemberProfileField(
          membership?.departmentName
        ),
        joined_at: membership?.joinedAt || null,
        left_at: membership?.leftAt || null
      };
    },

    listTenantMembersByTenantId: async ({ tenantId, page = 1, pageSize = 50 }) => {
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
      const members = [];
      for (const [userId, memberships] of tenantsByUserId.entries()) {
        const user = usersById.get(String(userId));
        if (!user) {
          continue;
        }
        for (const membership of Array.isArray(memberships) ? memberships : []) {
          if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
            continue;
          }
          members.push({
            membership_id: String(membership.membershipId || '').trim(),
            user_id: String(userId),
            tenant_id: normalizedTenantId,
            tenant_name: membership?.tenantName ? String(membership.tenantName) : null,
            phone: String(user.phone || ''),
            status: normalizeTenantMembershipStatusForRead(membership?.status),
            display_name: resolveOptionalTenantMemberProfileField(
              membership?.displayName
            ),
            department_name: resolveOptionalTenantMemberProfileField(
              membership?.departmentName
            ),
            joined_at: membership?.joinedAt || null,
            left_at: membership?.leftAt || null
          });
        }
      }
      members.sort((left, right) => {
        const leftJoinedAt = Date.parse(String(left.joined_at || ''));
        const rightJoinedAt = Date.parse(String(right.joined_at || ''));
        const normalizedLeftJoinedAt = Number.isFinite(leftJoinedAt) ? leftJoinedAt : 0;
        const normalizedRightJoinedAt = Number.isFinite(rightJoinedAt) ? rightJoinedAt : 0;
        if (normalizedLeftJoinedAt !== normalizedRightJoinedAt) {
          return normalizedRightJoinedAt - normalizedLeftJoinedAt;
        }
        return String(right.membership_id || '').localeCompare(
          String(left.membership_id || '')
        );
      });
      const offset = (resolvedPage - 1) * resolvedPageSize;
      return members.slice(offset, offset + resolvedPageSize);
    },

    updateTenantMembershipProfile: async ({
      membershipId,
      tenantId,
      displayName,
      departmentNameProvided = false,
      departmentName = null
    }) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedDisplayName = normalizeOptionalTenantMemberProfileField({
        value: displayName,
        maxLength: MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH
      });
      if (
        !normalizedMembershipId
        || !normalizedTenantId
        || normalizedDisplayName === null
      ) {
        throw new Error(
          'updateTenantMembershipProfile requires membershipId, tenantId and displayName'
        );
      }
      const shouldUpdateDepartmentName = departmentNameProvided === true;
      let normalizedDepartmentName = null;
      if (shouldUpdateDepartmentName) {
        if (departmentName === null) {
          normalizedDepartmentName = null;
        } else {
          normalizedDepartmentName = normalizeOptionalTenantMemberProfileField({
            value: departmentName,
            maxLength: MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH
          });
          if (normalizedDepartmentName === null) {
            throw new Error('updateTenantMembershipProfile departmentName is invalid');
          }
        }
      }

      const membershipState = findTenantMembershipStateByMembershipId(
        normalizedMembershipId
      );
      if (!membershipState) {
        return null;
      }
      const membership = membershipState.membership;
      if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
        return null;
      }
      const resolvedUserId = String(membershipState.userId || '').trim();
      const user = usersById.get(resolvedUserId);
      const rawUserPhone = user?.phone === null || user?.phone === undefined
        ? ''
        : String(user.phone);
      const normalizedUserPhone = rawUserPhone.trim();
      if (
        !normalizedUserPhone
        || rawUserPhone !== normalizedUserPhone
        || !MAINLAND_PHONE_PATTERN.test(normalizedUserPhone)
      ) {
        const dependencyError = new Error(
          'updateTenantMembershipProfile dependency unavailable: user-profile-missing'
        );
        dependencyError.code =
          'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
        throw dependencyError;
      }
      if (
        !shouldUpdateDepartmentName
        && !isStrictOptionalTenantMemberProfileField({
          value: membership?.departmentName,
          maxLength: MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH
        })
      ) {
        const dependencyError = new Error(
          'updateTenantMembershipProfile dependency unavailable: membership-profile-invalid'
        );
        dependencyError.code =
          'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
        throw dependencyError;
      }
      membership.displayName = normalizedDisplayName;
      if (shouldUpdateDepartmentName) {
        membership.departmentName = normalizedDepartmentName;
      }
      return {
        membership_id: normalizedMembershipId,
        user_id: resolvedUserId,
        tenant_id: normalizedTenantId,
        tenant_name: membership?.tenantName ? String(membership.tenantName) : null,
        phone: normalizedUserPhone,
        status: normalizeTenantMembershipStatusForRead(membership?.status),
        display_name: resolveOptionalTenantMemberProfileField(
          membership?.displayName
        ),
        department_name: resolveOptionalTenantMemberProfileField(
          membership?.departmentName
        ),
        joined_at: membership?.joinedAt || null,
        left_at: membership?.leftAt || null
      };
    },

    updateTenantMembershipStatus: async ({
      membershipId,
      tenantId,
      nextStatus,
      operatorUserId = null,
      reason = null,
      auditContext = null
    }) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedNextStatus = normalizeTenantMembershipStatusForRead(nextStatus);
      if (
        !normalizedMembershipId
        || !normalizedTenantId
        || !VALID_TENANT_MEMBERSHIP_STATUS.has(normalizedNextStatus)
      ) {
        throw new Error(
          'updateTenantMembershipStatus requires membershipId, tenantId and supported nextStatus'
        );
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          tenantsByUserId: structuredClone(tenantsByUserId),
          tenantMembershipRolesByMembershipId: structuredClone(
            tenantMembershipRolesByMembershipId
          ),
          tenantMembershipHistoryByPair: structuredClone(tenantMembershipHistoryByPair),
          domainsByUserId: structuredClone(domainsByUserId),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        let targetUserId = '';
        const tenantMembershipsByUser = [...tenantsByUserId.entries()];
        let targetMembership = null;
        let targetMemberships = null;

        for (const [userId, memberships] of tenantMembershipsByUser) {
          if (!Array.isArray(memberships)) {
            continue;
          }
          const match = memberships.find((membership) => {
            const membershipTenantId = String(membership?.tenantId || '').trim();
            const resolvedMembershipId = String(membership?.membershipId || '').trim();
            return (
              membershipTenantId === normalizedTenantId
              && resolvedMembershipId === normalizedMembershipId
            );
          });
          if (!match) {
            continue;
          }
          targetUserId = String(userId || '').trim();
          targetMembership = match;
          targetMemberships = memberships;
          break;
        }

        if (!targetMembership || !targetUserId || !targetMemberships) {
          return null;
        }

        const previousStatus = normalizeTenantMembershipStatusForRead(targetMembership.status);
        if (!VALID_TENANT_MEMBERSHIP_STATUS.has(previousStatus)) {
          throw new Error('updateTenantMembershipStatus encountered unsupported existing status');
        }
        if (previousStatus !== normalizedNextStatus) {
          let previousMembershipId = '';
          if (previousStatus === 'left' && normalizedNextStatus === 'active') {
            appendTenantMembershipHistory({
              membership: {
                ...targetMembership,
                userId: targetUserId,
                tenantId: normalizedTenantId
              },
              reason: reason || 'reactivate',
              operatorUserId
            });
            previousMembershipId = String(targetMembership.membershipId || '').trim();
            targetMembership.membershipId = randomUUID();
            targetMembership.joinedAt = new Date().toISOString();
            targetMembership.leftAt = null;
            if (targetMembership.permission) {
              targetMembership.permission = {
                ...targetMembership.permission,
                canViewMemberAdmin: false,
                canOperateMemberAdmin: false,
                canViewBilling: false,
                canOperateBilling: false
              };
            }
            if (previousMembershipId) {
              tenantMembershipRolesByMembershipId.delete(previousMembershipId);
            }
            tenantMembershipRolesByMembershipId.set(
              String(targetMembership.membershipId || '').trim(),
              []
            );
          } else if (normalizedNextStatus === 'left') {
            appendTenantMembershipHistory({
              membership: {
                ...targetMembership,
                userId: targetUserId,
                tenantId: normalizedTenantId
              },
              reason: reason || 'left',
              operatorUserId
            });
            targetMembership.leftAt = new Date().toISOString();
            if (targetMembership.permission) {
              targetMembership.permission = {
                ...targetMembership.permission,
                canViewMemberAdmin: false,
                canOperateMemberAdmin: false,
                canViewBilling: false,
                canOperateBilling: false
              };
            }
            const resolvedMembershipId = String(targetMembership.membershipId || '').trim();
            if (resolvedMembershipId) {
              tenantMembershipRolesByMembershipId.delete(resolvedMembershipId);
            }
          } else if (normalizedNextStatus === 'active') {
            targetMembership.leftAt = null;
          }

          targetMembership.status = normalizedNextStatus;
          tenantsByUserId.set(targetUserId, targetMemberships);

          if (normalizedNextStatus === 'active') {
            const userDomains = domainsByUserId.get(targetUserId) || new Set();
            userDomains.add('tenant');
            domainsByUserId.set(targetUserId, userDomains);
          } else {
            revokeTenantSessionsForUser({
              userId: targetUserId,
              reason: 'tenant-membership-status-changed',
              activeTenantId: normalizedTenantId
            });
            const userDomains = domainsByUserId.get(targetUserId) || new Set();
            const hasAnyActiveMembership = (tenantsByUserId.get(targetUserId) || []).some(
              (membership) => isTenantMembershipActiveForAuth(membership)
            );
            if (!hasAnyActiveMembership) {
              userDomains.delete('tenant');
            }
            domainsByUserId.set(targetUserId, userDomains);
          }

          if (normalizedNextStatus === 'active') {
            syncTenantMembershipPermissionSnapshot({
              membershipState: {
                userId: targetUserId,
                memberships: targetMemberships,
                membership: targetMembership
              },
              reason: 'tenant-membership-status-changed'
            });
          }
        }

        const resolvedMembershipId = String(targetMembership.membershipId || '').trim();
        const currentStatus = normalizeTenantMembershipStatusForRead(targetMembership.status);
        let auditRecorded = false;
        if (shouldRecordAudit) {
          const normalizedAuditReason =
            auditContext.reason === null || auditContext.reason === undefined
              ? null
              : String(auditContext.reason).trim() || null;
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedTenantId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.tenant.member.status.updated',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || null,
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
                tenant_id: normalizedTenantId,
                membership_id: resolvedMembershipId,
                target_user_id: targetUserId,
                previous_status: previousStatus,
                current_status: currentStatus,
                reason: normalizedAuditReason
              }
            });
          } catch (error) {
            const auditWriteError = new Error('tenant membership status audit write failed');
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }

        return {
          membership_id: resolvedMembershipId,
          user_id: targetUserId,
          tenant_id: normalizedTenantId,
          previous_status: previousStatus,
          current_status: currentStatus,
          audit_recorded: auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(tenantsByUserId, snapshot.tenantsByUserId);
          restoreMapFromSnapshot(
            tenantMembershipRolesByMembershipId,
            snapshot.tenantMembershipRolesByMembershipId
          );
          restoreMapFromSnapshot(
            tenantMembershipHistoryByPair,
            snapshot.tenantMembershipHistoryByPair
          );
          restoreMapFromSnapshot(domainsByUserId, snapshot.domainsByUserId);
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    listTenantMembershipRoleBindings: async ({
      membershipId,
      tenantId
    } = {}) =>
      listTenantMembershipRoleBindingsForMembershipId({
        membershipId,
        tenantId
      }),

    replaceTenantMembershipRoleBindingsAndSyncSnapshot: async ({
      tenantId,
      membershipId,
      roleIds = [],
      auditContext = null
    } = {}) => {
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedMembershipId = String(membershipId || '').trim();
      if (!normalizedTenantId || !normalizedMembershipId) {
        throw new Error('replaceTenantMembershipRoleBindingsAndSyncSnapshot requires tenantId and membershipId');
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          tenantMembershipRolesByMembershipId: structuredClone(
            tenantMembershipRolesByMembershipId
          ),
          tenantsByUserId: structuredClone(tenantsByUserId),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const membershipState = findTenantMembershipStateByMembershipId(
          normalizedMembershipId
        );
        if (!membershipState) {
          return null;
        }
        if (
          String(membershipState.membership?.tenantId || '').trim()
          !== normalizedTenantId
        ) {
          return null;
        }
        if (
          !isActiveLikeStatus(
            normalizeTenantMembershipStatusForRead(
              membershipState.membership?.status
            )
          )
        ) {
          const membershipStatusError = new Error(
            'tenant membership role bindings membership not active'
          );
          membershipStatusError.code =
            'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_MEMBERSHIP_NOT_ACTIVE';
          throw membershipStatusError;
        }
        const normalizedAffectedUserId =
          normalizeStrictTenantMembershipRoleBindingIdentity(
            membershipState?.userId,
            'tenant-membership-role-bindings-invalid-affected-user-id'
          );
        const normalizedRoleIds = [...new Set(
          (Array.isArray(roleIds) ? roleIds : [])
            .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
            .filter((roleId) => roleId.length > 0)
        )].sort((left, right) => left.localeCompare(right));
        for (const roleId of normalizedRoleIds) {
          const catalogEntry = findPlatformRoleCatalogRecordStateByRoleId(
            roleId
          )?.record;
          const normalizedScope = normalizePlatformRoleCatalogScope(
            catalogEntry?.scope
          );
          const normalizedCatalogTenantId = normalizePlatformRoleCatalogTenantId(
            catalogEntry?.tenantId
          );
          let normalizedCatalogStatus = 'disabled';
          try {
            normalizedCatalogStatus = normalizePlatformRoleCatalogStatus(
              catalogEntry?.status || 'disabled'
            );
          } catch (_error) {}
          if (
            !catalogEntry
            || normalizedScope !== 'tenant'
            || normalizedCatalogTenantId !== normalizedTenantId
            || !isActiveLikeStatus(normalizedCatalogStatus)
          ) {
            const roleBindingError = new Error(
              'tenant membership role bindings role invalid'
            );
            roleBindingError.code =
              'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_ROLE_INVALID';
            roleBindingError.roleId = roleId;
            throw roleBindingError;
          }
        }
        const previousRoleIds = listTenantMembershipRoleBindingsForMembershipId({
          membershipId: normalizedMembershipId,
          tenantId: normalizedTenantId
        });
        const resolvedRoleIds = replaceTenantMembershipRoleBindingsForMembershipId({
          membershipId: normalizedMembershipId,
          roleIds: normalizedRoleIds
        });
        const rollbackRoleBindings = () =>
          replaceTenantMembershipRoleBindingsForMembershipId({
            membershipId: normalizedMembershipId,
            roleIds: previousRoleIds
          });
        let syncResult;
        try {
          syncResult = syncTenantMembershipPermissionSnapshot({
            membershipState,
            reason: 'tenant-membership-role-bindings-changed'
          });
        } catch (error) {
          rollbackRoleBindings();
          throw error;
        }
        const syncReason = String(syncResult?.reason || 'unknown')
          .trim()
          .toLowerCase();
        if (syncReason !== 'ok') {
          rollbackRoleBindings();
          const syncError = new Error(
            `tenant membership role bindings sync failed: ${syncReason || 'unknown'}`
          );
          syncError.code = 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_SYNC_FAILED';
          syncError.syncReason = syncReason || 'unknown';
          throw syncError;
        }
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedTenantId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.tenant_membership_roles.updated',
              actorUserId: auditContext.actorUserId || null,
              actorSessionId: auditContext.actorSessionId || null,
              targetType: 'membership_role_bindings',
              targetId: normalizedMembershipId,
              result: 'success',
              beforeState: {
                role_ids: previousRoleIds
              },
              afterState: {
                role_ids: resolvedRoleIds
              },
              metadata: {
                affected_user_count: 1
              }
            });
          } catch (error) {
            const auditWriteError = new Error(
              'tenant membership role bindings audit write failed'
            );
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }
        return {
          membershipId: normalizedMembershipId,
          roleIds: resolvedRoleIds,
          affectedUserIds: [normalizedAffectedUserId],
          affectedUserCount: 1,
          auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            tenantMembershipRolesByMembershipId,
            snapshot.tenantMembershipRolesByMembershipId
          );
          restoreMapFromSnapshot(tenantsByUserId, snapshot.tenantsByUserId);
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    hasAnyTenantRelationshipByUserId: async (userId) =>
      (tenantsByUserId.get(String(userId)) || []).length > 0,

    findTenantPermissionByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedTenantId) {
        return null;
      }

      const tenant = (tenantsByUserId.get(String(userId)) || []).find(
        (item) =>
          String(item.tenantId) === normalizedTenantId &&
          isTenantMembershipActiveForAuth(item)
      );
      if (!tenant) {
        return null;
      }
      if (tenant.permission) {
        return {
          scopeLabel: tenant.permission.scopeLabel || `组织权限（${tenant.tenantName || tenant.tenantId}）`,
          canViewMemberAdmin: Boolean(tenant.permission.canViewMemberAdmin),
          canOperateMemberAdmin: Boolean(tenant.permission.canOperateMemberAdmin),
          canViewBilling: Boolean(tenant.permission.canViewBilling),
          canOperateBilling: Boolean(tenant.permission.canOperateBilling)
        };
      }
      return null;
    },

    findPlatformPermissionByUserId: async ({ userId }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return null;
      }
      const permission = platformPermissionsByUserId.get(normalizedUserId);
      return permission ? { ...permission } : null;
    },

    hasPlatformPermissionByUserId: async ({
      userId,
      permissionCode
    } = {}) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedPermissionCode = toPlatformPermissionCodeKey(permissionCode);
      if (
        !normalizedUserId
        || !normalizedPermissionCode
        || (
          normalizedPermissionCode !== PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE
          && normalizedPermissionCode !== PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE
        )
      ) {
        return {
          canViewSystemConfig: false,
          canOperateSystemConfig: false,
          granted: false
        };
      }

      const roles = platformRolesByUserId.get(normalizedUserId) || [];
      let canViewSystemConfig = false;
      let canOperateSystemConfig = false;

      for (const role of roles) {
        if (!role || !isActiveLikeStatus(role.status)) {
          continue;
        }
        const roleCatalogEntry = findPlatformRoleCatalogRecordStateByRoleId(
          role.roleId
        )?.record || null;
        if (roleCatalogEntry) {
          const roleCatalogScope = normalizePlatformRoleCatalogScope(
            roleCatalogEntry.scope
          );
          const roleCatalogTenantId = normalizePlatformRoleCatalogTenantId(
            roleCatalogEntry.tenantId
          );
          const roleCatalogStatus = normalizePlatformRoleCatalogStatus(
            roleCatalogEntry.status
          );
          if (
            roleCatalogScope !== 'platform'
            || roleCatalogTenantId !== ''
            || !isActiveLikeStatus(roleCatalogStatus)
          ) {
            continue;
          }
        }
        const permission = role.permission || {};
        if (Boolean(permission.canViewSystemConfig ?? permission.can_view_system_config)) {
          canViewSystemConfig = true;
        }
        if (Boolean(permission.canOperateSystemConfig ?? permission.can_operate_system_config)) {
          canOperateSystemConfig = true;
          canViewSystemConfig = true;
        }

        const grantCodes = listPlatformRolePermissionGrantsForRoleId(role.roleId);
        if (grantCodes.includes(PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE)) {
          canOperateSystemConfig = true;
          canViewSystemConfig = true;
        } else if (grantCodes.includes(PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE)) {
          canViewSystemConfig = true;
        }

        if (canViewSystemConfig && canOperateSystemConfig) {
          break;
        }
      }

      const granted = normalizedPermissionCode === PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE
        ? canOperateSystemConfig
        : canViewSystemConfig;
      return {
        canViewSystemConfig,
        canOperateSystemConfig,
        granted
      };
    },

    countPlatformRoleCatalogEntries: async () => platformRoleCatalogById.size,

    listPlatformRoleCatalogEntries: async ({
      scope = 'platform',
      tenantId = null
    } = {}) => {
      const normalizedScope = normalizePlatformRoleCatalogScope(scope);
      const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
        scope: normalizedScope,
        tenantId
      });
      return [...platformRoleCatalogById.values()]
        .filter((entry) => {
          if (normalizePlatformRoleCatalogScope(entry.scope) !== normalizedScope) {
            return false;
          }
          if (normalizedScope === 'tenant') {
            return String(entry.tenantId || '') === normalizedTenantId;
          }
          return String(entry.tenantId || '') === '';
        })
        .sort((left, right) => {
          const leftCreatedAt = new Date(left.createdAt).getTime();
          const rightCreatedAt = new Date(right.createdAt).getTime();
          if (leftCreatedAt !== rightCreatedAt) {
            return leftCreatedAt - rightCreatedAt;
          }
          return String(left.roleId || '').localeCompare(String(right.roleId || ''));
        })
        .map((entry) => clonePlatformRoleCatalogRecord(entry));
    },

    findPlatformRoleCatalogEntryByRoleId: async ({
      roleId,
      scope = undefined,
      tenantId = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        return null;
      }
      const hasScopeFilter = scope !== undefined && scope !== null;
      const normalizedScope = hasScopeFilter
        ? normalizePlatformRoleCatalogScope(scope)
        : null;
      const normalizedTenantId = hasScopeFilter
        ? normalizePlatformRoleCatalogTenantIdForScope({
          scope: normalizedScope,
          tenantId
        })
        : null;
      const existingState = findPlatformRoleCatalogRecordStateByRoleId(
        normalizedRoleId
      );
      const existing = existingState?.record || null;
      if (!existing) {
        return null;
      }
      if (
        hasScopeFilter
        && normalizePlatformRoleCatalogScope(existing.scope) !== normalizedScope
      ) {
        return null;
      }
      if (
        hasScopeFilter
        && normalizedScope === 'tenant'
        && String(existing.tenantId || '') !== normalizedTenantId
      ) {
        return null;
      }
      if (
        hasScopeFilter
        && normalizedScope !== 'tenant'
        && String(existing.tenantId || '') !== ''
      ) {
        return null;
      }
      return clonePlatformRoleCatalogRecord(existing);
    },

    findPlatformRoleCatalogEntriesByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIdKeys = new Set(
        (Array.isArray(roleIds) ? roleIds : [])
          .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
          .filter((roleId) => roleId.length > 0)
          .map((roleId) => roleId.toLowerCase())
      );
      if (normalizedRoleIdKeys.size === 0) {
        return [];
      }
      const matches = [];
      for (const [roleId, entry] of platformRoleCatalogById.entries()) {
        if (!normalizedRoleIdKeys.has(String(roleId).toLowerCase())) {
          continue;
        }
        matches.push(clonePlatformRoleCatalogRecord(entry));
      }
      return matches;
    },

    listPlatformIntegrationCatalogEntries: async ({
      direction = null,
      protocol = null,
      authMode = null,
      lifecycleStatus = null,
      keyword = null
    } = {}) =>
      [...platformIntegrationCatalogById.values()]
        .filter((entry) => {
          if (direction !== null && direction !== undefined) {
            const normalizedDirection = normalizePlatformIntegrationDirection(direction);
            if (!VALID_PLATFORM_INTEGRATION_DIRECTION.has(normalizedDirection)) {
              throw new Error(
                'listPlatformIntegrationCatalogEntries received unsupported direction'
              );
            }
            if (entry.direction !== normalizedDirection) {
              return false;
            }
          }
          if (lifecycleStatus !== null && lifecycleStatus !== undefined) {
            const normalizedLifecycleStatus = normalizePlatformIntegrationLifecycleStatus(
              lifecycleStatus
            );
            if (
              !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedLifecycleStatus)
            ) {
              throw new Error(
                'listPlatformIntegrationCatalogEntries received unsupported lifecycleStatus'
              );
            }
            if (entry.lifecycleStatus !== normalizedLifecycleStatus) {
              return false;
            }
          }
          if (protocol !== null && protocol !== undefined) {
            const normalizedProtocol = String(protocol || '').trim();
            if (!normalizedProtocol) {
              throw new Error(
                'listPlatformIntegrationCatalogEntries received unsupported protocol'
              );
            }
            if (entry.protocol !== normalizedProtocol) {
              return false;
            }
          }
          if (authMode !== null && authMode !== undefined) {
            const normalizedAuthMode = String(authMode || '').trim();
            if (!normalizedAuthMode) {
              throw new Error(
                'listPlatformIntegrationCatalogEntries received unsupported authMode'
              );
            }
            if (entry.authMode !== normalizedAuthMode) {
              return false;
            }
          }
          if (keyword !== null && keyword !== undefined) {
            const normalizedKeyword = String(keyword || '').trim().toLowerCase();
            if (normalizedKeyword) {
              const searchable = [
                entry.codeNormalized,
                String(entry.name || '').toLowerCase()
              ];
              if (!searchable.some((value) => String(value || '').includes(normalizedKeyword))) {
                return false;
              }
            }
          }
          return true;
        })
        .sort((left, right) => {
          const leftCreatedAt = new Date(left.createdAt).getTime();
          const rightCreatedAt = new Date(right.createdAt).getTime();
          if (leftCreatedAt !== rightCreatedAt) {
            return leftCreatedAt - rightCreatedAt;
          }
          return String(left.integrationId || '').localeCompare(
            String(right.integrationId || '')
          );
        })
        .map((entry) => clonePlatformIntegrationCatalogRecord(entry)),

    findPlatformIntegrationCatalogEntryByIntegrationId: async ({
      integrationId
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
        return null;
      }
      const existingState = findPlatformIntegrationCatalogRecordStateByIntegrationId(
        normalizedIntegrationId
      );
      return clonePlatformIntegrationCatalogRecord(existingState?.record || null);
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
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationCatalogById: structuredClone(platformIntegrationCatalogById),
          platformIntegrationCatalogCodeIndex: structuredClone(
            platformIntegrationCatalogCodeIndex
          ),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
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
        assertPlatformIntegrationWriteAllowedByFreezeGate();
        if (
          findPlatformIntegrationCatalogRecordStateByIntegrationId(
            normalizedIntegrationId
          )
        ) {
          throw createDuplicatePlatformIntegrationCatalogEntryError({
            target: 'integration_id'
          });
        }
        const createdRecord = upsertPlatformIntegrationCatalogRecord({
          integrationId: normalizedIntegrationId,
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
          lifecycleStatus,
          lifecycleReason,
          createdByUserId: normalizePlatformIntegrationOptionalText(operatorUserId),
          updatedByUserId: normalizePlatformIntegrationOptionalText(operatorUserId)
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.created',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration',
              targetId: createdRecord.integrationId,
              result: 'success',
              beforeState: null,
              afterState: {
                integration_id: createdRecord.integrationId,
                code: createdRecord.code,
                direction: createdRecord.direction,
                protocol: createdRecord.protocol,
                auth_mode: createdRecord.authMode,
                lifecycle_status: createdRecord.lifecycleStatus
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
          ...createdRecord,
          auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationCatalogById,
            snapshot.platformIntegrationCatalogById
          );
          restoreMapFromSnapshot(
            platformIntegrationCatalogCodeIndex,
            snapshot.platformIntegrationCatalogCodeIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

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
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationCatalogById: structuredClone(platformIntegrationCatalogById),
          platformIntegrationCatalogCodeIndex: structuredClone(
            platformIntegrationCatalogCodeIndex
          ),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
        if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
          throw new Error('updatePlatformIntegrationCatalogEntry requires integrationId');
        }
        const existingState = findPlatformIntegrationCatalogRecordStateByIntegrationId(
          normalizedIntegrationId
        );
        const existingRecord = existingState?.record || null;
        if (!existingRecord) {
          return null;
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
        assertPlatformIntegrationWriteAllowedByFreezeGate();
        const updatedRecord = upsertPlatformIntegrationCatalogRecord({
          ...existingRecord,
          integrationId: existingRecord.integrationId,
          code: code === undefined ? existingRecord.code : code,
          name: name === undefined ? existingRecord.name : name,
          direction: direction === undefined ? existingRecord.direction : direction,
          protocol: protocol === undefined ? existingRecord.protocol : protocol,
          authMode: authMode === undefined ? existingRecord.authMode : authMode,
          endpoint: endpoint === undefined ? existingRecord.endpoint : endpoint,
          baseUrl: baseUrl === undefined ? existingRecord.baseUrl : baseUrl,
          timeoutMs: timeoutMs === undefined ? existingRecord.timeoutMs : timeoutMs,
          retryPolicy: retryPolicy === undefined
            ? existingRecord.retryPolicy
            : retryPolicy,
          idempotencyPolicy: idempotencyPolicy === undefined
            ? existingRecord.idempotencyPolicy
            : idempotencyPolicy,
          versionStrategy: versionStrategy === undefined
            ? existingRecord.versionStrategy
            : versionStrategy,
          runbookUrl: runbookUrl === undefined
            ? existingRecord.runbookUrl
            : runbookUrl,
          lifecycleReason: lifecycleReason === undefined
            ? existingRecord.lifecycleReason
            : lifecycleReason,
          updatedByUserId:
            normalizePlatformIntegrationOptionalText(operatorUserId)
            || existingRecord.updatedByUserId,
          updatedAt: new Date().toISOString()
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.updated',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration',
              targetId: updatedRecord.integrationId,
              result: 'success',
              beforeState: {
                code: existingRecord.code,
                direction: existingRecord.direction,
                protocol: existingRecord.protocol,
                auth_mode: existingRecord.authMode
              },
              afterState: {
                code: updatedRecord.code,
                direction: updatedRecord.direction,
                protocol: updatedRecord.protocol,
                auth_mode: updatedRecord.authMode
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
          ...updatedRecord,
          auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationCatalogById,
            snapshot.platformIntegrationCatalogById
          );
          restoreMapFromSnapshot(
            platformIntegrationCatalogCodeIndex,
            snapshot.platformIntegrationCatalogCodeIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    transitionPlatformIntegrationLifecycle: async ({
      integrationId,
      nextStatus,
      reason = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationCatalogById: structuredClone(platformIntegrationCatalogById),
          platformIntegrationCatalogCodeIndex: structuredClone(
            platformIntegrationCatalogCodeIndex
          ),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
        const normalizedNextStatus = normalizePlatformIntegrationLifecycleStatus(nextStatus);
        if (
          !isValidPlatformIntegrationId(normalizedIntegrationId)
          || !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedNextStatus)
        ) {
          throw new Error('transitionPlatformIntegrationLifecycle received invalid input');
        }
        assertPlatformIntegrationWriteAllowedByFreezeGate();
        const existingState = findPlatformIntegrationCatalogRecordStateByIntegrationId(
          normalizedIntegrationId
        );
        const existingRecord = existingState?.record || null;
        if (!existingRecord) {
          return null;
        }
        if (
          !isPlatformIntegrationLifecycleTransitionAllowed({
            previousStatus: existingRecord.lifecycleStatus,
            nextStatus: normalizedNextStatus
          })
        ) {
          throw createPlatformIntegrationLifecycleConflictError({
            integrationId: normalizedIntegrationId,
            previousStatus: existingRecord.lifecycleStatus,
            requestedStatus: normalizedNextStatus
          });
        }
        const updatedRecord = upsertPlatformIntegrationCatalogRecord({
          ...existingRecord,
          lifecycleStatus: normalizedNextStatus,
          lifecycleReason: reason,
          updatedByUserId:
            normalizePlatformIntegrationOptionalText(operatorUserId)
            || existingRecord.updatedByUserId,
          updatedAt: new Date().toISOString()
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.lifecycle_changed',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration',
              targetId: updatedRecord.integrationId,
              result: 'success',
              beforeState: {
                lifecycle_status: existingRecord.lifecycleStatus
              },
              afterState: {
                lifecycle_status: updatedRecord.lifecycleStatus
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
          ...updatedRecord,
          previousStatus: existingRecord.lifecycleStatus,
          currentStatus: updatedRecord.lifecycleStatus,
          effectiveInvocationEnabled: updatedRecord.lifecycleStatus === 'active',
          auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationCatalogById,
            snapshot.platformIntegrationCatalogById
          );
          restoreMapFromSnapshot(
            platformIntegrationCatalogCodeIndex,
            snapshot.platformIntegrationCatalogCodeIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    findActivePlatformIntegrationFreeze: async () => {
      const activeState = findActivePlatformIntegrationFreezeRecordState();
      if (!activeState?.record) {
        return null;
      }
      const normalizedRecord = toPlatformIntegrationFreezeRecord(activeState.record);
      if (!normalizedRecord) {
        throw new Error('findActivePlatformIntegrationFreeze result malformed');
      }
      return clonePlatformIntegrationFreezeRecord(normalizedRecord);
    },

    findLatestPlatformIntegrationFreeze: async () => {
      const latestState = findLatestPlatformIntegrationFreezeRecordState();
      if (!latestState?.record) {
        return null;
      }
      const normalizedRecord = toPlatformIntegrationFreezeRecord(latestState.record);
      if (!normalizedRecord) {
        throw new Error('findLatestPlatformIntegrationFreeze result malformed');
      }
      return clonePlatformIntegrationFreezeRecord(normalizedRecord);
    },

    activatePlatformIntegrationFreeze: async ({
      freezeId = randomUUID(),
      freezeReason,
      operatorUserId = null,
      operatorSessionId = null,
      requestId,
      traceparent = null,
      auditContext = null
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationFreezeById: structuredClone(platformIntegrationFreezeById),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
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
        const normalizedTraceparent = normalizePlatformIntegrationOptionalText(traceparent);
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
        const activeState = findActivePlatformIntegrationFreezeRecordState();
        if (activeState?.record) {
          const activeFreeze = toPlatformIntegrationFreezeRecord(activeState.record);
          if (!activeFreeze) {
            throw new Error('activatePlatformIntegrationFreeze active row malformed');
          }
          throw createPlatformIntegrationFreezeActiveConflictError({
            freezeId: activeFreeze.freezeId,
            frozenAt: activeFreeze.frozenAt,
            freezeReason: activeFreeze.freezeReason
          });
        }
        if (platformIntegrationFreezeById.has(normalizedFreezeId)) {
          throw createPlatformIntegrationFreezeActiveConflictError();
        }
        const nowIso = new Date().toISOString();
        const createdRecord = upsertPlatformIntegrationFreezeRecord({
          freezeId: normalizedFreezeId,
          status: 'active',
          freezeReason: normalizedFreezeReason,
          rollbackReason: null,
          frozenAt: nowIso,
          releasedAt: null,
          frozenByUserId: normalizePlatformIntegrationOptionalText(operatorUserId),
          releasedByUserId: null,
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          createdAt: nowIso,
          updatedAt: nowIso
        });
        if (!createdRecord) {
          throw new Error('activatePlatformIntegrationFreeze result unavailable');
        }
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            invokeFaultInjector('beforePlatformIntegrationFreezeActivateAuditWrite', {
              freezeId: normalizedFreezeId,
              requestId: normalizedRequestId
            });
            persistAuditEvent({
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationFreezeById,
            snapshot.platformIntegrationFreezeById
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    releasePlatformIntegrationFreeze: async ({
      rollbackReason = null,
      operatorUserId = null,
      operatorSessionId = null,
      requestId = 'request_id_unset',
      traceparent = null,
      auditContext = null
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationFreezeById: structuredClone(platformIntegrationFreezeById),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedRollbackReason =
          normalizePlatformIntegrationOptionalText(rollbackReason);
        const normalizedRequestId = String(requestId || '').trim();
        const normalizedTraceparent = normalizePlatformIntegrationOptionalText(traceparent);
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
        const activeState = findActivePlatformIntegrationFreezeRecordState();
        if (!activeState?.record) {
          throw createPlatformIntegrationFreezeReleaseConflictError();
        }
        const activeRecord = toPlatformIntegrationFreezeRecord(activeState.record);
        if (!activeRecord) {
          throw new Error('releasePlatformIntegrationFreeze active row malformed');
        }
        const nowIso = new Date().toISOString();
        const releasedRecord = upsertPlatformIntegrationFreezeRecord({
          ...activeRecord,
          status: 'released',
          rollbackReason: normalizedRollbackReason,
          releasedAt: nowIso,
          releasedByUserId: normalizePlatformIntegrationOptionalText(operatorUserId),
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          updatedAt: nowIso
        });
        if (!releasedRecord) {
          throw new Error('releasePlatformIntegrationFreeze result unavailable');
        }
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            invokeFaultInjector('beforePlatformIntegrationFreezeReleaseAuditWrite', {
              freezeId: activeRecord.freezeId,
              requestId: normalizedRequestId
            });
            persistAuditEvent({
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationFreezeById,
            snapshot.platformIntegrationFreezeById
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

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
      return [...platformIntegrationContractVersionsByKey.values()]
        .filter((entry) => {
          if (entry.integrationId !== normalizedIntegrationId) {
            return false;
          }
          if (
            normalizedContractType !== null
            && entry.contractType !== normalizedContractType
          ) {
            return false;
          }
          if (normalizedStatus !== null && entry.status !== normalizedStatus) {
            return false;
          }
          return true;
        })
        .sort((left, right) => {
          const leftCreatedAt = new Date(left.createdAt).getTime();
          const rightCreatedAt = new Date(right.createdAt).getTime();
          if (leftCreatedAt !== rightCreatedAt) {
            return leftCreatedAt - rightCreatedAt;
          }
          return Number(left.contractId || 0) - Number(right.contractId || 0);
        })
        .map((entry) => clonePlatformIntegrationContractVersionRecord(entry));
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
      const existingState = findPlatformIntegrationContractVersionRecordState({
        integrationId: normalizedIntegrationId,
        contractType: normalizedContractType,
        contractVersion: normalizedContractVersion
      });
      return clonePlatformIntegrationContractVersionRecord(existingState?.record || null);
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
      const activeEntries = [...platformIntegrationContractVersionsByKey.values()]
        .filter((entry) =>
          entry.integrationId === normalizedIntegrationId
          && entry.contractType === normalizedContractType
          && entry.status === 'active'
        )
        .sort((left, right) => {
          const leftUpdatedAt = new Date(left.updatedAt).getTime();
          const rightUpdatedAt = new Date(right.updatedAt).getTime();
          if (leftUpdatedAt !== rightUpdatedAt) {
            return rightUpdatedAt - leftUpdatedAt;
          }
          return Number(right.contractId || 0) - Number(left.contractId || 0);
        });
      return clonePlatformIntegrationContractVersionRecord(activeEntries[0] || null);
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
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationContractVersionsByKey:
            structuredClone(platformIntegrationContractVersionsByKey),
          nextPlatformIntegrationContractVersionId,
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
        const normalizedContractType = normalizePlatformIntegrationContractType(contractType);
        const normalizedContractVersion =
          normalizePlatformIntegrationContractVersion(contractVersion);
        if (
          !isValidPlatformIntegrationId(normalizedIntegrationId)
          || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
          || !normalizedContractVersion
          || normalizedContractVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
          || typeof isBackwardCompatible !== 'boolean'
        ) {
          throw new Error('createPlatformIntegrationContractVersion received invalid input');
        }
        if (
          !findPlatformIntegrationCatalogRecordStateByIntegrationId(normalizedIntegrationId)
        ) {
          throw new Error('createPlatformIntegrationContractVersion integration not found');
        }
        assertPlatformIntegrationWriteAllowedByFreezeGate();
        if (
          findPlatformIntegrationContractVersionRecordState({
            integrationId: normalizedIntegrationId,
            contractType: normalizedContractType,
            contractVersion: normalizedContractVersion
          })
        ) {
          throw createDuplicatePlatformIntegrationContractVersionError();
        }
        const createdRecord = upsertPlatformIntegrationContractVersionRecord({
          integrationId: normalizedIntegrationId,
          contractType: normalizedContractType,
          contractVersion: normalizedContractVersion,
          schemaRef,
          schemaChecksum,
          status,
          isBackwardCompatible,
          compatibilityNotes,
          createdByUserId: normalizePlatformIntegrationOptionalText(operatorUserId),
          updatedByUserId: normalizePlatformIntegrationOptionalText(operatorUserId)
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.contract.created',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration_contract',
              targetId:
                `${normalizedIntegrationId}:${normalizedContractType}:${normalizedContractVersion}`,
              result: 'success',
              beforeState: null,
              afterState: {
                integration_id: normalizedIntegrationId,
                contract_type: normalizedContractType,
                contract_version: normalizedContractVersion,
                status: createdRecord.status,
                is_backward_compatible: createdRecord.isBackwardCompatible
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationContractVersionsByKey,
            snapshot.platformIntegrationContractVersionsByKey
          );
          nextPlatformIntegrationContractVersionId = Number(
            snapshot.nextPlatformIntegrationContractVersionId || 1
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

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
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationContractChecksById:
            structuredClone(platformIntegrationContractChecksById),
          nextPlatformIntegrationContractCheckId,
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
        const normalizedContractType = normalizePlatformIntegrationContractType(contractType);
        const normalizedBaselineVersion =
          normalizePlatformIntegrationContractVersion(baselineVersion);
        const normalizedCandidateVersion =
          normalizePlatformIntegrationContractVersion(candidateVersion);
        const normalizedEvaluationResult =
          normalizePlatformIntegrationContractEvaluationResult(evaluationResult);
        const normalizedBreakingChangeCount = Number(breakingChangeCount);
        const normalizedRequestId = String(requestId || '').trim();
        if (
          !isValidPlatformIntegrationId(normalizedIntegrationId)
          || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
          || !normalizedBaselineVersion
          || normalizedBaselineVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
          || !normalizedCandidateVersion
          || normalizedCandidateVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
          || !VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT.has(
            normalizedEvaluationResult
          )
          || !Number.isInteger(normalizedBreakingChangeCount)
          || normalizedBreakingChangeCount < 0
          || !normalizedRequestId
          || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
        ) {
          throw new Error(
            'createPlatformIntegrationContractCompatibilityCheck received invalid input'
          );
        }
        if (
          !findPlatformIntegrationContractVersionRecordState({
            integrationId: normalizedIntegrationId,
            contractType: normalizedContractType,
            contractVersion: normalizedBaselineVersion
          })
          || !findPlatformIntegrationContractVersionRecordState({
            integrationId: normalizedIntegrationId,
            contractType: normalizedContractType,
            contractVersion: normalizedCandidateVersion
          })
        ) {
          throw new Error(
            'createPlatformIntegrationContractCompatibilityCheck contract version not found'
          );
        }
        const checkRecord = toPlatformIntegrationContractCompatibilityCheckRecord({
          checkId: nextPlatformIntegrationContractCheckId,
          integrationId: normalizedIntegrationId,
          contractType: normalizedContractType,
          baselineVersion: normalizedBaselineVersion,
          candidateVersion: normalizedCandidateVersion,
          evaluationResult: normalizedEvaluationResult,
          breakingChangeCount: normalizedBreakingChangeCount,
          diffSummary,
          requestId: normalizedRequestId,
          checkedByUserId: normalizePlatformIntegrationOptionalText(checkedByUserId),
          checkedAt: new Date().toISOString()
        });
        platformIntegrationContractChecksById.set(
          Number(nextPlatformIntegrationContractCheckId),
          checkRecord
        );
        nextPlatformIntegrationContractCheckId += 1;
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || normalizedRequestId).trim()
                || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.contract.compatibility_evaluated',
              actorUserId: auditContext.actorUserId || checkedByUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration_contract',
              targetId:
                `${normalizedIntegrationId}:${normalizedContractType}:${normalizedCandidateVersion}`,
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
          ...clonePlatformIntegrationContractCompatibilityCheckRecord(checkRecord),
          auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationContractChecksById,
            snapshot.platformIntegrationContractChecksById
          );
          nextPlatformIntegrationContractCheckId = Number(
            snapshot.nextPlatformIntegrationContractCheckId || 1
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

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
      const matches = [...platformIntegrationContractChecksById.values()]
        .filter((entry) =>
          entry.integrationId === normalizedIntegrationId
          && entry.contractType === normalizedContractType
          && entry.baselineVersion === normalizedBaselineVersion
          && entry.candidateVersion === normalizedCandidateVersion
        )
        .sort((left, right) => {
          const leftCheckedAt = new Date(left.checkedAt).getTime();
          const rightCheckedAt = new Date(right.checkedAt).getTime();
          if (leftCheckedAt !== rightCheckedAt) {
            return rightCheckedAt - leftCheckedAt;
          }
          return Number(right.checkId || 0) - Number(left.checkId || 0);
        });
      return clonePlatformIntegrationContractCompatibilityCheckRecord(matches[0] || null);
    },

    activatePlatformIntegrationContractVersion: async ({
      integrationId,
      contractType,
      contractVersion,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationContractVersionsByKey:
            structuredClone(platformIntegrationContractVersionsByKey),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
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
          throw new Error('activatePlatformIntegrationContractVersion received invalid input');
        }
        assertPlatformIntegrationWriteAllowedByFreezeGate();
        const targetState = findPlatformIntegrationContractVersionRecordState({
          integrationId: normalizedIntegrationId,
          contractType: normalizedContractType,
          contractVersion: normalizedContractVersion
        });
        if (!targetState?.record) {
          return null;
        }
        const targetRecord = targetState.record;
        if (targetRecord.status === 'retired') {
          throw createPlatformIntegrationContractActivationBlockedError({
            integrationId: normalizedIntegrationId,
            contractType: normalizedContractType,
            contractVersion: normalizedContractVersion,
            reason: 'retired-version'
          });
        }
        const scopeKey = toPlatformIntegrationContractScopeKey({
          integrationId: normalizedIntegrationId,
          contractType: normalizedContractType
        });
        const previousStatus = targetRecord.status;
        for (const [contractKey, entry] of platformIntegrationContractVersionsByKey.entries()) {
          if (!contractKey.startsWith(`${scopeKey}::`)) {
            continue;
          }
          if (
            entry.status === 'active'
            && entry.contractVersion !== normalizedContractVersion
          ) {
            const updatedEntry = toPlatformIntegrationContractVersionRecord({
              ...entry,
              status: 'deprecated',
              updatedByUserId:
                normalizePlatformIntegrationOptionalText(operatorUserId)
                || entry.updatedByUserId,
              updatedAt: new Date().toISOString()
            });
            platformIntegrationContractVersionsByKey.set(contractKey, updatedEntry);
          }
        }
        const activeRecord = toPlatformIntegrationContractVersionRecord({
          ...targetRecord,
          status: 'active',
          updatedByUserId:
            normalizePlatformIntegrationOptionalText(operatorUserId)
            || targetRecord.updatedByUserId,
          updatedAt: new Date().toISOString()
        });
        platformIntegrationContractVersionsByKey.set(targetState.key, activeRecord);
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.contract.activated',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration_contract',
              targetId:
                `${normalizedIntegrationId}:${normalizedContractType}:${normalizedContractVersion}`,
              result: 'success',
              beforeState: {
                status: previousStatus
              },
              afterState: {
                status: activeRecord.status
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
          ...clonePlatformIntegrationContractVersionRecord(activeRecord),
          previousStatus,
          currentStatus: activeRecord.status,
          switched: previousStatus !== activeRecord.status,
          auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationContractVersionsByKey,
            snapshot.platformIntegrationContractVersionsByKey
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

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
      return [...platformIntegrationRecoveryQueueByRecoveryId.values()]
        .filter((entry) => {
          if (entry.integrationId !== normalizedIntegrationId) {
            return false;
          }
          if (normalizedStatus !== null && entry.status !== normalizedStatus) {
            return false;
          }
          return true;
        })
        .sort((left, right) => {
          const leftCreatedAt = new Date(left.createdAt).getTime();
          const rightCreatedAt = new Date(right.createdAt).getTime();
          if (leftCreatedAt !== rightCreatedAt) {
            return rightCreatedAt - leftCreatedAt;
          }
          return String(right.recoveryId || '').localeCompare(
            String(left.recoveryId || '')
          );
        })
        .slice(0, normalizedLimit)
        .map((entry) => clonePlatformIntegrationRecoveryQueueRecord(entry));
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
      const existingState = findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId(
        normalizedRecoveryId
      );
      if (!existingState?.record) {
        return null;
      }
      if (existingState.record.integrationId !== normalizedIntegrationId) {
        return null;
      }
      return clonePlatformIntegrationRecoveryQueueRecord(existingState.record);
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
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationRecoveryQueueByRecoveryId: structuredClone(
            platformIntegrationRecoveryQueueByRecoveryId
          ),
          platformIntegrationRecoveryDedupIndex: structuredClone(
            platformIntegrationRecoveryDedupIndex
          ),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(recoveryId);
        const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
        const normalizedContractType =
          normalizePlatformIntegrationContractType(contractType);
        const normalizedContractVersion =
          normalizePlatformIntegrationContractVersion(contractVersion);
        const normalizedRequestId = String(requestId || '').trim();
        const normalizedTraceparent = normalizePlatformIntegrationOptionalText(traceparent);
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
          || !findPlatformIntegrationCatalogRecordStateByIntegrationId(
            normalizedIntegrationId
          )
          || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
          || !normalizedContractVersion
          || normalizedContractVersion.length
            > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
          || !normalizedRequestId
          || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
          || (
            normalizedTraceparent !== null
            && normalizedTraceparent.length
              > MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH
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
        const existingState = findPlatformIntegrationRecoveryQueueRecordStateByDedupKey({
          integrationId: normalizedIntegrationId,
          contractType: normalizedContractType,
          contractVersion: normalizedContractVersion,
          requestId: normalizedRequestId,
          idempotencyKey: normalizedIdempotencyKey
        });
        const existingRecord = existingState?.record || null;
        if (
          existingRecord
          && (
            existingRecord.status === 'succeeded'
            || existingRecord.status === 'replayed'
          )
        ) {
          return {
            ...clonePlatformIntegrationRecoveryQueueRecord(existingRecord),
            inserted: false,
            auditRecorded: false
          };
        }
        const persistedRecord = upsertPlatformIntegrationRecoveryQueueRecord({
          entry: {
            recoveryId: normalizedRecoveryId,
            integrationId: normalizedIntegrationId,
            contractType: normalizedContractType,
            contractVersion: normalizedContractVersion,
            requestId: normalizedRequestId,
            traceparent: normalizedTraceparent,
            idempotencyKey: normalizedIdempotencyKey,
            attemptCount: normalizedAttemptCount,
            maxAttempts: normalizedMaxAttempts,
            nextRetryAt: normalizedNextRetryAt,
            lastAttemptAt: normalizedLastAttemptAt,
            status: normalizedStatus,
            failureCode: normalizedFailureCode,
            failureDetail: normalizedFailureDetail,
            lastHttpStatus: normalizedLastHttpStatus,
            retryable: Boolean(retryable),
            payloadSnapshot: normalizedPayloadSnapshot,
            responseSnapshot: normalizedResponseSnapshot,
            createdByUserId:
              existingRecord?.createdByUserId || normalizedOperatorUserId,
            updatedByUserId: normalizedOperatorUserId
          },
          preserveTerminalStatus: true
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.recovery.retry_scheduled',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration_recovery',
              targetId: persistedRecord.recoveryId,
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationRecoveryQueueByRecoveryId,
            snapshot.platformIntegrationRecoveryQueueByRecoveryId
          );
          restoreMapFromSnapshot(
            platformIntegrationRecoveryDedupIndex,
            snapshot.platformIntegrationRecoveryDedupIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    claimNextDuePlatformIntegrationRecoveryQueueEntry: async ({
      integrationId = null,
      now = new Date().toISOString(),
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) => {
      const normalizedNow = new Date(now);
      if (Number.isNaN(normalizedNow.getTime())) {
        throw new Error(
          'claimNextDuePlatformIntegrationRecoveryQueueEntry received invalid now'
        );
      }
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
      const normalizedNowIso = normalizedNow.toISOString();
      const normalizedNowEpochMs = normalizedNow.getTime();
      const staleRetryingThresholdMs =
        normalizedNow.getTime() - DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS;
      const claimLeaseExpiresAtIso = new Date(
        normalizedNow.getTime() + DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS
      ).toISOString();
      const normalizedOperatorUserId = normalizePlatformIntegrationOptionalText(operatorUserId);
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
      const isStaleRetryingEntry = (entry) => {
        if (entry.status !== 'retrying') {
          return false;
        }
        if (entry.nextRetryAt !== null) {
          return new Date(entry.nextRetryAt).getTime() <= normalizedNowEpochMs;
        }
        if (entry.lastAttemptAt === null) {
          return true;
        }
        return new Date(entry.lastAttemptAt).getTime() <= staleRetryingThresholdMs;
      };
      const staleRetryingRecords = [];
      for (const entry of [...platformIntegrationRecoveryQueueByRecoveryId.values()]) {
        if (
          normalizedIntegrationId !== null
          && entry.integrationId !== normalizedIntegrationId
        ) {
          continue;
        }
        if (!isStaleRetryingEntry(entry) || entry.attemptCount < entry.maxAttempts) {
          continue;
        }
        staleRetryingRecords.push(entry);
      }
      if (staleRetryingRecords.length > 0) {
        const staleSweepSnapshot = {
          platformIntegrationRecoveryQueueByRecoveryId: structuredClone(
            platformIntegrationRecoveryQueueByRecoveryId
          ),
          platformIntegrationRecoveryDedupIndex: structuredClone(
            platformIntegrationRecoveryDedupIndex
          ),
          auditEvents: structuredClone(auditEvents)
        };
        try {
          for (const staleEntry of staleRetryingRecords) {
            upsertPlatformIntegrationRecoveryQueueRecord({
              entry: {
                ...staleEntry,
                status: 'dlq',
                nextRetryAt: null,
                updatedByUserId: normalizedOperatorUserId,
                updatedAt: normalizedNowIso
              }
            });
            persistAuditEvent({
              domain: 'platform',
              requestId: auditRequestId,
              traceparent: auditTraceparent,
              eventType: 'platform.integration.recovery.retry_exhausted',
              actorUserId: auditActorUserId,
              actorSessionId: auditActorSessionId,
              targetType: 'integration_recovery',
              targetId: staleEntry.recoveryId,
              result: 'failed',
              beforeState: {
                status: staleEntry.status,
                attempt_count: staleEntry.attemptCount,
                max_attempts: staleEntry.maxAttempts,
                next_retry_at: staleEntry.nextRetryAt,
                last_attempt_at: staleEntry.lastAttemptAt
              },
              afterState: {
                status: 'dlq',
                attempt_count: staleEntry.attemptCount,
                max_attempts: staleEntry.maxAttempts,
                next_retry_at: null,
                last_attempt_at: staleEntry.lastAttemptAt
              },
              metadata: {
                exhausted_by: 'stale-retrying-claim-sweep'
              }
            });
          }
        } catch (error) {
          restoreMapFromSnapshot(
            platformIntegrationRecoveryQueueByRecoveryId,
            staleSweepSnapshot.platformIntegrationRecoveryQueueByRecoveryId
          );
          restoreMapFromSnapshot(
            platformIntegrationRecoveryDedupIndex,
            staleSweepSnapshot.platformIntegrationRecoveryDedupIndex
          );
          restoreAuditEventsFromSnapshot(staleSweepSnapshot.auditEvents);
          const auditWriteError = new Error(
            'platform integration recovery claim sweep audit write failed'
          );
          auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
          auditWriteError.cause = error;
          throw auditWriteError;
        }
      }
      const candidateRecord = [...platformIntegrationRecoveryQueueByRecoveryId.values()]
        .filter((entry) => {
          if (entry.status === 'pending') {
            if (
              entry.nextRetryAt !== null
              && new Date(entry.nextRetryAt).getTime() > normalizedNowEpochMs
            ) {
              return false;
            }
          } else if (entry.status === 'replayed') {
            if (
              entry.nextRetryAt !== null
              && new Date(entry.nextRetryAt).getTime() > normalizedNowEpochMs
            ) {
              return false;
            }
          } else if (entry.status === 'retrying') {
            if (!isStaleRetryingEntry(entry)) {
              return false;
            }
          } else {
            return false;
          }
          if (entry.attemptCount >= entry.maxAttempts) {
            return false;
          }
          if (
            normalizedIntegrationId !== null
            && entry.integrationId !== normalizedIntegrationId
          ) {
            return false;
          }
          return true;
        })
        .sort((left, right) => {
          const leftDueAt = new Date(left.nextRetryAt || left.createdAt).getTime();
          const rightDueAt = new Date(right.nextRetryAt || right.createdAt).getTime();
          if (leftDueAt !== rightDueAt) {
            return leftDueAt - rightDueAt;
          }
          const leftCreatedAt = new Date(left.createdAt).getTime();
          const rightCreatedAt = new Date(right.createdAt).getTime();
          if (leftCreatedAt !== rightCreatedAt) {
            return leftCreatedAt - rightCreatedAt;
          }
          return String(left.recoveryId || '').localeCompare(
            String(right.recoveryId || '')
          );
        })[0] || null;
      if (!candidateRecord) {
        return null;
      }
      const updatedRecord = upsertPlatformIntegrationRecoveryQueueRecord({
        entry: {
          ...candidateRecord,
          attemptCount: Math.min(
            candidateRecord.maxAttempts,
            candidateRecord.attemptCount + 1
          ),
          status: 'retrying',
          nextRetryAt: claimLeaseExpiresAtIso,
          lastAttemptAt: normalizedNowIso,
          updatedByUserId: normalizedOperatorUserId,
          updatedAt: normalizedNowIso
        }
      });
      return {
        ...updatedRecord,
        previousStatus: candidateRecord.status,
        currentStatus: updatedRecord.status
      };
    },

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
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationRecoveryQueueByRecoveryId: structuredClone(
            platformIntegrationRecoveryQueueByRecoveryId
          ),
          platformIntegrationRecoveryDedupIndex: structuredClone(
            platformIntegrationRecoveryDedupIndex
          ),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
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
        const existingState = findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId(
          normalizedRecoveryId
        );
        const existingRecord = existingState?.record || null;
        if (!existingRecord || existingRecord.integrationId !== normalizedIntegrationId) {
          return null;
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
        const updatedRecord = upsertPlatformIntegrationRecoveryQueueRecord({
          entry: {
            ...existingRecord,
            status: nextStatus,
            nextRetryAt: persistedNextRetryAt,
            failureCode: persistedFailureCode,
            failureDetail: persistedFailureDetail,
            lastHttpStatus: persistedLastHttpStatus,
            retryable: persistedRetryable,
            responseSnapshot: normalizedResponseSnapshot,
            updatedByUserId: normalizedOperatorUserId,
            updatedAt: completionNowIso
          }
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          const emitAuditEvent = (eventType) =>
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType,
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
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
              emitAuditEvent('platform.integration.recovery.reprocess_succeeded');
            } else {
              emitAuditEvent('platform.integration.recovery.reprocess_failed');
              if (updatedRecord.status === 'dlq') {
                emitAuditEvent('platform.integration.recovery.retry_exhausted');
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationRecoveryQueueByRecoveryId,
            snapshot.platformIntegrationRecoveryQueueByRecoveryId
          );
          restoreMapFromSnapshot(
            platformIntegrationRecoveryDedupIndex,
            snapshot.platformIntegrationRecoveryDedupIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    replayPlatformIntegrationRecoveryQueueEntry: async ({
      integrationId,
      recoveryId,
      reason = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationRecoveryQueueByRecoveryId: structuredClone(
            platformIntegrationRecoveryQueueByRecoveryId
          ),
          platformIntegrationRecoveryDedupIndex: structuredClone(
            platformIntegrationRecoveryDedupIndex
          ),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
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
        const existingState = findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId(
          normalizedRecoveryId
        );
        const existingRecord = existingState?.record || null;
        if (!existingRecord || existingRecord.integrationId !== normalizedIntegrationId) {
          return null;
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
        const updatedRecord = upsertPlatformIntegrationRecoveryQueueRecord({
          entry: {
            ...existingRecord,
            status: 'replayed',
            attemptCount: 0,
            nextRetryAt: new Date().toISOString(),
            lastAttemptAt: null,
            failureCode: null,
            failureDetail: null,
            lastHttpStatus: null,
            retryable: true,
            updatedByUserId: normalizedOperatorUserId,
            updatedAt: new Date().toISOString()
          }
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.recovery.replayed',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationRecoveryQueueByRecoveryId,
            snapshot.platformIntegrationRecoveryQueueByRecoveryId
          );
          restoreMapFromSnapshot(
            platformIntegrationRecoveryDedupIndex,
            snapshot.platformIntegrationRecoveryDedupIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    listPlatformRolePermissionGrants: async ({ roleId }) =>
      listPlatformRolePermissionGrantsForRoleId(roleId),

    listPlatformRolePermissionGrantsByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIds = [...new Set(
        (Array.isArray(roleIds) ? roleIds : [])
          .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
          .filter((roleId) => roleId.length > 0)
      )];
      return normalizedRoleIds.map((roleId) => ({
        roleId,
        permissionCodes: listPlatformRolePermissionGrantsForRoleId(roleId)
      }));
    },

    replacePlatformRolePermissionGrants: async ({
      roleId,
      permissionCodes = []
    }) =>
      replacePlatformRolePermissionGrantsForRoleId({
        roleId,
        permissionCodes
      }),

    listTenantRolePermissionGrants: async ({ roleId }) =>
      listTenantRolePermissionGrantsForRoleId(roleId),

    listTenantRolePermissionGrantsByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIds = [...new Set(
        (Array.isArray(roleIds) ? roleIds : [])
          .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
          .filter((roleId) => roleId.length > 0)
      )];
      return normalizedRoleIds.map((roleId) => ({
        roleId,
        permissionCodes: listTenantRolePermissionGrantsForRoleId(roleId)
      }));
    },

    replaceTenantRolePermissionGrantsAndSyncSnapshots: async ({
      tenantId,
      roleId,
      permissionCodes = [],
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null,
      maxAffectedMemberships = 100
    }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedTenantId || !normalizedRoleId) {
        throw new Error('replaceTenantRolePermissionGrantsAndSyncSnapshots requires tenantId and roleId');
      }
      const roleCatalogEntry = findPlatformRoleCatalogRecordStateByRoleId(
        normalizedRoleId
      )?.record;
      if (!roleCatalogEntry) {
        return null;
      }
      if (
        normalizePlatformRoleCatalogScope(roleCatalogEntry.scope) !== 'tenant'
        || normalizePlatformRoleCatalogTenantId(roleCatalogEntry.tenantId) !== normalizedTenantId
      ) {
        return null;
      }
      const normalizedMaxAffectedMemberships = Math.max(
        1,
        Math.floor(Number(maxAffectedMemberships || 100))
      );
      const affectedMembershipStatesByMembershipId = new Map();
      for (const [userId, memberships] of tenantsByUserId.entries()) {
        for (const membership of Array.isArray(memberships) ? memberships : []) {
          if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
            continue;
          }
          if (!isTenantMembershipActiveForAuth(membership)) {
            continue;
          }
          const membershipId = normalizeStrictTenantRolePermissionGrantIdentity(
            membership?.membershipId || membership?.membership_id,
            'tenant-role-permission-grants-invalid-membership-id'
          );
          const boundRoleIds = listTenantMembershipRoleBindingsForMembershipId({
            membershipId,
            tenantId: normalizedTenantId
          });
          if (!boundRoleIds.includes(normalizedRoleId)) {
            continue;
          }
          affectedMembershipStatesByMembershipId.set(membershipId, {
            userId: normalizeStrictTenantRolePermissionGrantIdentity(
              userId,
              'tenant-role-permission-grants-invalid-affected-user-id'
            ),
            memberships,
            membership
          });
        }
      }
      if (
        affectedMembershipStatesByMembershipId.size
        > normalizedMaxAffectedMemberships
      ) {
        const limitError = new Error('tenant role permission affected memberships exceed limit');
        limitError.code = 'ERR_TENANT_ROLE_PERMISSION_AFFECTED_MEMBERSHIPS_OVER_LIMIT';
        limitError.maxAffectedMemberships = normalizedMaxAffectedMemberships;
        limitError.affectedMemberships = affectedMembershipStatesByMembershipId.size;
        throw limitError;
      }
      const previousPermissionCodes = listTenantRolePermissionGrantsForRoleId(
        normalizedRoleId
      );
      const previousMembershipPermissionsByMembershipId = new Map();
      for (const [membershipId, membershipState] of affectedMembershipStatesByMembershipId.entries()) {
        const previousPermission =
          membershipState?.membership?.permission
          && typeof membershipState.membership.permission === 'object'
            ? { ...membershipState.membership.permission }
            : null;
        previousMembershipPermissionsByMembershipId.set(
          membershipId,
          previousPermission
        );
      }
      const savedPermissionCodes = replaceTenantRolePermissionGrantsForRoleId({
        roleId: normalizedRoleId,
        permissionCodes
      });
      const affectedUserIds = new Set();
      const tenantSessionRevocations = new Map();
      try {
        for (const [
          membershipId,
          membershipState
        ] of affectedMembershipStatesByMembershipId.entries()) {
          const resolvedUserId = normalizeStrictTenantRolePermissionGrantIdentity(
            membershipState?.userId,
            'tenant-role-permission-grants-invalid-affected-user-id'
          );
          affectedUserIds.add(resolvedUserId);
          invokeFaultInjector('beforeTenantRolePermissionSnapshotSync', {
            tenantId: normalizedTenantId,
            roleId: normalizedRoleId,
            membershipId,
            userId: resolvedUserId
          });
          const syncResult = syncTenantMembershipPermissionSnapshot({
            membershipState,
            reason: 'tenant-role-permission-grants-changed',
            revokeSessions: false
          });
          if (!syncResult?.synced || syncResult.reason !== 'ok') {
            const syncError = new Error(
              `tenant role permission sync failed: ${String(syncResult?.reason || 'unknown')}`
            );
            syncError.code = 'ERR_TENANT_ROLE_PERMISSION_SYNC_FAILED';
            syncError.syncReason = String(syncResult?.reason || 'unknown');
            throw syncError;
          }
          const syncUserId = String(syncResult?.userId || '').trim();
          const syncTenantId = String(syncResult?.tenantId || '').trim();
          if (syncResult.changed && syncUserId && syncTenantId) {
            tenantSessionRevocations.set(`${syncUserId}::${syncTenantId}`, {
              userId: syncUserId,
              tenantId: syncTenantId
            });
          }
        }
      } catch (error) {
        replaceTenantRolePermissionGrantsForRoleId({
          roleId: normalizedRoleId,
          permissionCodes: previousPermissionCodes
        });
        for (const [
          membershipId,
          membershipState
        ] of affectedMembershipStatesByMembershipId.entries()) {
          if (!membershipState?.membership || typeof membershipState.membership !== 'object') {
            continue;
          }
          const previousPermission =
            previousMembershipPermissionsByMembershipId.get(membershipId);
          membershipState.membership.permission = previousPermission
            ? { ...previousPermission }
            : null;
        }
        throw error;
      }
      for (const { userId, tenantId: activeTenantId } of tenantSessionRevocations.values()) {
        revokeTenantSessionsForUser({
          userId,
          reason: 'tenant-role-permission-grants-changed',
          activeTenantId
        });
      }
      let auditRecorded = false;
      if (auditContext && typeof auditContext === 'object') {
        try {
          persistAuditEvent({
            domain: 'tenant',
            tenantId: normalizedTenantId,
            requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
            traceparent: auditContext.traceparent,
            eventType: 'auth.tenant_role_permission_grants.updated',
            actorUserId: auditContext.actorUserId || operatorUserId || null,
            actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
            targetType: 'role_permission_grants',
            targetId: normalizedRoleId,
            result: 'success',
            beforeState: {
              permission_codes: [...previousPermissionCodes]
            },
            afterState: {
              permission_codes: [...savedPermissionCodes]
            },
            metadata: {
              affected_user_count: affectedUserIds.size
            }
          });
        } catch (error) {
          const auditWriteError = new Error(
            'tenant role permission grants audit write failed'
          );
          auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
          auditWriteError.cause = error;
          throw auditWriteError;
        }
        auditRecorded = true;
      }

      return {
        roleId: normalizedRoleId,
        permissionCodes: savedPermissionCodes,
        affectedUserIds: [...affectedUserIds],
        affectedUserCount: affectedUserIds.size,
        auditRecorded
      };
    },

    listUserIdsByPlatformRoleId: async ({ roleId }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        return [];
      }
      const normalizedRoleIdKey = normalizedRoleId.toLowerCase();
      const matchedUserIds = [];
      for (const [userId, roles] of platformRolesByUserId.entries()) {
        const hasMatchedRole = (Array.isArray(roles) ? roles : []).some((role) =>
          String(role?.roleId || '').trim().toLowerCase() === normalizedRoleIdKey
        );
        if (hasMatchedRole) {
          matchedUserIds.push(String(userId));
        }
      }
      return matchedUserIds;
    },

    listPlatformRoleFactsByUserId: async ({ userId }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return [];
      }
      const roles = platformRolesByUserId.get(normalizedUserId) || [];
      return (Array.isArray(roles) ? roles : []).map((role) => ({
        roleId: String(role?.roleId || '').trim(),
        role_id: String(role?.roleId || '').trim(),
        status: String(role?.status || 'active').trim().toLowerCase() || 'active',
        permission: role?.permission ? { ...role.permission } : null
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
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformRoleCatalogById: structuredClone(platformRoleCatalogById),
          platformRoleCatalogCodeIndex: structuredClone(platformRoleCatalogCodeIndex),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
        const normalizedCode = normalizePlatformRoleCatalogCode(code);
        const normalizedName = String(name || '').trim();
        const normalizedScope = normalizePlatformRoleCatalogScope(scope);
        const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
          scope: normalizedScope,
          tenantId
        });
        if (!normalizedRoleId || !normalizedCode || !normalizedName) {
          throw new Error('createPlatformRoleCatalogEntry requires roleId, code, and name');
        }
        if (findPlatformRoleCatalogRecordStateByRoleId(normalizedRoleId)) {
          throw createDuplicatePlatformRoleCatalogEntryError({
            target: 'role_id'
          });
        }
        const createdRole = upsertPlatformRoleCatalogRecord({
          roleId: normalizedRoleId,
          code: normalizedCode,
          name: normalizedName,
          status: normalizePlatformRoleCatalogStatus(status),
          scope: normalizedScope,
          tenantId: normalizedTenantId,
          isSystem: Boolean(isSystem),
          createdByUserId: operatorUserId ? String(operatorUserId) : null,
          updatedByUserId: operatorUserId ? String(operatorUserId) : null,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          updatedBySessionId: operatorSessionId ? String(operatorSessionId) : null
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
              tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.role.catalog.created',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'role',
              targetId: normalizedRoleId,
              result: 'success',
              beforeState: null,
              afterState: {
                role_id: normalizedRoleId,
                code: createdRole.code,
                name: createdRole.name,
                status: createdRole.status,
                scope: createdRole.scope,
                tenant_id: createdRole.tenantId,
                is_system: createdRole.isSystem
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(platformRoleCatalogById, snapshot.platformRoleCatalogById);
          restoreMapFromSnapshot(
            platformRoleCatalogCodeIndex,
            snapshot.platformRoleCatalogCodeIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
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
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformRoleCatalogById: structuredClone(platformRoleCatalogById),
          platformRoleCatalogCodeIndex: structuredClone(platformRoleCatalogCodeIndex),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
        if (!normalizedRoleId) {
          throw new Error('updatePlatformRoleCatalogEntry requires roleId');
        }
        const normalizedScope = normalizePlatformRoleCatalogScope(scope);
        const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
          scope: normalizedScope,
          tenantId
        });
        const existingState = findPlatformRoleCatalogRecordStateByRoleId(
          normalizedRoleId
        );
        const existing = existingState?.record || null;
        if (!existing) {
          return null;
        }
        if (normalizePlatformRoleCatalogScope(existing.scope) !== normalizedScope) {
          return null;
        }
        if (
          normalizedScope === 'tenant'
          && String(existing.tenantId || '') !== normalizedTenantId
        ) {
          return null;
        }
        if (normalizedScope !== 'tenant' && String(existing.tenantId || '') !== '') {
          return null;
        }
        const nextCode = code === undefined
          ? existing.code
          : normalizePlatformRoleCatalogCode(code);
        const nextName = name === undefined
          ? existing.name
          : String(name || '').trim();
        const nextStatus = status === undefined
          ? existing.status
          : normalizePlatformRoleCatalogStatus(status);
        if (!nextCode || !nextName) {
          throw new Error('updatePlatformRoleCatalogEntry requires non-empty code and name');
        }
        const updatedRole = upsertPlatformRoleCatalogRecord({
          ...existing,
          roleId: existing.roleId,
          code: nextCode,
          name: nextName,
          status: nextStatus,
          scope: existing.scope,
          tenantId: existing.tenantId,
          isSystem: Boolean(existing.isSystem),
          updatedByUserId: operatorUserId ? String(operatorUserId) : existing.updatedByUserId,
          updatedBySessionId: operatorSessionId ? String(operatorSessionId) : null,
          updatedAt: new Date().toISOString()
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
              tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.role.catalog.updated',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'role',
              targetId: normalizedRoleId,
              result: 'success',
              beforeState: {
                code: existing.code,
                name: existing.name,
                status: existing.status
              },
              afterState: {
                code: updatedRole.code,
                name: updatedRole.name,
                status: updatedRole.status
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(platformRoleCatalogById, snapshot.platformRoleCatalogById);
          restoreMapFromSnapshot(
            platformRoleCatalogCodeIndex,
            snapshot.platformRoleCatalogCodeIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    deletePlatformRoleCatalogEntry: async ({
      roleId,
      scope = 'platform',
      tenantId = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    }) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformRoleCatalogById: structuredClone(platformRoleCatalogById),
          platformRoleCatalogCodeIndex: structuredClone(platformRoleCatalogCodeIndex),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
        if (!normalizedRoleId) {
          throw new Error('deletePlatformRoleCatalogEntry requires roleId');
        }
        const normalizedScope = normalizePlatformRoleCatalogScope(scope);
        const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
          scope: normalizedScope,
          tenantId
        });
        const existingState = findPlatformRoleCatalogRecordStateByRoleId(
          normalizedRoleId
        );
        const existing = existingState?.record || null;
        if (!existing) {
          return null;
        }
        if (normalizePlatformRoleCatalogScope(existing.scope) !== normalizedScope) {
          return null;
        }
        if (
          normalizedScope === 'tenant'
          && String(existing.tenantId || '') !== normalizedTenantId
        ) {
          return null;
        }
        if (normalizedScope !== 'tenant' && String(existing.tenantId || '') !== '') {
          return null;
        }
        const deletedRole = upsertPlatformRoleCatalogRecord({
          ...existing,
          status: 'disabled',
          updatedByUserId: operatorUserId ? String(operatorUserId) : existing.updatedByUserId,
          updatedBySessionId: operatorSessionId ? String(operatorSessionId) : null,
          updatedAt: new Date().toISOString()
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
              tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.role.catalog.deleted',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'role',
              targetId: normalizedRoleId,
              result: 'success',
              beforeState: {
                code: existing.code,
                name: existing.name,
                status: existing.status
              },
              afterState: {
                status: deletedRole.status
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(platformRoleCatalogById, snapshot.platformRoleCatalogById);
          restoreMapFromSnapshot(
            platformRoleCatalogCodeIndex,
            snapshot.platformRoleCatalogCodeIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    syncPlatformPermissionSnapshotByUserId: async ({
      userId,
      forceWhenNoRoleFacts = false
    }) =>
      syncPlatformPermissionFromRoleFacts({
        userId,
        forceWhenNoRoleFacts
      }),

    replacePlatformRolesAndSyncSnapshot: async ({ userId, roles = [] }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId || !usersById.has(normalizedUserId)) {
        return {
          synced: false,
          reason: 'invalid-user-id',
          permission: null
        };
      }

      const previousRoles = platformRolesByUserId.get(normalizedUserId) || [];
      const previousPermission = platformPermissionsByUserId.get(normalizedUserId)
        || mergePlatformPermissionFromRoles(previousRoles)
        || buildEmptyPlatformPermission();

      const normalizedRoles = dedupePlatformRolesByRoleId(
        (Array.isArray(roles) ? roles : [])
          .map((role) => normalizePlatformRole(role))
          .filter(Boolean)
      );
      platformRolesByUserId.set(normalizedUserId, normalizedRoles);
      const syncResult = syncPlatformPermissionFromRoleFacts({
        userId: normalizedUserId,
        forceWhenNoRoleFacts: true
      });

      const nextPermission = syncResult?.permission || buildEmptyPlatformPermission();
      if (!isSamePlatformPermission(previousPermission, nextPermission)) {
        bumpSessionVersionAndConvergeSessions({
          userId: normalizedUserId,
          reason: 'platform-role-facts-changed',
          revokeRefreshTokens: true,
          revokeAuthSessions: true
        });
      }

      return syncResult;
    },

    revokeSession: async ({ sessionId, reason }) => {
      const session = sessionsById.get(sessionId);
      if (session && session.status === 'active') {
        session.status = 'revoked';
        session.revokedReason = reason;
        session.updatedAt = Date.now();
      }

      for (const refreshRecord of refreshTokensByHash.values()) {
        if (refreshRecord.sessionId === sessionId && refreshRecord.status === 'active') {
          refreshRecord.status = 'revoked';
          refreshRecord.updatedAt = Date.now();
        }
      }
    },

    revokeAllUserSessions: async ({ userId, reason }) => {
      for (const session of sessionsById.values()) {
        if (session.userId === String(userId) && session.status === 'active') {
          session.status = 'revoked';
          session.revokedReason = reason;
          session.updatedAt = Date.now();
        }
      }

      for (const refreshRecord of refreshTokensByHash.values()) {
        if (refreshRecord.userId === String(userId) && refreshRecord.status === 'active') {
          refreshRecord.status = 'revoked';
          refreshRecord.updatedAt = Date.now();
        }
      }
    },

    createRefreshToken: async ({ tokenHash, sessionId, userId, expiresAt }) => {
      refreshTokensByHash.set(tokenHash, {
        tokenHash,
        sessionId,
        userId: String(userId),
        status: 'active',
        rotatedFrom: null,
        rotatedTo: null,
        expiresAt,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
    },

    findRefreshTokenByHash: async (tokenHash) => clone(refreshTokensByHash.get(tokenHash) || null),

    markRefreshTokenStatus: async ({ tokenHash, status }) => {
      const token = refreshTokensByHash.get(tokenHash);
      if (!token) {
        return;
      }

      token.status = status;
      token.updatedAt = Date.now();
    },

    linkRefreshRotation: async ({ previousTokenHash, nextTokenHash }) => {
      const previous = refreshTokensByHash.get(previousTokenHash);
      if (previous) {
        previous.rotatedTo = nextTokenHash;
        previous.updatedAt = Date.now();
      }

      const next = refreshTokensByHash.get(nextTokenHash);
      if (next) {
        next.rotatedFrom = previousTokenHash;
        next.updatedAt = Date.now();
      }
    },

    rotateRefreshToken: async ({ previousTokenHash, nextTokenHash, sessionId, userId, expiresAt }) => {
      const normalizedSessionId = String(sessionId);
      const normalizedUserId = String(userId);
      const previous = refreshTokensByHash.get(previousTokenHash);
      if (
        !previous
        || previous.status !== 'active'
        || String(previous.sessionId || '') !== normalizedSessionId
        || String(previous.userId || '') !== normalizedUserId
      ) {
        return { ok: false };
      }

      previous.status = 'rotated';
      previous.rotatedTo = nextTokenHash;
      previous.updatedAt = Date.now();

      refreshTokensByHash.set(nextTokenHash, {
        tokenHash: nextTokenHash,
        sessionId: normalizedSessionId,
        userId: normalizedUserId,
        status: 'active',
        rotatedFrom: previousTokenHash,
        rotatedTo: null,
        expiresAt,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });

      return { ok: true };
    },

    updateUserPasswordAndBumpSessionVersion: async ({ userId, passwordHash }) => {
      const user = bumpSessionVersionAndConvergeSessions({
        userId,
        passwordHash,
        reason: 'password-changed',
        revokeRefreshTokens: false,
        revokeAuthSessions: false
      });
      return clone(user);
    },

    updateUserPasswordAndRevokeSessions: async ({ userId, passwordHash, reason }) => {
      const user = bumpSessionVersionAndConvergeSessions({
        userId,
        passwordHash,
        reason: reason || 'password-changed',
        revokeRefreshTokens: true,
        revokeAuthSessions: true
      });
      return clone(user);
    }
  };
};

module.exports = { createInMemoryAuthStore };

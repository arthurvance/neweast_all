'use strict';

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
  createSharedMysqlAuthStoreRepositoryCapabilityComposition
} = require('./mysql/shared-mysql-auth-store-repository-capability-composition');
const {
  createSharedMysqlAuthStoreSessionAuditMethodComposition
} = require('./mysql/shared-mysql-auth-store-session-audit-method-composition');
const {
  createSharedMysqlAuthStoreSessionAuditRuntimeCapability
} = require('./mysql/shared-mysql-auth-store-session-audit-runtime-capability');
const {
  createSharedMysqlAuthStoreDeadlockRetryRuntimeCapability
} = require('./mysql/shared-mysql-auth-store-deadlock-retry-runtime-capability');
const {
  createSharedMysqlAuthStoreSessionConvergenceRuntimeSupport
} = require('./mysql/shared-mysql-auth-store-session-convergence-runtime-support');
const {
  createPlatformMysqlAuthStoreCapabilityComposition
} = require('../../../domains/platform/auth/store/mysql/platform-mysql-auth-store-capability-composition');
const {
  createPlatformMysqlAuthStoreRoleSnapshotRuntimeSupport
} = require('../../../domains/platform/auth/store/mysql/platform-mysql-auth-store-role-snapshot-runtime-support');
const {
  createPlatformMysqlAuthStoreRepositoryCapabilityComposition
} = require('../../../domains/platform/auth/store/mysql/platform-mysql-auth-store-repository-capability-composition');
const {
  createTenantMysqlAuthStoreCapabilityComposition
} = require('../../../domains/tenant/auth/store/mysql/tenant-mysql-auth-store-capability-composition');
const {
  createTenantMysqlAuthStoreRepositoryCapabilityComposition
} = require('../../../domains/tenant/auth/store/mysql/tenant-mysql-auth-store-repository-capability-composition');
const {
  createTenantMysqlAuthStoreUsershipDomainAccessRuntimeSupport
} = require('../../../domains/tenant/auth/store/mysql/tenant-mysql-auth-store-usership-domain-access-runtime-support');
const {
  createTenantMysqlAuthStoreUsershipHistoryRuntimeSupport
} = require('../../../domains/tenant/auth/store/mysql/tenant-mysql-auth-store-usership-history-runtime-support');
const {
  createTenantMysqlAuthStoreUsershipPermissionSnapshotRuntimeSupport
} = require('../../../domains/tenant/auth/store/mysql/tenant-mysql-auth-store-usership-permission-snapshot-runtime-support');

const {
  DEFAULT_DEADLOCK_RETRY_CONFIG,
  DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS,
  MYSQL_DUP_ENTRY_ERRNO,
  CONTROL_CHAR_PATTERN,
  ROLE_ID_ADDRESSABLE_PATTERN,
  VALID_ORG_STATUS,
  VALID_PLATFORM_USER_STATUS,
  VALID_SYSTEM_SENSITIVE_CONFIG_STATUS,
  ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS,
  VALID_PLATFORM_ROLE_CATALOG_STATUS,
  VALID_PLATFORM_ROLE_CATALOG_SCOPE,
  VALID_PLATFORM_INTEGRATION_DIRECTION,
  VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS,
  VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT,
  VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS,
  VALID_PLATFORM_INTEGRATION_FREEZE_STATUS,
  MAX_PLATFORM_INTEGRATION_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_CODE_LENGTH,
  MAX_PLATFORM_INTEGRATION_NAME_LENGTH,
  MAX_PLATFORM_INTEGRATION_PROTOCOL_LENGTH,
  MAX_PLATFORM_INTEGRATION_AUTH_MODE_LENGTH,
  MAX_PLATFORM_INTEGRATION_ENDPOINT_LENGTH,
  MAX_PLATFORM_INTEGRATION_BASE_URL_LENGTH,
  MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH,
  MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH,
  MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_REF_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_CHECKSUM_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_NOTES_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_DIFF_SUMMARY_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_REASON_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_LIST_LIMIT,
  MAX_PLATFORM_INTEGRATION_FREEZE_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH,
  MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH,
  MAX_OPERATOR_USER_ID_LENGTH,
  PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS,
  MAX_PLATFORM_INTEGRATION_TIMEOUT_MS,
  DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS,
  VALID_TENANT_MEMBERSHIP_STATUS,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
  MAX_PLATFORM_ROLE_CODE_LENGTH,
  MAX_PLATFORM_ROLE_NAME_LENGTH,
  MAINLAND_PHONE_PATTERN,
  KNOWN_PLATFORM_PERMISSION_CODE_SET,
  KNOWN_TENANT_PERMISSION_CODE_SET,
  PLATFORM_ROLE_MANAGEMENT_PERMISSION_CODE_SET,
  OWNER_TRANSFER_LOCK_TIMEOUT_SECONDS_MAX,
  OWNER_TRANSFER_LOCK_NAME_PREFIX,
  OWNER_TRANSFER_TAKEOVER_ROLE_ID_PREFIX,
  OWNER_TRANSFER_TAKEOVER_ROLE_ID_DIGEST_LENGTH,
  OWNER_TRANSFER_TAKEOVER_ROLE_CODE,
  OWNER_TRANSFER_TAKEOVER_ROLE_NAME,
  OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES,
  AUDIT_EVENT_ALLOWED_DOMAINS,
  AUDIT_EVENT_ALLOWED_RESULTS,
  AUDIT_EVENT_REDACTION_KEY_PATTERN,
  AUDIT_EVENT_REDACTION_COUNT_KEY_PATTERN,
  MAX_AUDIT_QUERY_PAGE_SIZE,
  MYSQL_AUDIT_DATETIME_PATTERN,
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
  isStrictOptionalTenantUserProfileField,
  toBoolean,
  normalizeAuditDomain,
  normalizeAuditResult,
  normalizeAuditStringOrNull,
  normalizeAuditTraceparentOrNull,
  parseMySqlAuditDateTimeAsUtc,
  resolveAuditOccurredAtDate,
  normalizeAuditOccurredAt,
  formatAuditDateTimeForMySql,
  safeParseJsonValue,
  resolvePlatformIntegrationNetworkErrorCodeFromSnapshot,
  isPlatformIntegrationRecoveryFailureRetryable,
  sanitizeAuditState,
  toAuditEventRecord,
  isActiveLikeStatus,
  VALID_PLATFORM_ROLE_FACT_STATUS,
  toPlatformPermissionSnapshot,
  isSamePlatformPermissionSnapshot,
  normalizePlatformRoleStatus,
  aggregatePlatformPermissionFromRoleRows,
  normalizePlatformRoleFactPayload,
  dedupePlatformRoleFacts,
  toSessionRecord,
  toRefreshRecord,
  toUserRecord,
  toPlatformRoleCatalogRecord,
  toPlatformIntegrationCatalogRecord,
  toPlatformIntegrationContractVersionRecord,
  toPlatformIntegrationContractCompatibilityCheckRecord,
  toPlatformIntegrationRecoveryQueueRecord,
  toPlatformIntegrationFreezeRecord,
  findActivePlatformIntegrationFreezeRecordForWriteGate,
  assertPlatformIntegrationWriteAllowedByFreezeGate,
  isTableMissingError,
  isDeadlockError,
  isDuplicateEntryError,
  isMissingTenantUsershipHistoryTableError,
  isMissingTenantsTableError,
  TENANT_MEMBERSHIP_HISTORY_UNAVAILABLE_CODE,
  createTenantUsershipHistoryUnavailableError,
  buildSqlInPlaceholders,
  normalizeSystemSensitiveConfigKey,
  normalizeSystemSensitiveConfigStatus,
  createSystemSensitiveConfigVersionConflictError,
  toSystemSensitiveConfigRecord,
  normalizePlatformPermissionCode,
  toPlatformPermissionCodeKey,
  normalizePlatformPermissionCodes,
  createPlatformRolePermissionGrantDataError,
  normalizeStrictPlatformPermissionCodeFromGrantRow,
  normalizeStrictRoleIdFromPlatformGrantRow,
  toPlatformPermissionSnapshotFromGrantCodes,
  normalizeTenantPermissionCode,
  normalizeTenantPermissionCodes,
  createTenantRolePermissionGrantDataError,
  normalizeStrictTenantPermissionCodeFromGrantRow,
  normalizeStrictTenantRolePermissionGrantIdentity,
  normalizeStrictRoleIdFromTenantGrantRow,
  createTenantUsershipRoleBindingDataError,
  normalizeStrictTenantUsershipRoleIdFromBindingRow,
  normalizeStrictTenantUsershipRoleBindingIdentity,
  toTenantPermissionSnapshotFromGrantCodes,
  toTenantPermissionSnapshotFromRow,
  isSameTenantPermissionSnapshot,
} = {
  ...require('./mysql/shared-mysql-auth-store-runtime-domain-constraint-constants'),
  ...require('./mysql/shared-mysql-auth-store-runtime-domain-normalization-guard-capability'),
  ...require('./mysql/shared-mysql-auth-store-runtime-storage-row-projection-capability'),
  ...require('./mysql/shared-mysql-auth-store-runtime-audit-normalization-capability'),
  ...require('./mysql/shared-mysql-auth-store-runtime-platform-permission-aggregation-capability'),
  ...require('./mysql/shared-mysql-auth-store-runtime-storage-grant-validation-capability')
};

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

  const {
    retryConfig,
    deadlockMetricsByOperation,
    getDeadlockMetricsByOperation,
    toDeadlockRates,
    emitDeadlockMetric,
    computeRetryDelayMs,
    executeWithDeadlockRetry
  } = createSharedMysqlAuthStoreDeadlockRetryRuntimeCapability({
    random,
    sleepFn,
    onDeadlockMetric,
    defaultRetryConfig: DEFAULT_DEADLOCK_RETRY_CONFIG,
    defaultFallbackResult: DEFAULT_DEADLOCK_FALLBACK_RESULT,
    deadlockRetryConfig,
    isDeadlockError,
    log
  });
  const {
    runTenantUsershipQuery,
    ensureTenantDomainAccessForUserTx,
    removeTenantDomainAccessForUserTx,
    isOrgStatusGuardAvailable
  } = createTenantMysqlAuthStoreUsershipDomainAccessRuntimeSupport({
    dbClient,
    isMissingTenantsTableError
  });

  const {
    insertTenantUsershipHistoryTx,
    isTenantUsershipHistoryTableAvailable
  } = createTenantMysqlAuthStoreUsershipHistoryRuntimeSupport({
    createTenantUsershipHistoryUnavailableError,
    isMissingTenantUsershipHistoryTableError,
    normalizeTenantUsershipStatusForRead,
    VALID_TENANT_MEMBERSHIP_STATUS,
    toBoolean
  });

  const {
    normalizeTenantUsershipRoleIds,
    revokeTenantSessionsForUserTx,
    listTenantUsershipRoleBindingsTx,
    loadActiveTenantRoleGrantCodesByRoleIdsTx,
    resolveTenantPermissionSnapshotForMembershipTx,
    syncTenantUsershipPermissionSnapshotInTx
  } = createTenantMysqlAuthStoreUsershipPermissionSnapshotRuntimeSupport({
    buildSqlInPlaceholders,
    normalizePlatformRoleCatalogRoleId,
    normalizeStrictTenantUsershipRoleIdFromBindingRow,
    createTenantUsershipRoleBindingDataError,
    normalizeStrictRoleIdFromTenantGrantRow,
    normalizePlatformRoleCatalogScope,
    normalizePlatformRoleCatalogTenantId,
    normalizePlatformRoleCatalogStatus,
    isActiveLikeStatus,
    createTenantRolePermissionGrantDataError,
    normalizeStrictTenantPermissionCodeFromGrantRow,
    normalizeTenantUsershipStatusForRead,
    toTenantPermissionSnapshotFromGrantCodes,
    toTenantPermissionSnapshotFromRow,
    isSameTenantPermissionSnapshot
  });

  const { bumpSessionVersionAndConvergeSessionsTx } =
    createSharedMysqlAuthStoreSessionConvergenceRuntimeSupport({
      toUserRecord
    });

  const {
    replacePlatformRolesAndSyncSnapshot,
    replacePlatformRolesAndSyncSnapshotInTx,
    replacePlatformRolesAndSyncSnapshotOnce,
    resolveActivePlatformPermissionSnapshotByUserIdTx,
    syncPlatformPermissionSnapshotByUserId,
    syncPlatformPermissionSnapshotByUserIdOnce
  } = createPlatformMysqlAuthStoreRoleSnapshotRuntimeSupport({
    VALID_PLATFORM_USER_STATUS,
    aggregatePlatformPermissionFromRoleRows,
    bumpSessionVersionAndConvergeSessionsTx,
    dbClient,
    dedupePlatformRoleFacts,
    executeWithDeadlockRetry,
    isSamePlatformPermissionSnapshot,
    normalizeOrgStatus,
    normalizeUserStatus,
    toPlatformPermissionSnapshot,
    toPlatformPermissionSnapshotFromCodes
  });

  const {
    listAuditEvents,
    recordAuditEvent,
    recordAuditEventWithQueryClient
  } = createSharedMysqlAuthStoreSessionAuditRuntimeCapability({
    MAX_AUDIT_QUERY_PAGE_SIZE,
    dbClient,
    formatAuditDateTimeForMySql,
    normalizeAuditDomain,
    normalizeAuditOccurredAt,
    normalizeAuditResult,
    normalizeAuditStringOrNull,
    normalizeAuditTraceparentOrNull,
    randomUUID,
    sanitizeAuditState,
    toAuditEventRecord
  });

  const repositoryMethodDependencies = {
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
  };
  const sharedRepositoryMethods = createSharedMysqlAuthStoreRepositoryCapabilityComposition(
    repositoryMethodDependencies
  );
  const platformRepositoryMethods = createPlatformMysqlAuthStoreRepositoryCapabilityComposition(
    repositoryMethodDependencies
  );
  const tenantRepositoryMethods = createTenantMysqlAuthStoreRepositoryCapabilityComposition(
    repositoryMethodDependencies
  );
  const repositoryMethods = {
    ...sharedRepositoryMethods,
    ...platformRepositoryMethods,
    ...tenantRepositoryMethods
  };

    const authStoreMethodDependencies = {
    ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS,
    AUDIT_EVENT_ALLOWED_DOMAINS,
    AUDIT_EVENT_ALLOWED_RESULTS,
    AUDIT_EVENT_REDACTION_COUNT_KEY_PATTERN,
    AUDIT_EVENT_REDACTION_KEY_PATTERN,
    CONTROL_CHAR_PATTERN,
    DEFAULT_DEADLOCK_FALLBACK_RESULT,
    DEFAULT_DEADLOCK_RETRY_CONFIG,
    DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS,
    DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS,
    KNOWN_PLATFORM_PERMISSION_CODES,
    KNOWN_PLATFORM_PERMISSION_CODE_SET,
    KNOWN_TENANT_PERMISSION_CODES,
    KNOWN_TENANT_PERMISSION_CODE_SET,
    MAINLAND_PHONE_PATTERN,
    MAX_AUDIT_QUERY_PAGE_SIZE,
    MAX_OPERATOR_USER_ID_LENGTH,
    MAX_PLATFORM_INTEGRATION_AUTH_MODE_LENGTH,
    MAX_PLATFORM_INTEGRATION_BASE_URL_LENGTH,
    MAX_PLATFORM_INTEGRATION_CODE_LENGTH,
    MAX_PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_NOTES_LENGTH,
    MAX_PLATFORM_INTEGRATION_CONTRACT_DIFF_SUMMARY_LENGTH,
    MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH,
    MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_CHECKSUM_LENGTH,
    MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_REF_LENGTH,
    MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
    MAX_PLATFORM_INTEGRATION_ENDPOINT_LENGTH,
    MAX_PLATFORM_INTEGRATION_FREEZE_ID_LENGTH,
    MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH,
    MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH,
    MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH,
    MAX_PLATFORM_INTEGRATION_ID_LENGTH,
    MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH,
    MAX_PLATFORM_INTEGRATION_NAME_LENGTH,
    MAX_PLATFORM_INTEGRATION_PROTOCOL_LENGTH,
    MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH,
    MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH,
    MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH,
    MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH,
    MAX_PLATFORM_INTEGRATION_RECOVERY_LIST_LIMIT,
    MAX_PLATFORM_INTEGRATION_RECOVERY_REASON_LENGTH,
    MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH,
    MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH,
    MAX_PLATFORM_INTEGRATION_TIMEOUT_MS,
    MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH,
    MAX_PLATFORM_ROLE_CODE_LENGTH,
    MAX_PLATFORM_ROLE_NAME_LENGTH,
    MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
    MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
    MYSQL_AUDIT_DATETIME_PATTERN,
    MYSQL_DUP_ENTRY_ERRNO,
    OWNER_TRANSFER_LOCK_NAME_PREFIX,
    OWNER_TRANSFER_LOCK_TIMEOUT_SECONDS_MAX,
    OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES,
    OWNER_TRANSFER_TAKEOVER_ROLE_CODE,
    OWNER_TRANSFER_TAKEOVER_ROLE_ID_DIGEST_LENGTH,
    OWNER_TRANSFER_TAKEOVER_ROLE_ID_PREFIX,
    OWNER_TRANSFER_TAKEOVER_ROLE_NAME,
    PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN,
    PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS,
    PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
    PLATFORM_ROLE_MANAGEMENT_PERMISSION_CODE_SET,
    PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
    PLATFORM_TENANT_MANAGEMENT_OPERATE_PERMISSION_CODE,
    PLATFORM_TENANT_MANAGEMENT_VIEW_PERMISSION_CODE,
    PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
    PLATFORM_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
    ROLE_ID_ADDRESSABLE_PATTERN,
    ROLE_MANAGEMENT_PERMISSION_CODE_KEY_SET,
    TENANT_MEMBERSHIP_HISTORY_UNAVAILABLE_CODE,
    TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
    TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
    TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
    TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
    VALID_ORG_STATUS,
    VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT,
    VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS,
    VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
    VALID_PLATFORM_INTEGRATION_DIRECTION,
    VALID_PLATFORM_INTEGRATION_FREEZE_STATUS,
    VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS,
    VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS,
    VALID_PLATFORM_ROLE_CATALOG_SCOPE,
    VALID_PLATFORM_ROLE_CATALOG_STATUS,
    VALID_PLATFORM_ROLE_FACT_STATUS,
    VALID_PLATFORM_USER_STATUS,
    VALID_SYSTEM_SENSITIVE_CONFIG_STATUS,
    VALID_TENANT_MEMBERSHIP_STATUS,
    aggregatePlatformPermissionFromRoleRows,
    assertPlatformIntegrationWriteAllowedByFreezeGate,
    buildSqlInPlaceholders,
    bumpSessionVersionAndConvergeSessionsTx,
    computeRetryDelayMs,
    computeRetrySchedule,
    createHash,
    createSharedMysqlAuthStoreRepositoryCapabilityComposition,
    createPlatformIntegrationContractActivationBlockedError,
    createPlatformIntegrationFreezeActiveConflictError,
    createPlatformIntegrationFreezeReleaseConflictError,
    createPlatformIntegrationLifecycleConflictError,
    createPlatformIntegrationRecoveryReplayConflictError,
    createPlatformMysqlAuthStoreCapabilityComposition,
    createPlatformRolePermissionGrantDataError,
    createSystemSensitiveConfigVersionConflictError,
    createTenantMysqlAuthStoreCapabilityComposition,
    createTenantRolePermissionGrantDataError,
    createTenantUsershipHistoryUnavailableError,
    createTenantUsershipRoleBindingDataError,
    dbClient,
    deadlockMetricsByOperation,
    deadlockRetryConfig,
    dedupePlatformRoleFacts,
    emitDeadlockMetric,
    ensureTenantDomainAccessForUserTx,
    escapeSqlLikePattern,
    executeWithDeadlockRetry,
    findActivePlatformIntegrationFreezeRecordForWriteGate,
    formatAuditDateTimeForMySql,
    getDeadlockMetricsByOperation,
    insertTenantUsershipHistoryTx,
    isActiveLikeStatus,
    isDeadlockError,
    isDuplicateEntryError,
    isMissingTenantUsershipHistoryTableError,
    isMissingTenantsTableError,
    isPlatformIntegrationLifecycleTransitionAllowed,
    isPlatformIntegrationRecoveryFailureRetryable,
    isRetryableDeliveryFailure,
    isSamePlatformPermissionSnapshot,
    isSameTenantPermissionSnapshot,
    isStrictMainlandPhone,
    isStrictOptionalTenantUserProfileField,
    isTableMissingError,
    isValidPlatformIntegrationId,
    listAuditEvents,
    listTenantUsershipRoleBindingsTx,
    loadActiveTenantRoleGrantCodesByRoleIdsTx,
    log,
    normalizeAuditDomain,
    normalizeAuditOccurredAt,
    normalizeAuditResult,
    normalizeAuditStringOrNull,
    normalizeAuditTraceparentOrNull,
    normalizeOptionalPlatformUserProfileField,
    normalizeOptionalTenantUserProfileField,
    normalizeOrgName,
    normalizeOrgStatus,
    normalizeOwnerTransferLockTimeoutSeconds,
    normalizePlatformIntegrationCode,
    normalizePlatformIntegrationCodeKey,
    normalizePlatformIntegrationContractEvaluationResult,
    normalizePlatformIntegrationContractSchemaChecksum,
    normalizePlatformIntegrationContractStatus,
    normalizePlatformIntegrationContractType,
    normalizePlatformIntegrationContractVersion,
    normalizePlatformIntegrationDirection,
    normalizePlatformIntegrationFreezeId,
    normalizePlatformIntegrationFreezeStatus,
    normalizePlatformIntegrationId,
    normalizePlatformIntegrationJsonForStorage,
    normalizePlatformIntegrationLifecycleStatus,
    normalizePlatformIntegrationOptionalText,
    normalizePlatformIntegrationRecoveryId,
    normalizePlatformIntegrationRecoveryIdempotencyKey,
    normalizePlatformIntegrationRecoveryStatus,
    normalizePlatformIntegrationTimeoutMs,
    normalizePlatformPermissionCode,
    normalizePlatformPermissionCodes,
    normalizePlatformRoleCatalogCode,
    normalizePlatformRoleCatalogRoleId,
    normalizePlatformRoleCatalogScope,
    normalizePlatformRoleCatalogStatus,
    normalizePlatformRoleCatalogTenantId,
    normalizePlatformRoleCatalogTenantIdForScope,
    normalizePlatformRoleFactPayload,
    normalizePlatformRoleStatus,
    normalizeRequiredPlatformUserProfileField,
    normalizeStoreIsoTimestamp,
    normalizeStrictPlatformPermissionCodeFromGrantRow,
    normalizeStrictRoleIdFromPlatformGrantRow,
    normalizeStrictRoleIdFromTenantGrantRow,
    normalizeStrictTenantPermissionCodeFromGrantRow,
    normalizeStrictTenantRolePermissionGrantIdentity,
    normalizeStrictTenantUsershipRoleBindingIdentity,
    normalizeStrictTenantUsershipRoleIdFromBindingRow,
    normalizeSystemSensitiveConfigKey,
    normalizeSystemSensitiveConfigStatus,
    normalizeTenantPermissionCode,
    normalizeTenantPermissionCodes,
    normalizeTenantUsershipRoleIds,
    normalizeTenantUsershipStatus,
    normalizeTenantUsershipStatusForRead,
    normalizeTraceparent,
    normalizeUserStatus,
    onDeadlockMetric,
    orgStatusGuardAvailable: isOrgStatusGuardAvailable(),
    parseMySqlAuditDateTimeAsUtc,
    random,
    randomUUID,
    recordAuditEvent,
    recordAuditEventWithQueryClient,
    removeTenantDomainAccessForUserTx,
    replacePlatformRolesAndSyncSnapshot,
    replacePlatformRolesAndSyncSnapshotInTx,
    replacePlatformRolesAndSyncSnapshotOnce,
    repositoryMethods,
    resolveActivePlatformPermissionSnapshotByUserIdTx,
    resolveAuditOccurredAtDate,
    resolveOptionalTenantUserProfileField,
    resolvePlatformIntegrationNetworkErrorCodeFromSnapshot,
    resolveTenantPermissionSnapshotForMembershipTx,
    retryConfig,
    revokeTenantSessionsForUserTx,
    runTenantUsershipQuery,
    safeParseJsonValue,
    sanitizeAuditState,
    sleep,
    sleepFn,
    syncPlatformPermissionSnapshotByUserId,
    syncPlatformPermissionSnapshotByUserIdOnce,
    syncTenantUsershipPermissionSnapshotInTx,
    tenantUsershipHistoryTableAvailable: isTenantUsershipHistoryTableAvailable(),
    toAuditEventRecord,
    toBoolean,
    toDeadlockRates,
    toOwnerTransferLockName,
    toOwnerTransferTakeoverRoleId,
    toPlatformIntegrationCatalogRecord,
    toPlatformIntegrationContractCompatibilityCheckRecord,
    toPlatformIntegrationContractVersionRecord,
    toPlatformIntegrationFreezeRecord,
    toPlatformIntegrationRecoveryQueueRecord,
    toPlatformPermissionCodeKey,
    toPlatformPermissionSnapshot,
    toPlatformPermissionSnapshotFromCodes,
    toPlatformPermissionSnapshotFromGrantCodes,
    toPlatformRoleCatalogRecord,
    toRefreshRecord,
    toSessionRecord,
    toSystemSensitiveConfigRecord,
    toTenantPermissionSnapshotFromCodes,
    toTenantPermissionSnapshotFromGrantCodes,
    toTenantPermissionSnapshotFromRow,
    toUserRecord
  };

  const sharedMysqlAuthStoreMethods = createSharedMysqlAuthStoreSessionAuditMethodComposition(
    authStoreMethodDependencies
  );
  const platformMysqlAuthStoreMethods = createPlatformMysqlAuthStoreCapabilityComposition(
    authStoreMethodDependencies
  );
  const tenantMysqlAuthStoreMethods = createTenantMysqlAuthStoreCapabilityComposition(
    authStoreMethodDependencies
  );

  return {
    ...sharedMysqlAuthStoreMethods,
    ...platformMysqlAuthStoreMethods,
    ...tenantMysqlAuthStoreMethods
  };
};

module.exports = { createMySqlAuthStore };

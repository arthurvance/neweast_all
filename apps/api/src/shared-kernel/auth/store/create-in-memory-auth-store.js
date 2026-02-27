'use strict';

const { createHash, randomUUID } = require('node:crypto');
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
  TENANT_ACCOUNT_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_ACCOUNT_MANAGEMENT_OPERATE_PERMISSION_CODE,
  TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
  PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
  toPlatformPermissionSnapshotFromCodes,
  toTenantPermissionSnapshotFromCodes
} = require('../../../modules/auth/permission-catalog');
const {
  createSharedMemoryAuthStoreRepositoryCapabilityComposition
} = require('./memory/shared-memory-auth-store-repository-capability-composition');
const {
  createSharedMemoryAuthStoreSessionAuditMethodComposition
} = require('./memory/shared-memory-auth-store-session-audit-method-composition');
const {
  createSharedMemoryAuthStoreSessionAuditRuntimeSupport
} = require('./memory/shared-memory-auth-store-session-audit-runtime-support');
const {
  createSharedMemoryAuthStoreSessionConvergenceRuntimeSupport
} = require('./memory/shared-memory-auth-store-session-convergence-runtime-support');
const {
  createSharedMemoryAuthStoreTestFaultInjectionRuntimeSupport
} = require('./memory/shared-memory-auth-store-test-fault-injection-runtime-support');
const {
  createSharedMemoryAuthStoreSystemSensitiveConfigRuntimeCapability
} = require('./memory/shared-memory-auth-store-system-sensitive-config-runtime-capability');
const {
  createSharedMemoryAuthStoreOrgGovernanceRuntimeCapability
} = require('./memory/shared-memory-auth-store-org-governance-runtime-capability');
const {
  createSharedMemoryAuthStorePlatformProfileNormalizationRuntimeCapability
} = require('./memory/shared-memory-auth-store-platform-profile-normalization-runtime-capability');
const {
  createSharedMemoryAuthStoreSeedUserBootstrapRuntimeSupport
} = require('./memory/shared-memory-auth-store-seed-user-bootstrap-runtime-support');
const {
  createSharedMemoryAuthStoreEntityRecordCloneRuntimeSupport
} = require('./memory/shared-memory-auth-store-entity-record-clone-runtime-support');
const {
  createPlatformMemoryAuthStoreCapabilityComposition
} = require('../../../domains/platform/auth/store/memory/platform-memory-auth-store-capability-composition');
const {
  createPlatformMemoryAuthStoreUserReadRuntimeSupport
} = require('../../../domains/platform/auth/store/memory/platform-memory-auth-store-user-read-runtime-support');
const {
  createPlatformMemoryAuthStoreRepositoryCapabilityComposition
} = require('../../../domains/platform/auth/store/memory/platform-memory-auth-store-repository-capability-composition');
const {
  createTenantMemoryAuthStoreCapabilityComposition
} = require('../../../domains/tenant/auth/store/memory/tenant-memory-auth-store-capability-composition');
const {
  createTenantMemoryAuthStoreRepositoryCapabilityComposition
} = require('../../../domains/tenant/auth/store/memory/tenant-memory-auth-store-repository-capability-composition');
const {
  createPlatformMemoryAuthStoreRuntimeBootstrap
} = require('../../../domains/platform/auth/store/memory/platform-memory-auth-store-runtime-bootstrap');
const {
  createTenantMemoryAuthStoreRuntimeBootstrap
} = require('../../../domains/tenant/auth/store/memory/tenant-memory-auth-store-runtime-bootstrap');

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
  const tenantUsershipRolesByMembershipId = new Map();
  const tenantAccountsByAccountId = new Map();
  const tenantAccountIdsByTenantId = new Map();
  const tenantAccountWechatIndexByTenantId = new Map();
  const tenantAccountAssistantsByAccountId = new Map();
  const tenantAccountOperationLogsByAccountId = new Map();
  const systemSensitiveConfigsByKey = new Map();
  const orgsById = new Map();
  const tenantUsershipHistoryByPair = new Map();
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
  const MAX_TENANT_USER_DISPLAY_NAME_LENGTH = 64;
  const MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH = 128;
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
  const MAX_PLATFORM_ROLE_CODE_LENGTH = 64;
  const MAX_PLATFORM_ROLE_NAME_LENGTH = 128;
  const { invokeFaultInjector } = createSharedMemoryAuthStoreTestFaultInjectionRuntimeSupport({
    faultInjector
  });
  const KNOWN_PLATFORM_PERMISSION_CODE_SET = new Set(KNOWN_PLATFORM_PERMISSION_CODES);
  const KNOWN_TENANT_PERMISSION_CODE_SET = new Set(KNOWN_TENANT_PERMISSION_CODES);
  const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
  const ROLE_ID_ADDRESSABLE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
  const MAINLAND_PHONE_PATTERN = /^1\d{10}$/;
  const {
    normalizeSystemSensitiveConfigKey,
    normalizeSystemSensitiveConfigStatus,
    cloneSystemSensitiveConfigRecord
  } = createSharedMemoryAuthStoreSystemSensitiveConfigRuntimeCapability({
    VALID_SYSTEM_SENSITIVE_CONFIG_STATUS
  });
  const {
    isActiveLikeStatus,
    normalizeOrgStatus,
    toOwnerTransferTakeoverRoleId
  } = createSharedMemoryAuthStoreOrgGovernanceRuntimeCapability({
    OWNER_TRANSFER_TAKEOVER_ROLE_ID_DIGEST_LENGTH,
    OWNER_TRANSFER_TAKEOVER_ROLE_ID_PREFIX
  });

  const platformMemoryRuntimeBootstrap = createPlatformMemoryAuthStoreRuntimeBootstrap({
    CONTROL_CHAR_PATTERN,
    KNOWN_PLATFORM_PERMISSION_CODES,
    KNOWN_PLATFORM_PERMISSION_CODE_SET,
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
    MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH,
    MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH,
    MAX_PLATFORM_INTEGRATION_TIMEOUT_MS,
    MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH,
    MAX_PLATFORM_ROLE_CODE_LENGTH,
    MAX_PLATFORM_ROLE_NAME_LENGTH,
    PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS,
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
    domainsByUserId,
    isActiveLikeStatus,
    platformIntegrationCatalogById,
    platformIntegrationCatalogCodeIndex,
    platformIntegrationContractVersionsByKey,
    platformIntegrationFreezeById,
    platformIntegrationRecoveryDedupIndex,
    platformIntegrationRecoveryQueueByRecoveryId,
    platformPermissionsByUserId,
    platformProfilesByUserId,
    platformRoleCatalogById,
    platformRoleCatalogCodeIndex,
    platformRolePermissionGrantsByRoleId,
    platformRolesByUserId,
    toPlatformPermissionSnapshotFromCodes,
    usersById,
    nextPlatformIntegrationContractVersionId
  });

  const {
    normalizePlatformRoleStatus,
    normalizePlatformRoleCatalogStatus,
    normalizePlatformRoleCatalogScope,
    normalizePlatformRoleCatalogTenantId,
    normalizePlatformRoleCatalogTenantIdForScope,
    normalizePlatformRoleCatalogRoleId,
    toPlatformRoleCatalogRoleIdKey,
    normalizePlatformRoleCatalogCode,
    toPlatformRoleCatalogCodeKey,
    toPlatformRoleCatalogCodeIndexKey,
    normalizePlatformIntegrationId,
    isValidPlatformIntegrationId,
    normalizePlatformIntegrationCode,
    toPlatformIntegrationCodeKey,
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
    toPlatformIntegrationContractVersionKey,
    toPlatformIntegrationContractScopeKey,
    toPlatformIntegrationRecoveryDedupKey,
    normalizePlatformIntegrationOptionalText,
    normalizePlatformIntegrationTimeoutMs,
    normalizePlatformIntegrationJsonForStorage,
    createDuplicatePlatformIntegrationCatalogEntryError,
    createDuplicatePlatformIntegrationContractVersionError,
    createPlatformIntegrationContractActivationBlockedError,
    isPlatformIntegrationLifecycleTransitionAllowed,
    createPlatformIntegrationLifecycleConflictError,
    createPlatformIntegrationRecoveryReplayConflictError,
    createPlatformIntegrationFreezeActiveConflictError,
    createPlatformIntegrationFreezeReleaseConflictError,
    normalizePlatformPermissionCode,
    toPlatformPermissionCodeKey,
    createDuplicatePlatformRoleCatalogEntryError,
    toPlatformRoleCatalogRecord,
    clonePlatformRoleCatalogRecord,
    toPlatformIntegrationCatalogRecord,
    clonePlatformIntegrationCatalogRecord,
    toPlatformIntegrationContractVersionRecord,
    clonePlatformIntegrationContractVersionRecord,
    toPlatformIntegrationContractCompatibilityCheckRecord,
    clonePlatformIntegrationContractCompatibilityCheckRecord,
    toPlatformIntegrationRecoveryQueueRecord,
    clonePlatformIntegrationRecoveryQueueRecord,
    toPlatformIntegrationFreezeRecord,
    clonePlatformIntegrationFreezeRecord,
    findPlatformRoleCatalogRecordStateByRoleId,
    findPlatformIntegrationCatalogRecordStateByIntegrationId,
    findPlatformIntegrationContractVersionRecordState,
    findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId,
    findPlatformIntegrationRecoveryQueueRecordStateByDedupKey,
    comparePlatformIntegrationFreezeRecords,
    findActivePlatformIntegrationFreezeRecordState,
    findLatestPlatformIntegrationFreezeRecordState,
    findActivePlatformIntegrationFreezeForWriteGate,
    assertPlatformIntegrationWriteAllowedByFreezeGate,
    normalizePlatformPermission,
    mergePlatformPermission,
    buildEmptyPlatformPermission,
    normalizePlatformPermissionCodes,
    resolvePlatformPermissionFromGrantCodes,
    createPlatformRolePermissionGrantDataError,
    listPlatformRolePermissionGrantsForRoleId,
    replacePlatformRolePermissionGrantsForRoleId,
    isSamePlatformPermission,
    normalizePlatformRole,
    dedupePlatformRolesByRoleId,
    mergePlatformPermissionFromRoles,
    syncPlatformPermissionFromRoleFacts,
    upsertPlatformRoleCatalogRecord,
    upsertPlatformIntegrationCatalogRecord,
    upsertPlatformIntegrationContractVersionRecord,
    upsertPlatformIntegrationRecoveryQueueRecord,
    upsertPlatformIntegrationFreezeRecord
  } = platformMemoryRuntimeBootstrap;

  const tenantMemoryRuntimeBootstrap = createTenantMemoryAuthStoreRuntimeBootstrap({
    CONTROL_CHAR_PATTERN,
    KNOWN_TENANT_PERMISSION_CODES,
    KNOWN_TENANT_PERMISSION_CODE_SET,
    MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
    MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
    ROLE_ID_ADDRESSABLE_PATTERN,
    VALID_TENANT_MEMBERSHIP_STATUS,
    findPlatformRoleCatalogRecordStateByRoleId,
    isActiveLikeStatus,
    isSamePlatformPermission,
    mergePlatformPermission,
    normalizePlatformPermission,
    normalizeOrgStatus,
    normalizePlatformRoleCatalogRoleId,
    normalizePlatformRoleCatalogScope,
    normalizePlatformRoleCatalogStatus,
    normalizePlatformRoleCatalogTenantId,
    orgsById,
    revokeTenantSessionsForUser: (params = {}) => revokeTenantSessionsForUser(params),
    tenantRolePermissionGrantsByRoleId,
    tenantAccountsByAccountId,
    tenantAccountIdsByTenantId,
    tenantAccountWechatIndexByTenantId,
    tenantAccountAssistantsByAccountId,
    tenantAccountOperationLogsByAccountId,
    tenantUsershipHistoryByPair,
    tenantUsershipRolesByMembershipId,
    tenantsByUserId,
    toTenantPermissionSnapshotFromCodes
  });

  const {
    normalizeTenantUsershipStatus,
    normalizeTenantUsershipStatusForRead,
    normalizeOptionalTenantUserProfileField,
    resolveOptionalTenantUserProfileField,
    isStrictOptionalTenantUserProfileField,
    appendTenantUsershipHistory,
    isTenantUsershipActiveForAuth,
    normalizeTenantPermissionCode,
    toTenantPermissionCodeKey,
    normalizeTenantPermissionCodes,
    createTenantRolePermissionGrantDataError,
    normalizeStrictTenantPermissionCodeFromGrantRow,
    normalizeStrictTenantRolePermissionGrantIdentity,
    createTenantUsershipRoleBindingDataError,
    normalizeStrictTenantUsershipRoleIdFromBindingRow,
    normalizeStrictTenantUsershipRoleBindingIdentity,
    buildEmptyTenantPermission,
    resolveTenantPermissionFromGrantCodes,
    listTenantRolePermissionGrantsForRoleId,
    replaceTenantRolePermissionGrantsForRoleId,
    findTenantUsershipStateByMembershipId,
    listTenantUsershipRoleBindingsForMembershipId,
    replaceTenantUsershipRoleBindingsForMembershipId,
    toTenantUsershipScopeLabel,
    resolveEffectiveTenantPermissionForMembership,
    syncTenantUsershipPermissionSnapshot,
    resolveLatestTenantUserProfileByUserId
  } = tenantMemoryRuntimeBootstrap;
  const {
    normalizeRequiredPlatformUserProfileField,
    normalizeOptionalPlatformUserProfileField
  } = createSharedMemoryAuthStorePlatformProfileNormalizationRuntimeCapability({
    normalizeOptionalTenantUserProfileField
  });
  const { bootstrapSeedUsers } = createSharedMemoryAuthStoreSeedUserBootstrapRuntimeSupport({
    dedupePlatformRolesByRoleId,
    mergePlatformPermission,
    mergePlatformPermissionFromRoles,
    normalizeOptionalTenantUserProfileField,
    normalizePlatformPermission,
    normalizePlatformRole,
    normalizeTenantUsershipStatus,
    randomUUID,
    resolveOptionalTenantUserProfileField
  });
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
  bootstrapSeedUsers({
    seedUsers,
    hashPassword,
    usersByPhone,
    usersById,
    domainsByUserId,
    platformDomainKnownByUserId,
    tenantsByUserId,
    platformProfilesByUserId,
    platformRolesByUserId,
    platformPermissionsByUserId,
    MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
    MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
  });

  const { clone } = createSharedMemoryAuthStoreEntityRecordCloneRuntimeSupport();

  const {
    cloneJsonValue,
    isPlatformIntegrationRecoveryFailureRetryable,
    normalizeAuditDomain,
    normalizeAuditOccurredAt,
    normalizeAuditResult,
    normalizeAuditStringOrNull,
    normalizeAuditTraceparentOrNull,
    persistAuditEvent,
    resolvePlatformIntegrationNetworkErrorCodeFromSnapshot,
    restoreAuditEventsFromSnapshot,
    restoreMapFromSnapshot,
    restoreSetFromSnapshot,
    safeParseJsonValue,
    sanitizeAuditState,
    toAuditEventRecord
  } = createSharedMemoryAuthStoreSessionAuditRuntimeSupport({
    AUDIT_EVENT_ALLOWED_DOMAINS,
    AUDIT_EVENT_ALLOWED_RESULTS,
    AUDIT_EVENT_REDACTION_COUNT_KEY_PATTERN,
    AUDIT_EVENT_REDACTION_KEY_PATTERN,
    auditEvents,
    isRetryableDeliveryFailure,
    normalizePlatformIntegrationOptionalText,
    normalizeTraceparent,
    randomUUID
  });

  const {
    bumpSessionVersionAndConvergeSessions,
    revokeSessionsForUserByEntryDomain,
    revokePlatformSessionsForUser,
    revokeTenantSessionsForUser,
    createForeignKeyConstraintError,
    createDataTooLongError,
    hasOrgReferenceForUser
  } = createSharedMemoryAuthStoreSessionConvergenceRuntimeSupport({
    usersByPhone,
    usersById,
    sessionsById,
    refreshTokensByHash,
    orgsById,
    membershipsByOrgId,
    clone
  });

  const {
    normalizeDateTimeFilterToEpoch,
    resolveLatestPlatformProfileByUserId,
    resolvePlatformUserReadModel
  } = createPlatformMemoryAuthStoreUserReadRuntimeSupport({
    MAX_PLATFORM_ROLE_CODE_LENGTH,
    MAX_PLATFORM_ROLE_NAME_LENGTH,
    MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
    MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
    VALID_PLATFORM_ROLE_CATALOG_STATUS,
    domainsByUserId,
    findPlatformRoleCatalogRecordStateByRoleId,
    isActiveLikeStatus,
    normalizeOptionalTenantUserProfileField,
    normalizePlatformRoleCatalogRoleId,
    normalizePlatformRoleCatalogStatus,
    normalizeRequiredPlatformUserProfileField,
    platformProfilesByUserId,
    platformRolesByUserId
  });

  const repositoryMethodDependencies = {
    clone,
    usersByPhone,
    usersById,
    orgsById,
    systemSensitiveConfigsByKey,
    sessionsById,
    refreshTokensByHash,
    domainsByUserId,
    platformDomainKnownByUserId,
    tenantsByUserId,
    platformProfilesByUserId,
    platformRoleCatalogById,
    platformRolesByUserId,
    platformPermissionsByUserId,
    cloneSystemSensitiveConfigRecord,
    clonePlatformRoleCatalogRecord,
    isTenantUsershipActiveForAuth,
    isActiveLikeStatus,
    resolvePlatformUserReadModel,
    resolveLatestTenantUserProfileByUserId,
    normalizeSystemSensitiveConfigKey,
    normalizeSystemSensitiveConfigStatus,
    normalizeOrgStatus,
    normalizeDateTimeFilterToEpoch,
    normalizeRequiredPlatformUserProfileField,
    normalizeOptionalPlatformUserProfileField,
    findPlatformRoleCatalogRecordStateByRoleId,
    normalizePlatformRoleCatalogRoleId,
    normalizePlatformRoleCatalogScope,
    normalizePlatformRoleCatalogTenantId,
    normalizePlatformRoleCatalogTenantIdForScope,
    normalizePlatformRoleCatalogStatus,
    listPlatformRolePermissionGrantsForRoleId,
    listTenantRolePermissionGrantsForRoleId,
    listTenantUsershipRoleBindingsForMembershipId,
    toPlatformPermissionCodeKey,
    syncPlatformPermissionFromRoleFacts,
    bumpSessionVersionAndConvergeSessions,
    MAINLAND_PHONE_PATTERN,
    CONTROL_CHAR_PATTERN,
    ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS,
    MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
    MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
    VALID_ORG_STATUS,
    VALID_PLATFORM_USER_STATUS,
    PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
    PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
  };
  const sharedRepositoryMethods = createSharedMemoryAuthStoreRepositoryCapabilityComposition(
    repositoryMethodDependencies
  );
  const platformRepositoryMethods =
    createPlatformMemoryAuthStoreRepositoryCapabilityComposition(
      repositoryMethodDependencies
    );
  const tenantRepositoryMethods =
    createTenantMemoryAuthStoreRepositoryCapabilityComposition(
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
    DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS,
    KNOWN_PLATFORM_PERMISSION_CODES,
    KNOWN_PLATFORM_PERMISSION_CODE_SET,
    KNOWN_TENANT_PERMISSION_CODES,
    KNOWN_TENANT_PERMISSION_CODE_SET,
    MAINLAND_PHONE_PATTERN,
    MAX_AUDIT_QUERY_PAGE_SIZE,
    MAX_OPERATOR_USER_ID_LENGTH,
    MAX_ORG_NAME_LENGTH,
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
    OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES,
    OWNER_TRANSFER_TAKEOVER_ROLE_CODE,
    OWNER_TRANSFER_TAKEOVER_ROLE_ID_DIGEST_LENGTH,
    OWNER_TRANSFER_TAKEOVER_ROLE_ID_PREFIX,
    OWNER_TRANSFER_TAKEOVER_ROLE_NAME,
    PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN,
    PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS,
    PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
    PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
    ROLE_ID_ADDRESSABLE_PATTERN,
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
    appendTenantUsershipHistory,
    assertPlatformIntegrationWriteAllowedByFreezeGate,
    auditEvents,
    buildEmptyPlatformPermission,
    buildEmptyTenantPermission,
    bumpSessionVersionAndConvergeSessions,
    clone,
    cloneJsonValue,
    clonePlatformIntegrationCatalogRecord,
    clonePlatformIntegrationContractCompatibilityCheckRecord,
    clonePlatformIntegrationContractVersionRecord,
    clonePlatformIntegrationFreezeRecord,
    clonePlatformIntegrationRecoveryQueueRecord,
    clonePlatformRoleCatalogRecord,
    cloneSystemSensitiveConfigRecord,
    comparePlatformIntegrationFreezeRecords,
    computeRetrySchedule,
    createDataTooLongError,
    createDuplicatePlatformIntegrationCatalogEntryError,
    createDuplicatePlatformIntegrationContractVersionError,
    createDuplicatePlatformRoleCatalogEntryError,
    createForeignKeyConstraintError,
    createHash,
    createSharedMemoryAuthStoreRepositoryCapabilityComposition,
    createPlatformIntegrationContractActivationBlockedError,
    createPlatformIntegrationFreezeActiveConflictError,
    createPlatformIntegrationFreezeReleaseConflictError,
    createPlatformIntegrationLifecycleConflictError,
    createPlatformIntegrationRecoveryReplayConflictError,
    createPlatformMemoryAuthStoreCapabilityComposition,
    createPlatformRolePermissionGrantDataError,
    createTenantMemoryAuthStoreCapabilityComposition,
    createTenantRolePermissionGrantDataError,
    createTenantUsershipRoleBindingDataError,
    dedupePlatformRolesByRoleId,
    domainsByUserId,
    faultInjector,
    findActivePlatformIntegrationFreezeForWriteGate,
    findActivePlatformIntegrationFreezeRecordState,
    findLatestPlatformIntegrationFreezeRecordState,
    findPlatformIntegrationCatalogRecordStateByIntegrationId,
    findPlatformIntegrationContractVersionRecordState,
    findPlatformIntegrationRecoveryQueueRecordStateByDedupKey,
    findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId,
    findPlatformRoleCatalogRecordStateByRoleId,
    findTenantUsershipStateByMembershipId,
    hasOrgReferenceForUser,
    hashPassword,
    invokeFaultInjector,
    isActiveLikeStatus,
    isPlatformIntegrationLifecycleTransitionAllowed,
    isPlatformIntegrationRecoveryFailureRetryable,
    isRetryableDeliveryFailure,
    isSamePlatformPermission,
    isStrictOptionalTenantUserProfileField,
    isTenantUsershipActiveForAuth,
    isValidPlatformIntegrationId,
    listPlatformRolePermissionGrantsForRoleId,
    listTenantRolePermissionGrantsForRoleId,
    listTenantUsershipRoleBindingsForMembershipId,
    membershipsByOrgId,
    mergePlatformPermission,
    mergePlatformPermissionFromRoles,
    nextPlatformIntegrationContractCheckId,
    nextPlatformIntegrationContractVersionId,
    normalizeAuditDomain,
    normalizeAuditOccurredAt,
    normalizeAuditResult,
    normalizeAuditStringOrNull,
    normalizeAuditTraceparentOrNull,
    normalizeDateTimeFilterToEpoch,
    normalizeOptionalPlatformUserProfileField,
    normalizeOptionalTenantUserProfileField,
    normalizeOrgStatus,
    normalizePlatformIntegrationCode,
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
    normalizePlatformPermission,
    normalizePlatformPermissionCode,
    normalizePlatformPermissionCodes,
    normalizePlatformRole,
    normalizePlatformRoleCatalogCode,
    normalizePlatformRoleCatalogRoleId,
    normalizePlatformRoleCatalogScope,
    normalizePlatformRoleCatalogStatus,
    normalizePlatformRoleCatalogTenantId,
    normalizePlatformRoleCatalogTenantIdForScope,
    normalizePlatformRoleStatus,
    normalizeRequiredPlatformUserProfileField,
    normalizeStrictTenantPermissionCodeFromGrantRow,
    normalizeStrictTenantRolePermissionGrantIdentity,
    normalizeStrictTenantUsershipRoleBindingIdentity,
    normalizeStrictTenantUsershipRoleIdFromBindingRow,
    normalizeSystemSensitiveConfigKey,
    normalizeSystemSensitiveConfigStatus,
    normalizeTenantPermissionCode,
    normalizeTenantPermissionCodes,
    normalizeTenantUsershipStatus,
    normalizeTenantUsershipStatusForRead,
    normalizeTraceparent,
    orgIdByName,
    orgsById,
    ownerTransferLocksByOrgId,
    persistAuditEvent,
    platformDomainKnownByUserId,
    platformIntegrationCatalogById,
    platformIntegrationCatalogCodeIndex,
    platformIntegrationContractChecksById,
    platformIntegrationContractVersionsByKey,
    platformIntegrationFreezeById,
    platformIntegrationRecoveryDedupIndex,
    platformIntegrationRecoveryQueueByRecoveryId,
    platformPermissionsByUserId,
    platformProfilesByUserId,
    platformRoleCatalogById,
    platformRoleCatalogCodeIndex,
    platformRolePermissionGrantsByRoleId,
    platformRolesByUserId,
    randomUUID,
    refreshTokensByHash,
    replacePlatformRolePermissionGrantsForRoleId,
    replaceTenantRolePermissionGrantsForRoleId,
    replaceTenantUsershipRoleBindingsForMembershipId,
    repositoryMethods,
    resolveEffectiveTenantPermissionForMembership,
    resolveLatestPlatformProfileByUserId,
    resolveLatestTenantUserProfileByUserId,
    resolveOptionalTenantUserProfileField,
    resolvePlatformIntegrationNetworkErrorCodeFromSnapshot,
    resolvePlatformPermissionFromGrantCodes,
    resolvePlatformUserReadModel,
    resolveTenantPermissionFromGrantCodes,
    restoreAuditEventsFromSnapshot,
    restoreMapFromSnapshot,
    restoreSetFromSnapshot,
    revokePlatformSessionsForUser,
    revokeSessionsForUserByEntryDomain,
    revokeTenantSessionsForUser,
    safeParseJsonValue,
    sanitizeAuditState,
    seedUsers,
    sessionsById,
    syncPlatformPermissionFromRoleFacts,
    syncTenantUsershipPermissionSnapshot,
    systemSensitiveConfigsByKey,
    tenantAccountsByAccountId,
    tenantAccountAssistantsByAccountId,
    tenantAccountIdsByTenantId,
    tenantAccountOperationLogsByAccountId,
    tenantAccountWechatIndexByTenantId,
    tenantRolePermissionGrantsByRoleId,
    tenantUsershipHistoryByPair,
    tenantUsershipRolesByMembershipId,
    tenantsByUserId,
    toAuditEventRecord,
    toOwnerTransferTakeoverRoleId,
    toPlatformIntegrationCatalogRecord,
    toPlatformIntegrationCodeKey,
    toPlatformIntegrationContractCompatibilityCheckRecord,
    toPlatformIntegrationContractScopeKey,
    toPlatformIntegrationContractVersionKey,
    toPlatformIntegrationContractVersionRecord,
    toPlatformIntegrationFreezeRecord,
    toPlatformIntegrationRecoveryDedupKey,
    toPlatformIntegrationRecoveryQueueRecord,
    toPlatformPermissionCodeKey,
    toPlatformPermissionSnapshotFromCodes,
    toPlatformRoleCatalogCodeIndexKey,
    toPlatformRoleCatalogCodeKey,
    toPlatformRoleCatalogRecord,
    toPlatformRoleCatalogRoleIdKey,
    toTenantPermissionCodeKey,
    toTenantPermissionSnapshotFromCodes,
    toTenantUsershipScopeLabel,
    upsertPlatformIntegrationCatalogRecord,
    upsertPlatformIntegrationContractVersionRecord,
    upsertPlatformIntegrationFreezeRecord,
    upsertPlatformIntegrationRecoveryQueueRecord,
    upsertPlatformRoleCatalogRecord,
    usersById,
    usersByPhone
  };

  const sharedMemoryAuthStoreMethods = createSharedMemoryAuthStoreSessionAuditMethodComposition(
    authStoreMethodDependencies
  );
  const platformMemoryAuthStoreMethods = createPlatformMemoryAuthStoreCapabilityComposition(
    authStoreMethodDependencies
  );
  const tenantMemoryAuthStoreMethods = createTenantMemoryAuthStoreCapabilityComposition(
    authStoreMethodDependencies
  );

  return {
    ...sharedMemoryAuthStoreMethods,
    ...platformMemoryAuthStoreMethods,
    ...tenantMemoryAuthStoreMethods
  };
};

module.exports = { createInMemoryAuthStore };

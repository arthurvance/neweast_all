'use strict';

const { randomUUID } = require('node:crypto');
const {
  listSupportedPlatformPermissionCodes,
  listPlatformPermissionCatalogItems
} = require('../../../../modules/auth/permission-catalog');
const {
  errors,
  AuthProblemError,
  assertStoreMethod,
  isPlainObject,
  hasOwnProperty,
  normalizePhone,
  normalizeOrgStatus,
  isUserActive,
  maskPhone,
  toOwnerTransferTakeoverRoleId,
  normalizeAuditStringOrNull,
  normalizeAuditRequestIdOrNull,
  normalizeSystemSensitiveConfigKey,
  normalizeSystemSensitiveConfigStatus,
  normalizeStrictRequiredStringField,
  normalizeRequiredStringField,
  normalizeTenantId,
  normalizeEntryDomain,
  normalizePlatformRoleIdKey,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogTenantIdForScope,
  normalizePlatformPermissionCode,
  resolveRawRoleIdCandidate,
  resolveRawCamelSnakeField,
  isDuplicateRoleFactEntryError,
  isDataTooLongRoleFactError,
  toPlatformPermissionSnapshotFromCodes,
  toPlatformPermissionCodeKey,
  toSystemSensitiveConfigRecord,
  isPlatformPermissionCode,
  assertOptionalBooleanRolePermission,
  hasTopLevelPlatformRolePermissionField,
  parseProvisionPayload,
  VALID_ORG_STATUS,
  VALID_PLATFORM_USER_STATUS,
  VALID_PLATFORM_ROLE_CATALOG_STATUS,
  VALID_PLATFORM_ROLE_CATALOG_SCOPE,
  VALID_PLATFORM_ROLE_FACT_STATUS,
  PLATFORM_ROLE_CATALOG_SCOPE,
  SUPPORTED_PLATFORM_PERMISSION_CODE_SET,
  REJECTED_SYSTEM_CONFIG_AUDIT_EVENT_TYPES,
  DEFAULT_PASSWORD_CONFIG_KEY,
  SUPPORTED_SYSTEM_SENSITIVE_CONFIG_KEYS,
  MAX_OWNER_TRANSFER_ORG_ID_LENGTH,
  MAX_OWNER_TRANSFER_REASON_LENGTH,
  MAX_PLATFORM_USER_ID_LENGTH,
  MAX_PLATFORM_ROLE_ID_LENGTH,
  MAX_PLATFORM_ROLE_FACTS_PER_USER,
  MAX_ROLE_PERMISSION_CODES_PER_REQUEST,
  MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  OWNER_TRANSFER_TAKEOVER_ROLE_CODE,
  OWNER_TRANSFER_TAKEOVER_ROLE_NAME,
  OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES,
  PLATFORM_ROLE_ASSIGNMENT_ALLOWED_FIELDS,
  PLATFORM_ROLE_FACTS_REPLACE_PERMISSION_CODE,
  PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
  CONTROL_CHAR_PATTERN,
  WHITESPACE_PATTERN
} = require('../../../../shared-kernel/auth/create-auth-service.helpers');
const {
  createPlatformSessionOptionsCapabilities
} = require('../context/platform-session-options.service');
const {
  createPlatformRoleFactsGovernanceCapabilities
} = require('./platform-role-facts-governance.service');
const {
  createPlatformOrgOnboardingCapabilities
} = require('./platform-org-onboarding.service');
const {
  createPlatformOwnerTransferGovernanceCapabilities
} = require('./platform-owner-transfer-governance.service');
const {
  createPlatformSystemSensitiveConfigCapabilities
} = require('../system-config/platform-system-sensitive-config.service');
const {
  createPlatformRoleCatalogGovernanceCapabilities
} = require('./platform-role-catalog-governance.service');
const {
  createPlatformRoleCatalogQueryCapabilities
} = require('./platform-role-catalog-query.service');
const {
  createPlatformRolePermissionGrantCapabilities
} = require('./platform-role-permission-grants.service');
const {
  createPlatformGovernanceCapabilities
} = require('./platform-governance.service');
const {
  createPlatformProvisioningOrchestrationCapabilities
} = require('../provisioning/platform-provisioning-orchestration.service');

const createPlatformAuthComposition = ({
  authStore,
  now,
  log,
  ownerTransferLocksByOrgId,
  resolveAuthorizedSession,
  buildSessionContext,
  rejectNoDomainAccess,
  getPlatformPermissionContext,
  resolveLoginUserName,
  loadValidatedPlatformRoleCatalogEntriesForRoleFacts,
  loadPlatformRolePermissionGrantsByRoleIds,
  invalidateSessionCacheByUserId,
  invalidateAllAccessSessionCache,
  getDomainAccessForUser,
  ensureDefaultDomainAccessForUser,
  getOrCreateProvisionUserByPhone,
  authorizeRoute,
  rollbackProvisionedUser,
  bindRequestTraceparent,
  addAuditEvent,
  recordPersistentAuditEvent,
  toDistinctNormalizedUserIds,
  normalizeStoredRoleFactsForPermissionResync,
  cloneRoleFactsSnapshotForRollback,
  normalizeStrictDistinctUserIdsFromPlatformDependency,
  normalizeStrictNonNegativeIntegerFromPlatformDependency,
  resyncRoleStatusAffectedSnapshots
} = {}) => {
  const {
    platformOptions
  } = createPlatformSessionOptionsCapabilities({
    resolveAuthorizedSession,
    buildSessionContext,
    rejectNoDomainAccess,
    getPlatformPermissionContext,
    resolveLoginUserName
  });

  const {
    replacePlatformRolesAndSyncSnapshot
  } = createPlatformRoleFactsGovernanceCapabilities({
    authStore,
    errors,
    isPlainObject,
    hasOwnProperty,
    hasTopLevelPlatformRolePermissionField,
    assertOptionalBooleanRolePermission,
    resolveRawRoleIdCandidate,
    normalizeRequiredStringField,
    normalizePlatformRoleIdKey,
    normalizeAuditStringOrNull,
    resolveRawCamelSnakeField,
    toPlatformPermissionSnapshotFromCodes,
    loadValidatedPlatformRoleCatalogEntriesForRoleFacts,
    loadPlatformRolePermissionGrantsByRoleIds,
    authorizeRoute,
    isDuplicateRoleFactEntryError,
    isDataTooLongRoleFactError,
    addAuditEvent,
    recordPersistentAuditEvent,
    invalidateSessionCacheByUserId,
    VALID_PLATFORM_ROLE_FACT_STATUS,
    PLATFORM_ROLE_ASSIGNMENT_ALLOWED_FIELDS,
    PLATFORM_ROLE_FACTS_REPLACE_PERMISSION_CODE,
    MAX_PLATFORM_ROLE_ID_LENGTH,
    MAX_PLATFORM_ROLE_FACTS_PER_USER
  });

  const {
    createOrganizationWithOwner
  } = createPlatformOrgOnboardingCapabilities({
    authStore,
    errors,
    randomUUID,
    assertStoreMethod,
    isPlainObject,
    resolveRawCamelSnakeField,
    normalizeAuditStringOrNull,
    recordPersistentAuditEvent,
    MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
    CONTROL_CHAR_PATTERN
  });

  const {
    acquireOwnerTransferLock,
    releaseOwnerTransferLock,
    validateOwnerTransferRequest,
    executeOwnerTransferTakeover
  } = createPlatformOwnerTransferGovernanceCapabilities({
    authStore,
    errors,
    AuthProblemError,
    now,
    ownerTransferLocksByOrgId,
    assertStoreMethod,
    normalizePhone,
    normalizeOrgStatus,
    isUserActive,
    maskPhone,
    toOwnerTransferTakeoverRoleId,
    normalizeAuditStringOrNull,
    invalidateSessionCacheByUserId,
    addAuditEvent,
    recordPersistentAuditEvent,
    MAX_OWNER_TRANSFER_ORG_ID_LENGTH,
    MAX_OWNER_TRANSFER_REASON_LENGTH,
    OWNER_TRANSFER_TAKEOVER_ROLE_CODE,
    OWNER_TRANSFER_TAKEOVER_ROLE_NAME,
    OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES,
    CONTROL_CHAR_PATTERN,
    WHITESPACE_PATTERN
  });

  const {
    recordSystemSensitiveConfigAuditEvent,
    getSystemSensitiveConfig,
    upsertSystemSensitiveConfig
  } = createPlatformSystemSensitiveConfigCapabilities({
    authStore,
    errors,
    assertStoreMethod,
    bindRequestTraceparent,
    normalizeAuditRequestIdOrNull,
    normalizeSystemSensitiveConfigKey,
    normalizeSystemSensitiveConfigStatus,
    normalizeStrictRequiredStringField,
    toSystemSensitiveConfigRecord,
    addAuditEvent,
    recordPersistentAuditEvent,
    DEFAULT_PASSWORD_CONFIG_KEY,
    SUPPORTED_SYSTEM_SENSITIVE_CONFIG_KEYS,
    REJECTED_SYSTEM_CONFIG_AUDIT_EVENT_TYPES,
    CONTROL_CHAR_PATTERN
  });

  const listPlatformPermissionCatalog = () =>
    listSupportedPlatformPermissionCodes();

  const listPlatformPermissionCatalogEntries = () =>
    listPlatformPermissionCatalogItems();

  const {
    createPlatformRoleCatalogEntry,
    updatePlatformRoleCatalogEntry,
    deletePlatformRoleCatalogEntry
  } = createPlatformRoleCatalogGovernanceCapabilities({
    authStore,
    errors,
    isPlainObject,
    assertStoreMethod,
    normalizeRequiredStringField,
    normalizePlatformRoleCatalogStatus,
    normalizePlatformRoleCatalogScope,
    normalizePlatformRoleCatalogTenantIdForScope,
    normalizeAuditStringOrNull,
    resolveRawCamelSnakeField,
    recordPersistentAuditEvent,
    resyncRoleStatusAffectedSnapshots,
    VALID_PLATFORM_ROLE_CATALOG_STATUS,
    VALID_PLATFORM_ROLE_CATALOG_SCOPE,
    PLATFORM_ROLE_CATALOG_SCOPE
  });

  const {
    listPlatformRoleCatalogEntries,
    findPlatformRoleCatalogEntryByRoleId
  } = createPlatformRoleCatalogQueryCapabilities({
    authStore,
    errors,
    assertStoreMethod,
    normalizeRequiredStringField,
    normalizePlatformRoleCatalogScope,
    normalizePlatformRoleCatalogTenantIdForScope,
    VALID_PLATFORM_ROLE_CATALOG_SCOPE,
    PLATFORM_ROLE_CATALOG_SCOPE
  });

  const {
    listPlatformRolePermissionGrants,
    replacePlatformRolePermissionGrants
  } = createPlatformRolePermissionGrantCapabilities({
    authStore,
    errors,
    AuthProblemError,
    hasOwnProperty,
    normalizeRequiredStringField,
    normalizeStrictRequiredStringField,
    normalizePlatformRoleIdKey,
    loadValidatedPlatformRoleCatalogEntriesForRoleFacts,
    loadPlatformRolePermissionGrantsByRoleIds,
    listSupportedPlatformPermissionCodes,
    listPlatformPermissionCatalogItems,
    normalizePlatformPermissionCode,
    toPlatformPermissionCodeKey,
    isPlatformPermissionCode,
    SUPPORTED_PLATFORM_PERMISSION_CODE_SET,
    CONTROL_CHAR_PATTERN,
    MAX_ROLE_PERMISSION_CODES_PER_REQUEST,
    MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS,
    resolveRawCamelSnakeField,
    normalizeStrictDistinctUserIdsFromPlatformDependency,
    normalizeStrictNonNegativeIntegerFromPlatformDependency,
    toDistinctNormalizedUserIds,
    invalidateSessionCacheByUserId,
    normalizeStoredRoleFactsForPermissionResync,
    cloneRoleFactsSnapshotForRollback,
    toPlatformPermissionSnapshotFromCodes,
    recordPersistentAuditEvent,
    normalizeAuditStringOrNull,
    addAuditEvent
  });

  const {
    updateOrganizationStatus,
    updatePlatformUserStatus,
    softDeleteUser
  } = createPlatformGovernanceCapabilities({
    authStore,
    errors,
    hasOwnProperty,
    assertStoreMethod,
    normalizeOrgStatus,
    normalizeAuditStringOrNull,
    normalizeStrictRequiredStringField,
    normalizeStrictNonNegativeIntegerFromPlatformDependency,
    resolveRawCamelSnakeField,
    invalidateAllAccessSessionCache,
    invalidateSessionCacheByUserId,
    addAuditEvent,
    recordPersistentAuditEvent,
    MAX_PLATFORM_USER_ID_LENGTH,
    VALID_ORG_STATUS,
    VALID_PLATFORM_USER_STATUS
  });

  const {
    provisionPlatformUserByPhone
  } = createPlatformProvisioningOrchestrationCapabilities({
    errors,
    AuthProblemError,
    log,
    normalizeTenantId,
    normalizeEntryDomain,
    getDomainAccessForUser,
    ensureDefaultDomainAccessForUser,
    getOrCreateProvisionUserByPhone,
    authorizeRoute,
    parseProvisionPayload,
    normalizePhone,
    rollbackProvisionedUser,
    addAuditEvent,
    maskPhone,
    PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE
  });

  return {
    platformOptions,
    replacePlatformRolesAndSyncSnapshot,
    createOrganizationWithOwner,
    acquireOwnerTransferLock,
    releaseOwnerTransferLock,
    validateOwnerTransferRequest,
    executeOwnerTransferTakeover,
    recordSystemSensitiveConfigAuditEvent,
    getSystemSensitiveConfig,
    upsertSystemSensitiveConfig,
    listPlatformPermissionCatalog,
    listPlatformPermissionCatalogEntries,
    createPlatformRoleCatalogEntry,
    updatePlatformRoleCatalogEntry,
    deletePlatformRoleCatalogEntry,
    listPlatformRoleCatalogEntries,
    findPlatformRoleCatalogEntryByRoleId,
    listPlatformRolePermissionGrants,
    replacePlatformRolePermissionGrants,
    updateOrganizationStatus,
    updatePlatformUserStatus,
    softDeleteUser,
    provisionPlatformUserByPhone
  };
};

module.exports = {
  createPlatformAuthComposition
};

'use strict';

const {
  createPlatformRoleStatusResyncCapabilities
} = require('../../../domains/platform/auth/governance/platform-role-status-resync.service');
const {
  createTenantRoleStatusResyncCapabilities
} = require('../../../domains/tenant/auth/governance/tenant-role-status-resync.service');
const {
  createSharedAuthRoleStatusResyncOrchestration
} = require('./shared-auth-role-status-resync-orchestration.service');
const {
  errors,
  AuthProblemError,
  hasOwnProperty,
  normalizeRequiredStringField,
  resolveRawRoleIdCandidate,
  normalizePlatformRoleIdKey,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogScope,
  normalizeTenantId,
  resolveRawCamelSnakeField,
  normalizeStrictAddressableTenantRoleIdFromInput,
  toPlatformPermissionSnapshotFromCodes,
  VALID_PLATFORM_ROLE_FACT_STATUS,
  VALID_PLATFORM_ROLE_CATALOG_SCOPE,
  PLATFORM_ROLE_CATALOG_SCOPE,
  TENANT_ROLE_SCOPE,
  MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS,
  CONTROL_CHAR_PATTERN,
  normalizeAuditStringOrNull
} = require('../create-auth-service.helpers');

const createSharedAuthRoleStatusResyncComposition = ({
  authStore,
  loadPlatformRolePermissionGrantsByRoleIds,
  loadTenantRolePermissionGrantsByRoleIds,
  invalidateSessionCacheByUserId,
  addAuditEvent,
  recordPersistentAuditEvent
} = {}) => {
  const {
    toDistinctNormalizedUserIds,
    normalizeStrictDistinctUserIdsFromPlatformDependency,
    normalizeStrictNonNegativeIntegerFromPlatformDependency,
    normalizeStoredRoleFactsForPermissionResync,
    cloneRoleFactsSnapshotForRollback,
    normalizeRoleCatalogStatusForResync,
    resyncPlatformRoleStatusAffectedSnapshots
  } = createPlatformRoleStatusResyncCapabilities({
    authStore,
    errors,
    AuthProblemError,
    normalizeRequiredStringField,
    resolveRawRoleIdCandidate,
    normalizePlatformRoleIdKey,
    normalizePlatformRoleCatalogStatus,
    normalizePlatformRoleCatalogScope,
    normalizeTenantId,
    resolveRawCamelSnakeField,
    loadPlatformRolePermissionGrantsByRoleIds,
    invalidateSessionCacheByUserId,
    toPlatformPermissionSnapshotFromCodes,
    addAuditEvent,
    VALID_PLATFORM_ROLE_FACT_STATUS,
    PLATFORM_ROLE_CATALOG_SCOPE,
    CONTROL_CHAR_PATTERN
  });

  const {
    normalizeStrictDistinctUserIdsFromDependency,
    normalizeStrictNonNegativeIntegerFromDependency,
    resyncTenantRoleStatusAffectedSnapshots
  } = createTenantRoleStatusResyncCapabilities({
    authStore,
    errors,
    AuthProblemError,
    hasOwnProperty,
    resolveRawCamelSnakeField,
    normalizeTenantId,
    normalizeStrictAddressableTenantRoleIdFromInput,
    normalizePlatformRoleIdKey,
    loadTenantRolePermissionGrantsByRoleIds,
    invalidateSessionCacheByUserId,
    addAuditEvent,
    TENANT_ROLE_SCOPE,
    MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS,
    CONTROL_CHAR_PATTERN
  });

  const {
    resyncRoleStatusAffectedSnapshots
  } = createSharedAuthRoleStatusResyncOrchestration({
    errors,
    normalizePlatformRoleCatalogScope,
    VALID_PLATFORM_ROLE_CATALOG_SCOPE,
    normalizeRequiredStringField,
    TENANT_ROLE_SCOPE,
    normalizeTenantId,
    resyncTenantRoleStatusAffectedSnapshots,
    resyncPlatformRoleStatusAffectedSnapshots,
    recordPersistentAuditEvent,
    normalizeAuditStringOrNull,
    normalizeRoleCatalogStatusForResync,
    PLATFORM_ROLE_CATALOG_SCOPE
  });

  return {
    toDistinctNormalizedUserIds,
    normalizeStrictDistinctUserIdsFromPlatformDependency,
    normalizeStrictNonNegativeIntegerFromPlatformDependency,
    normalizeStoredRoleFactsForPermissionResync,
    cloneRoleFactsSnapshotForRollback,
    normalizeStrictDistinctUserIdsFromDependency,
    normalizeStrictNonNegativeIntegerFromDependency,
    resyncRoleStatusAffectedSnapshots
  };
};

module.exports = {
  createSharedAuthRoleStatusResyncComposition
};

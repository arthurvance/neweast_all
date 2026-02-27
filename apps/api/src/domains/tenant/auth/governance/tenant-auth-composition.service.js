'use strict';

const {
  listSupportedTenantPermissionCodes,
  listTenantPermissionCatalogItems
} = require('../../../../modules/auth/permission-catalog');
const {
  errors,
  AuthProblemError,
  hasOwnProperty,
  assertStoreMethod,
  normalizeTenantId,
  normalizePhone,
  normalizeEntryDomain,
  normalizeRequiredStringField,
  normalizeStrictAddressableTenantRoleIdFromInput,
  normalizeStrictRequiredStringField,
  normalizeStrictTenantUsershipIdFromInput,
  normalizeTenantUsershipRecordFromStore,
  normalizeMemberListInteger,
  normalizeTenantUsershipStatus,
  normalizePlatformRoleCatalogTenantIdForScope,
  normalizePlatformRoleIdKey,
  normalizeTenantPermissionCode,
  normalizeAuditStringOrNull,
  resolveRawCamelSnakeField,
  parseOptionalTenantName,
  parseProvisionPayload,
  isDataTooLongRoleFactError,
  isTenantPermissionCode,
  isValidTenantUsershipId,
  toTenantPermissionCodeKey,
  TENANT_ROLE_SCOPE,
  TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
  UNSET_EXPECTED_TENANT_USER_PROFILE_FIELD,
  SUPPORTED_TENANT_PERMISSION_CODE_SET,
  MAX_ROLE_PERMISSION_CODES_PER_REQUEST,
  MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS,
  MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS,
  MAX_PLATFORM_ROLE_ID_LENGTH,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
  MAX_OWNER_TRANSFER_REASON_LENGTH,
  CONTROL_CHAR_PATTERN,
  ROLE_ID_ADDRESSABLE_PATTERN
} = require('../../../../shared-kernel/auth/create-auth-service.helpers');

const {
  createTenantSessionNavigationCapabilities
} = require('../context/tenant-session-navigation.service');
const {
  createTenantRolePermissionGrantCapabilities
} = require('./tenant-role-permission-grants.service');
const {
  createTenantRoleBindingCapabilities
} = require('./tenant-role-bindings.service');
const {
  createTenantProvisioningOrchestrationCapabilities
} = require('../provisioning/tenant-provisioning-orchestration.service');
const {
  createTenantUsershipGovernanceCapabilities
} = require('./tenant-usership-governance.service');

const createTenantAuthComposition = ({
  authStore,
  log,
  loadValidatedTenantRoleCatalogEntries,
  loadTenantRolePermissionGrantsByRoleIds,
  normalizeStrictDistinctUserIdsFromDependency,
  normalizeStrictNonNegativeIntegerFromDependency,
  resolveAuthorizedSession,
  buildSessionContext,
  rejectNoDomainAccess,
  getTenantOptionsForUser,
  reconcileTenantSessionContext,
  getTenantPermissionContext,
  resolveLoginUserName,
  assertDomainAccess,
  sessionRepository,
  invalidateSessionCacheBySessionId,
  invalidateSessionCacheByUserId,
  getDomainAccessForUser,
  ensureTenantDomainAccessForUser,
  getOrCreateProvisionUserByPhone,
  authorizeRoute,
  rollbackProvisionedUser,
  addAuditEvent,
  recordPersistentAuditEvent,
  maskPhone
} = {}) => {
  const {
    tenantOptions,
    switchTenant
  } = createTenantSessionNavigationCapabilities({
    errors,
    normalizeTenantId,
    resolveAuthorizedSession,
    buildSessionContext,
    rejectNoDomainAccess,
    getTenantOptionsForUser,
    reconcileTenantSessionContext,
    getTenantPermissionContext,
    resolveLoginUserName,
    assertDomainAccess,
    addAuditEvent,
    sessionRepository,
    invalidateSessionCacheBySessionId
  });

  const listTenantPermissionCatalog = () =>
    listSupportedTenantPermissionCodes();

  const listTenantPermissionCatalogEntries = (options = {}) =>
    listTenantPermissionCatalogItems(options);

  const {
    listTenantRolePermissionGrants,
    replaceTenantRolePermissionGrants
  } = createTenantRolePermissionGrantCapabilities({
    authStore,
    errors,
    AuthProblemError,
    hasOwnProperty,
    normalizeStrictAddressableTenantRoleIdFromInput,
    loadValidatedTenantRoleCatalogEntries,
    loadTenantRolePermissionGrantsByRoleIds,
    normalizePlatformRoleIdKey,
    listSupportedTenantPermissionCodes,
    listTenantPermissionCatalogItems,
    normalizeTenantPermissionCode,
    toTenantPermissionCodeKey,
    isTenantPermissionCode,
    SUPPORTED_TENANT_PERMISSION_CODE_SET,
    CONTROL_CHAR_PATTERN,
    MAX_ROLE_PERMISSION_CODES_PER_REQUEST,
    MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS,
    normalizeTenantId,
    normalizeAuditStringOrNull,
    normalizeStrictRequiredStringField,
    resolveRawCamelSnakeField,
    normalizeStrictDistinctUserIdsFromDependency,
    normalizeStrictNonNegativeIntegerFromDependency,
    invalidateSessionCacheByUserId,
    addAuditEvent,
    recordPersistentAuditEvent
  });

  const {
    listTenantUserRoleBindings,
    replaceTenantUserRoleBindings
  } = createTenantRoleBindingCapabilities({
    authStore,
    errors,
    AuthProblemError,
    hasOwnProperty,
    assertStoreMethod,
    normalizeRequiredStringField,
    normalizeStrictRequiredStringField,
    normalizeStrictTenantUsershipIdFromInput,
    normalizeTenantUsershipRecordFromStore,
    normalizeTenantUsershipStatus,
    normalizePlatformRoleCatalogTenantIdForScope,
    normalizeAuditStringOrNull,
    resolveRawCamelSnakeField,
    loadValidatedTenantRoleCatalogEntries,
    normalizeStrictDistinctUserIdsFromDependency,
    normalizeStrictNonNegativeIntegerFromDependency,
    invalidateSessionCacheByUserId,
    addAuditEvent,
    recordPersistentAuditEvent,
    MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS,
    MAX_PLATFORM_ROLE_ID_LENGTH,
    CONTROL_CHAR_PATTERN,
    ROLE_ID_ADDRESSABLE_PATTERN
  });

  const {
    provisionTenantUserByPhone
  } = createTenantProvisioningOrchestrationCapabilities({
    authStore,
    errors,
    AuthProblemError,
    log,
    assertStoreMethod,
    normalizeTenantId,
    normalizeEntryDomain,
    ensureTenantDomainAccessForUser,
    getDomainAccessForUser,
    getTenantOptionsForUser,
    getOrCreateProvisionUserByPhone,
    authorizeRoute,
    parseProvisionPayload,
    normalizePhone,
    parseOptionalTenantName,
    isDataTooLongRoleFactError,
    rollbackProvisionedUser,
    addAuditEvent,
    maskPhone,
    TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE
  });

  const {
    findTenantUsershipByUserAndTenantId,
    listTenantUsers,
    findTenantUsershipByMembershipIdAndTenantId,
    updateTenantUserProfile,
    updateTenantUserStatus
  } = createTenantUsershipGovernanceCapabilities({
    authStore,
    errors,
    hasOwnProperty,
    assertStoreMethod,
    normalizeTenantId,
    normalizeStrictTenantUsershipIdFromInput,
    normalizeTenantUsershipRecordFromStore,
    normalizeMemberListInteger,
    resolveRawCamelSnakeField,
    normalizeStrictRequiredStringField,
    normalizeEntryDomain,
    normalizeTenantUsershipStatus,
    isValidTenantUsershipId,
    normalizeAuditStringOrNull,
    authorizeRoute,
    addAuditEvent,
    recordPersistentAuditEvent,
    invalidateSessionCacheByUserId,
    TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
    UNSET_EXPECTED_TENANT_USER_PROFILE_FIELD,
    MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
    MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
    MAX_OWNER_TRANSFER_REASON_LENGTH,
    CONTROL_CHAR_PATTERN
  });

  return {
    tenantOptions,
    switchTenant,
    listTenantRolePermissionGrants,
    replaceTenantRolePermissionGrants,
    listTenantPermissionCatalog,
    listTenantPermissionCatalogEntries,
    listTenantUserRoleBindings,
    replaceTenantUserRoleBindings,
    provisionTenantUserByPhone,
    findTenantUsershipByUserAndTenantId,
    listTenantUsers,
    findTenantUsershipByMembershipIdAndTenantId,
    updateTenantUserProfile,
    updateTenantUserStatus
  };
};

module.exports = {
  createTenantAuthComposition
};

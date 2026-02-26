const { createDecipheriv, pbkdf2Sync, randomBytes, randomUUID, randomInt, timingSafeEqual, createSign, createVerify } = require('node:crypto');
const { log } = require('../../common/logger');
const { normalizeTraceparent } = require('../../common/trace-context');
const { createInMemoryAuthStore } = require('./store/create-in-memory-auth-store');
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
} = require('../../modules/auth/permission-catalog');
const { createAuthSessionService } = require('../../modules/auth/session-service');
const { createTenantContextService } = require('../../modules/auth/tenant-context-service');
const { createPermissionContextBuilder } = require('../../modules/auth/permission-context-builder');
const { createEntryPolicyService } = require('../../modules/auth/entry-policy-service');
const { createAuthRepositories } = require('../../modules/auth/repositories');
const {
  createPlatformRoleCatalogDependencyCapabilities
} = require('../../domains/platform/auth/governance/platform-role-catalog-dependency.service');
const {
  createTenantRoleCatalogDependencyCapabilities
} = require('../../domains/tenant/auth/governance/tenant-role-catalog-dependency.service');
const {
  createSharedAuthUserIdentityBootstrapCapabilities
} = require('./capabilities/shared-auth-user-identity-bootstrap.service');
const {
  createSharedAuthProvisioningRecoveryCapabilities
} = require('./capabilities/shared-auth-provisioning-recovery.service');
const {
  createSharedAuthAuditObservabilityCapabilities
} = require('./capabilities/shared-auth-audit-observability.service');
const {
  createSharedAuthRuntimeBootstrap
} = require('./capabilities/shared-auth-runtime-bootstrap.service');
const {
  createSharedAuthLoginUserNameCapabilities
} = require('./capabilities/shared-auth-login-user-name.service');
const {
  createSharedAuthSessionFlowComposition
} = require('./capabilities/shared-auth-session-flow-composition.service');
const {
  createPlatformAuthComposition
} = require('../../domains/platform/auth/governance/platform-auth-composition.service');
const {
  createTenantAuthComposition
} = require('../../domains/tenant/auth/governance/tenant-auth-composition.service');
const {
  createSharedAuthRoleStatusResyncComposition
} = require('./capabilities/shared-auth-role-status-resync-composition.service');
const {
  createSharedAuthServiceFacade
} = require('./capabilities/shared-auth-service-facade-composition.service');
const { ACCESS_SESSION_CACHE_TTL_MS, AUDIT_EVENT_ALLOWED_DOMAINS, AUDIT_EVENT_ALLOWED_RESULTS, AUDIT_EVENT_REDACTION_KEY_PATTERN, CONTROL_CHAR_PATTERN, DEFAULT_PASSWORD_CONFIG_KEY, DEFAULT_SEED_USERS, MAX_AUDIT_QUERY_PAGE_SIZE, MAX_AUTH_AUDIT_TRAIL_ENTRIES, MAX_ORG_STATUS_CASCADE_COUNT, MAX_OWNER_TRANSFER_ORG_ID_LENGTH, MAX_OWNER_TRANSFER_REASON_LENGTH, MAX_PLATFORM_ROLE_FACTS_PER_USER, MAX_PLATFORM_ROLE_ID_LENGTH, MAX_PLATFORM_USER_ID_LENGTH, MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS, MAX_ROLE_PERMISSION_CODES_PER_REQUEST, MAX_TENANT_MEMBERSHIP_ID_LENGTH, MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS, MAX_TENANT_NAME_LENGTH, MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH, MAX_TENANT_USER_DISPLAY_NAME_LENGTH, MYSQL_DATA_TOO_LONG_ERRNO, MYSQL_DUP_ENTRY_ERRNO, OTP_CODE_LENGTH, OTP_RESEND_COOLDOWN_SECONDS, OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES, OWNER_TRANSFER_TAKEOVER_ROLE_CODE, OWNER_TRANSFER_TAKEOVER_ROLE_ID_DIGEST_LENGTH, OWNER_TRANSFER_TAKEOVER_ROLE_ID_PREFIX, OWNER_TRANSFER_TAKEOVER_ROLE_NAME, PASSWORD_MIN_LENGTH, PBKDF2_DIGEST, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PLATFORM_ROLE_ASSIGNMENT_ALLOWED_FIELDS, PLATFORM_ROLE_CATALOG_SCOPE, PLATFORM_ROLE_FACTS_REPLACE_PERMISSION_CODE, PLATFORM_ROLE_PERMISSION_FIELD_KEYS, REJECTED_SYSTEM_CONFIG_AUDIT_EVENT_TYPES, ROLE_ID_ADDRESSABLE_PATTERN, SENSITIVE_CONFIG_ENVELOPE_VERSION, SENSITIVE_CONFIG_KEY_DERIVATION_ITERATIONS, SENSITIVE_CONFIG_KEY_DERIVATION_SALT, SUPPORTED_PLATFORM_PERMISSION_CODE_SET, SUPPORTED_SYSTEM_SENSITIVE_CONFIG_KEYS, SUPPORTED_TENANT_PERMISSION_CODE_SET, TENANT_MEMBERSHIP_ID_PATTERN, TENANT_ROLE_SCOPE, UNSET_EXPECTED_TENANT_USER_PROFILE_FIELD, VALID_ORG_STATUS, VALID_PLATFORM_ROLE_CATALOG_SCOPE, VALID_PLATFORM_ROLE_CATALOG_STATUS, VALID_PLATFORM_ROLE_FACT_STATUS, VALID_PLATFORM_USER_STATUS, VALID_SYSTEM_SENSITIVE_CONFIG_STATUS, WHITESPACE_PATTERN, AuthProblemError, assertOptionalBooleanRolePermission, assertOtpStoreContract, assertStoreMethod, authError, createInMemoryOtpStore, createInMemoryRateLimitStore, createJwtError, decryptSensitiveConfigValue, deriveLegacySensitiveConfigKey, derivePrimarySensitiveConfigKey, deriveSensitiveConfigKeys, errors, fromBase64Url, hasOwnProperty, hasTopLevelPlatformRolePermissionField, hashPassword, isDataTooLongRoleFactError, isDuplicateRoleFactEntryError, isMissingPlatformRoleCatalogTableError, isMissingTableError, isPlainObject, isPlatformPermissionCode, isTenantPermissionCode, isUserActive, isValidTenantUsershipId, maskPhone, normalizeAuditDomain, normalizeAuditOccurredAt, normalizeAuditResult, normalizeAuditStringOrNull, normalizeAuditTraceparentOrNull, normalizeEntryDomain, normalizeMemberListInteger, normalizeOrgStatus, normalizePhone, normalizePlatformPermissionCode, normalizePlatformRoleCatalogScope, normalizePlatformRoleCatalogStatus, normalizePlatformRoleCatalogTenantIdForScope, normalizePlatformRoleIdKey, normalizeRequiredStringField, normalizeStrictAddressableTenantRoleIdFromInput, normalizeStrictRequiredStringField, normalizeStrictTenantUsershipIdFromInput, normalizeSystemSensitiveConfigKey, normalizeSystemSensitiveConfigStatus, normalizeTenantId, normalizeTenantPermissionCode, normalizeTenantUsershipRecordFromStore, normalizeTenantUsershipStatus, parseAuditQueryTimestamp, parseOptionalTenantName, parseOptionalTenantUserProfileField, parseProvisionPayload, resolveProvisioningConfigFailureReason, resolveRawCamelSnakeField, resolveRawRoleIdCandidate, sanitizeAuditState, signJwt, toBase64Url, toOwnerTransferTakeoverRoleId, toPlatformPermissionCodeKey, toSystemSensitiveConfigRecord, toTenantPermissionCodeKey, tokenHash, verifyJwt, verifyPassword } = require('./create-auth-service.helpers');

const ACCESS_TTL_SECONDS = 15 * 60;
const REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60;
const OTP_TTL_SECONDS = 15 * 60;
const RATE_LIMIT_WINDOW_SECONDS = 60;
const RATE_LIMIT_MAX_ATTEMPTS = 10;

const createAuthService = (options = {}) => {
  const {
    now,
    authStore,
    otpStore,
    rateLimitStore,
    accessSessionCache,
    accessSessionCacheTtlMs,
    sensitiveConfigProvider,
    sensitiveConfigDecryptionKey,
    sensitiveConfigDecryptionKeys,
    jwtKeyPair,
    ownerTransferLocksByOrgId
  } = createSharedAuthRuntimeBootstrap({
    options
  });

  const {
    userRepository,
    sessionRepository,
    domainAccessRepository,
    tenantUsershipRepository,
    permissionRepository
  } = createAuthRepositories({ authStore });

  const {
    auditTrail,
    normalizeAuditRequestIdOrNull,
    bindRequestTraceparent,
    addAuditEvent,
    recordPersistentAuditEvent,
    listAuditEvents,
    recordIdempotencyEvent,
    addAccessInvalidAuditEvent
  } = createSharedAuthAuditObservabilityCapabilities({
    now,
    authStore,
    errors,
    log,
    normalizeAuditStringOrNull,
    normalizeAuditTraceparentOrNull,
    normalizeAuditDomain,
    normalizeAuditResult,
    sanitizeAuditState,
    parseAuditQueryTimestamp,
    MAX_AUTH_AUDIT_TRAIL_ENTRIES,
    MAX_AUDIT_QUERY_PAGE_SIZE
  });

  const {
    invalidateSessionCacheBySessionId,
    invalidateSessionCacheByUserId,
    invalidateAllAccessSessionCache,
    buildSessionContext,
    issueAccessToken,
    issueRefreshToken,
    createSessionAndIssueLoginTokens,
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
    tenantUsershipRepository,
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

  const {
    resolveLoginUserName
  } = createSharedAuthLoginUserNameCapabilities({
    userRepository,
    authStore,
    normalizeTenantId,
    normalizeTenantUsershipRecordFromStore,
    normalizeAuditStringOrNull
  });

  const reconcileTenantSessionContext = (params = {}) =>
    tenantContextService.reconcileTenantSessionContext({
      ...params,
      rejectNoDomainAccess
    });

  const sharedSessionFlowCapabilities = createSharedAuthSessionFlowComposition({
    now,
    errors,
    authStore,
    userRepository,
    otpStore,
    rateLimitStore,
    bindRequestTraceparent,
    addAuditEvent,
    maskPhone,
    normalizePhone,
    randomInt,
    isUserActive,
    normalizeEntryDomain,
    resolveAuthorizedSession,
    verifyPassword,
    normalizeAuditStringOrNull,
    normalizeAuditDomain,
    recordPersistentAuditEvent,
    hashPassword,
    invalidateSessionCacheByUserId,
    createSessionAndIssueLoginTokens,
    shouldProvisionDefaultPlatformDomainAccess,
    ensureDefaultDomainAccessForUser,
    ensureTenantDomainAccessForUser,
    assertDomainAccess,
    getTenantOptionsForUser,
    getTenantPermissionContext,
    getPlatformPermissionContext,
    resolveLoginUserName,
    verifyJwt,
    jwtKeyPair,
    tokenHash,
    normalizeOrgStatus,
    invalidateSessionCacheBySessionId,
    randomUUID,
    issueAccessToken,
    issueRefreshToken,
    buildSessionContext,
    reconcileTenantSessionContext,
    normalizeTenantId,
    resolveSystemConfigPermissionGrant,
    ROUTE_PERMISSION_EVALUATORS,
    TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT,
    toPlatformPermissionCodeKey,
    ROLE_MANAGEMENT_PERMISSION_CODE_KEY_SET,
    OTP_CODE_LENGTH,
    OTP_RESEND_COOLDOWN_SECONDS,
    PASSWORD_MIN_LENGTH,
    OTP_TTL_SECONDS,
    RATE_LIMIT_WINDOW_SECONDS,
    RATE_LIMIT_MAX_ATTEMPTS,
    ACCESS_TTL_SECONDS,
    REFRESH_TTL_SECONDS
  });
  const {
    validatePasswordPolicy,
    authorizeRoute
  } = sharedSessionFlowCapabilities;

  const {
    loadValidatedPlatformRoleCatalogEntriesForRoleFacts,
    loadPlatformRolePermissionGrantsByRoleIds
  } = createPlatformRoleCatalogDependencyCapabilities({
    authStore,
    errors,
    isMissingPlatformRoleCatalogTableError,
    resolveRawRoleIdCandidate,
    normalizeRequiredStringField,
    normalizePlatformRoleIdKey,
    normalizePlatformRoleCatalogStatus,
    normalizePlatformRoleCatalogScope,
    normalizeStrictRequiredStringField,
    resolveRawCamelSnakeField,
    toPlatformPermissionCodeKey,
    isPlatformPermissionCode,
    VALID_PLATFORM_ROLE_CATALOG_STATUS,
    PLATFORM_ROLE_CATALOG_SCOPE,
    SUPPORTED_PLATFORM_PERMISSION_CODE_SET,
    CONTROL_CHAR_PATTERN,
    ROLE_ID_ADDRESSABLE_PATTERN
  });

  const {
    loadValidatedTenantRoleCatalogEntries,
    loadTenantRolePermissionGrantsByRoleIds
  } = createTenantRoleCatalogDependencyCapabilities({
    authStore,
    errors,
    AuthProblemError,
    normalizePlatformRoleCatalogTenantIdForScope,
    normalizeRequiredStringField,
    normalizePlatformRoleIdKey,
    resolveRawCamelSnakeField,
    normalizeStrictRequiredStringField,
    toTenantPermissionCodeKey,
    isTenantPermissionCode,
    VALID_PLATFORM_ROLE_CATALOG_STATUS,
    VALID_PLATFORM_ROLE_CATALOG_SCOPE,
    SUPPORTED_TENANT_PERMISSION_CODE_SET,
    CONTROL_CHAR_PATTERN,
    ROLE_ID_ADDRESSABLE_PATTERN
  });

  const {
    getOrCreateProvisionUserByPhone,
    getOrCreateUserIdentityByPhone
  } = createSharedAuthUserIdentityBootstrapCapabilities({
    authStore,
    errors,
    sensitiveConfigProvider,
    sensitiveConfigDecryptionKeys,
    sensitiveConfigDecryptionKey,
    DEFAULT_PASSWORD_CONFIG_KEY,
    decryptSensitiveConfigValue,
    validatePasswordPolicy,
    resolveProvisioningConfigFailureReason,
    addAuditEvent,
    hashPassword,
    assertStoreMethod,
    isDataTooLongRoleFactError,
    normalizePhone,
    maskPhone
  });

  const {
    toDistinctNormalizedUserIds,
    normalizeStrictDistinctUserIdsFromPlatformDependency,
    normalizeStrictNonNegativeIntegerFromPlatformDependency,
    normalizeStoredRoleFactsForPermissionResync,
    cloneRoleFactsSnapshotForRollback,
    normalizeStrictDistinctUserIdsFromDependency,
    normalizeStrictNonNegativeIntegerFromDependency,
    resyncRoleStatusAffectedSnapshots
  } = createSharedAuthRoleStatusResyncComposition({
    authStore,
    loadPlatformRolePermissionGrantsByRoleIds,
    loadTenantRolePermissionGrantsByRoleIds,
    invalidateSessionCacheByUserId,
    addAuditEvent,
    recordPersistentAuditEvent
  });

  const {
    rollbackProvisionedUser,
    rollbackProvisionedUserIdentity
  } = createSharedAuthProvisioningRecoveryCapabilities({
    authStore,
    log,
    getDomainAccessForUser,
    getTenantOptionsForUser
  });

  const platformAuthCapabilities = createPlatformAuthComposition({
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
    resyncRoleStatusAffectedSnapshots,
  });

  const tenantAuthCapabilities = createTenantAuthComposition({
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
  });

  return createSharedAuthServiceFacade({
    ...sharedSessionFlowCapabilities,
    ...platformAuthCapabilities,
    ...tenantAuthCapabilities,
    getOrCreateUserIdentityByPhone,
    rollbackProvisionedUserIdentity,
    listAuditEvents,
    recordIdempotencyEvent,
    auditTrail,
    authStore,
    accessSessionCache,
    accessSessionCacheTtlMs,
    ownerTransferLocksByOrgId
  });
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

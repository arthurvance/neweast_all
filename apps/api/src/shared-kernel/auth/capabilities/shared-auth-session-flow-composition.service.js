'use strict';

const { createLoginService } = require('../../../modules/auth/login-service');
const {
  ROUTE_PERMISSION_EVALUATORS,
  TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT,
  ROLE_MANAGEMENT_PERMISSION_CODE_KEY_SET
} = require('../../../modules/auth/permission-catalog');
const {
  OTP_CODE_LENGTH,
  OTP_RESEND_COOLDOWN_SECONDS,
  PASSWORD_MIN_LENGTH,
  maskPhone,
  normalizePhone,
  isUserActive,
  normalizeEntryDomain,
  verifyPassword,
  normalizeAuditStringOrNull,
  normalizeAuditDomain,
  hashPassword,
  verifyJwt,
  tokenHash,
  normalizeOrgStatus,
  normalizeTenantId,
  toPlatformPermissionCodeKey
} = require('../create-auth-service.helpers');
const {
  createSharedAuthCredentialGovernanceCapabilities
} = require('./shared-auth-credential-governance.service');
const {
  createSharedAuthRefreshSessionCapabilities
} = require('./shared-auth-refresh-session.service');
const {
  createSharedRouteAuthorizationCapabilities
} = require('./shared-route-authorization.service');

const createSharedAuthSessionFlowComposition = ({
  now,
  errors,
  authStore,
  userRepository,
  otpStore,
  rateLimitStore,
  bindRequestTraceparent,
  addAuditEvent,
  randomInt,
  resolveAuthorizedSession,
  recordPersistentAuditEvent,
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
  jwtKeyPair,
  invalidateSessionCacheBySessionId,
  randomUUID,
  issueAccessToken,
  issueRefreshToken,
  buildSessionContext,
  reconcileTenantSessionContext,
  resolveSystemConfigPermissionGrant,
  OTP_TTL_SECONDS,
  RATE_LIMIT_WINDOW_SECONDS,
  RATE_LIMIT_MAX_ATTEMPTS,
  ACCESS_TTL_SECONDS,
  REFRESH_TTL_SECONDS
} = {}) => {
  const {
    validatePasswordPolicy,
    assertRateLimit,
    sendOtp,
    changePassword
  } = createSharedAuthCredentialGovernanceCapabilities({
    now,
    errors,
    otpStore,
    rateLimitStore,
    bindRequestTraceparent,
    addAuditEvent,
    maskPhone,
    normalizePhone,
    randomInt,
    resolveAuthorizedSession,
    verifyPassword,
    normalizeAuditStringOrNull,
    normalizeAuditDomain,
    recordPersistentAuditEvent,
    authStore,
    hashPassword,
    invalidateSessionCacheByUserId,
    OTP_CODE_LENGTH,
    OTP_RESEND_COOLDOWN_SECONDS,
    PASSWORD_MIN_LENGTH,
    OTP_TTL_SECONDS,
    RATE_LIMIT_WINDOW_SECONDS,
    RATE_LIMIT_MAX_ATTEMPTS
  });

  const { login, loginWithOtp } = createLoginService({
    userRepository,
    otpStore,
    errors,
    addAuditEvent,
    bindRequestTraceparent,
    now,
    normalizePhone,
    normalizeEntryDomain,
    maskPhone,
    isUserActive,
    verifyPassword,
    assertRateLimit,
    shouldProvisionDefaultPlatformDomainAccess,
    ensureDefaultDomainAccessForUser,
    ensureTenantDomainAccessForUser,
    assertDomainAccess,
    getTenantOptionsForUser,
    createSessionAndIssueLoginTokens,
    getTenantPermissionContext,
    getPlatformPermissionContext,
    resolveLoginUserName,
    accessTtlSeconds: ACCESS_TTL_SECONDS,
    refreshTtlSeconds: REFRESH_TTL_SECONDS
  });

  const {
    refresh,
    logout
  } = createSharedAuthRefreshSessionCapabilities({
    authStore,
    now,
    errors,
    bindRequestTraceparent,
    addAuditEvent,
    verifyJwt,
    jwtKeyPair,
    tokenHash,
    normalizeOrgStatus,
    invalidateSessionCacheBySessionId,
    randomUUID,
    issueAccessToken,
    issueRefreshToken,
    buildSessionContext,
    getTenantOptionsForUser,
    reconcileTenantSessionContext,
    getTenantPermissionContext,
    getPlatformPermissionContext,
    resolveLoginUserName,
    resolveAuthorizedSession,
    ACCESS_TTL_SECONDS,
    REFRESH_TTL_SECONDS
  });

  const {
    authorizeRoute
  } = createSharedRouteAuthorizationCapabilities({
    errors,
    resolveAuthorizedSession,
    buildSessionContext,
    normalizeTenantId,
    addAuditEvent,
    getTenantPermissionContext,
    getPlatformPermissionContext,
    resolveSystemConfigPermissionGrant,
    ROUTE_PERMISSION_EVALUATORS,
    TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT,
    toPlatformPermissionCodeKey,
    ROLE_MANAGEMENT_PERMISSION_CODE_KEY_SET
  });

  return {
    validatePasswordPolicy,
    assertRateLimit,
    sendOtp,
    changePassword,
    login,
    loginWithOtp,
    refresh,
    logout,
    authorizeRoute
  };
};

module.exports = {
  createSharedAuthSessionFlowComposition
};

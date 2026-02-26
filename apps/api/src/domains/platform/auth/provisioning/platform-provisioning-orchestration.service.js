'use strict';

const createPlatformProvisioningOrchestrationCapabilities = ({
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
} = {}) => {
  const ensurePlatformProvisioningRelationship = async ({
    requestId,
    userId
  }) => {
    const domainAccess = await getDomainAccessForUser(userId);
    if (domainAccess.platform) {
      throw errors.provisionConflict();
    }
    const provisionedDomainAccess = await ensureDefaultDomainAccessForUser({
      requestId,
      userId
    });
    if (!provisionedDomainAccess || provisionedDomainAccess.inserted !== true) {
      throw errors.provisionConflict();
    }
    const updatedDomainAccess = await getDomainAccessForUser(userId);
    if (!updatedDomainAccess.platform) {
      throw errors.provisionConflict();
    }
    return null;
  };

  const recoverPlatformProvisioningOutcomeAfterConflict = async ({
    error,
    createdUser,
    userId
  }) => {
    if (
      !(error instanceof AuthProblemError)
      || error.errorCode !== 'AUTH-409-PROVISION-CONFLICT'
      || !createdUser
    ) {
      return null;
    }
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return null;
    }
    const domainAccess = await getDomainAccessForUser(normalizedUserId);
    if (!domainAccess.platform) {
      return null;
    }
    return { active_tenant_id: null };
  };

  const provisionPlatformUserByPhone = async ({
    requestId,
    accessToken,
    phone,
    tenantName = undefined,
    payload = undefined,
    authorizationContext = null,
    authorizedRoute = null
  }) => {
    const payloadCandidate = payload === undefined
      ? {
        phone,
        ...(tenantName !== undefined ? { tenant_name: tenantName } : {})
      }
      : payload;
    const parsedPayload = parseProvisionPayload({
      payload: payloadCandidate,
      scope: 'platform'
    });
    if (!parsedPayload.valid) {
      throw errors.invalidPayload();
    }
    const normalizedPhone = normalizePhone(parsedPayload.phone);
    if (parsedPayload.tenantNameProvided || !normalizedPhone) {
      throw errors.invalidPayload();
    }

    const normalizedAuthorizedRoute =
      authorizedRoute && typeof authorizedRoute === 'object'
        ? {
          user_id: String(
            authorizedRoute.user_id
            || authorizedRoute.userId
            || ''
          ).trim(),
          session_id: String(
            authorizedRoute.session_id
            || authorizedRoute.sessionId
            || ''
          ).trim(),
          entry_domain: normalizeEntryDomain(
            authorizedRoute.entry_domain
            || authorizedRoute.entryDomain
          ),
          active_tenant_id: normalizeTenantId(
            authorizedRoute.active_tenant_id
            || authorizedRoute.activeTenantId
          )
        }
        : null;

    let resolvedAuthorizedRoute = null;
    if (normalizedAuthorizedRoute) {
      if (
        !normalizedAuthorizedRoute.user_id
        || !normalizedAuthorizedRoute.session_id
        || normalizedAuthorizedRoute.entry_domain !== 'platform'
      ) {
        throw errors.forbidden();
      }
      resolvedAuthorizedRoute = normalizedAuthorizedRoute;
    } else {
      resolvedAuthorizedRoute = await authorizeRoute({
        requestId,
        accessToken,
        permissionCode: PLATFORM_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
        scope: 'platform',
        authorizationContext
      });
    }

    const operatorUserId = String(resolvedAuthorizedRoute?.user_id || '').trim() || 'unknown';
    const operatorSessionId = String(resolvedAuthorizedRoute?.session_id || '').trim() || 'unknown';
    const sessionEntryDomain = String(
      resolvedAuthorizedRoute?.entry_domain || ''
    ).trim().toLowerCase();

    let provisionedUser = null;
    let createdUser = false;
    let relationTenantId = null;
    try {
      const provisionedResult = await getOrCreateProvisionUserByPhone({
        requestId,
        phone: normalizedPhone,
        operatorUserId,
        operatorSessionId
      });
      provisionedUser = provisionedResult.user;
      createdUser = provisionedResult.createdUser;
      relationTenantId = await ensurePlatformProvisioningRelationship({
        requestId,
        userId: provisionedUser.id
      });
    } catch (error) {
      let recoveredOutcome = null;
      try {
        recoveredOutcome = await recoverPlatformProvisioningOutcomeAfterConflict({
          error,
          createdUser,
          userId: provisionedUser?.id
        });
      } catch (recoveryError) {
        log('warn', 'Post-conflict platform provisioning recovery check failed', {
          request_id: requestId || 'request_id_unset',
          user_id: String(provisionedUser?.id || 'unknown'),
          reason: String(recoveryError?.message || 'unknown')
        });
      }

      if (recoveredOutcome) {
        relationTenantId = recoveredOutcome.active_tenant_id;
      } else if (createdUser && provisionedUser?.id) {
        await rollbackProvisionedUser({
          requestId,
          userId: provisionedUser.id
        });
        addAuditEvent({
          type: 'auth.user.provision.rejected',
          requestId,
          userId: operatorUserId || 'unknown',
          sessionId: operatorSessionId || 'unknown',
          detail: 'platform user provisioning rejected after rollback',
          metadata: {
            operator_user_id: operatorUserId,
            phone_masked: maskPhone(normalizedPhone),
            entry_domain: sessionEntryDomain,
            tenant_id: null,
            error_code:
              error instanceof AuthProblemError
                ? error.errorCode
                : 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
          }
        });
        throw error;
      } else {
        addAuditEvent({
          type: 'auth.user.provision.rejected',
          requestId,
          userId: operatorUserId || 'unknown',
          sessionId: operatorSessionId || 'unknown',
          detail: 'platform user provisioning rejected',
          metadata: {
            operator_user_id: operatorUserId,
            phone_masked: maskPhone(normalizedPhone),
            entry_domain: sessionEntryDomain,
            tenant_id: null,
            error_code:
              error instanceof AuthProblemError
                ? error.errorCode
                : 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
          }
        });
        throw error;
      }
    }

    addAuditEvent({
      type: createdUser ? 'auth.user.provision.created' : 'auth.user.provision.reused',
      requestId,
      userId: provisionedUser.id,
      sessionId: operatorSessionId,
      detail: createdUser
        ? 'user provisioned with default password policy'
        : 'existing user reused without credential mutation',
      metadata: {
        operator_user_id: operatorUserId,
        phone_masked: maskPhone(normalizedPhone),
        entry_domain: sessionEntryDomain,
        tenant_id: relationTenantId,
        credential_initialized: createdUser,
        first_login_force_password_change: false
      }
    });

    return {
      user_id: provisionedUser.id,
      phone: provisionedUser.phone,
      created_user: createdUser,
      reused_existing_user: !createdUser,
      credential_initialized: createdUser,
      first_login_force_password_change: false,
      entry_domain: sessionEntryDomain,
      active_tenant_id: relationTenantId,
      request_id: requestId || 'request_id_unset'
    };
  };

  return {
    provisionPlatformUserByPhone
  };
};

module.exports = {
  createPlatformProvisioningOrchestrationCapabilities
};

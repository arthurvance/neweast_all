'use strict';

const createTenantProvisioningOrchestrationCapabilities = ({
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
} = {}) => {
  const rollbackProvisionedTenantUsership = async ({
    requestId,
    userId,
    tenantId
  }) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (
      !normalizedUserId
      || !normalizedTenantId
      || typeof authStore.removeTenantUsershipForUser !== 'function'
    ) {
      return;
    }
    try {
      await authStore.removeTenantUsershipForUser({
        userId: normalizedUserId,
        tenantId: normalizedTenantId
      });
    } catch (rollbackError) {
      log('warn', 'Failed to rollback provisioned tenant usership after conflict', {
        request_id: requestId || 'request_id_unset',
        user_id: normalizedUserId,
        tenant_id: normalizedTenantId,
        reason: String(rollbackError?.message || 'unknown')
      });
    }
    if (typeof authStore.removeTenantDomainAccessForUser !== 'function') {
      return;
    }
    try {
      await authStore.removeTenantDomainAccessForUser(normalizedUserId);
    } catch (rollbackError) {
      log('warn', 'Failed to rollback provisioned tenant domain access after conflict', {
        request_id: requestId || 'request_id_unset',
        user_id: normalizedUserId,
        reason: String(rollbackError?.message || 'unknown')
      });
    }
  };

  const ensureTenantProvisioningRelationship = async ({
    requestId,
    activeTenantId,
    userId,
    tenantName
  }) => {
    const normalizedTenantId = normalizeTenantId(activeTenantId);
    if (!normalizedTenantId) {
      throw errors.noDomainAccess();
    }

    const existingTenantOptions = await getTenantOptionsForUser(userId);
    if (existingTenantOptions.some((option) => option.tenant_id === normalizedTenantId)) {
      const domainAccessBefore = await getDomainAccessForUser(userId);
      if (domainAccessBefore.tenant) {
        throw errors.provisionConflict();
      }

      await ensureTenantDomainAccessForUser({
        requestId,
        userId,
        entryDomain: 'tenant'
      });
      const domainAccessAfter = await getDomainAccessForUser(userId);
      if (!domainAccessAfter.tenant) {
        throw errors.provisionConflict();
      }
      return normalizedTenantId;
    }

    assertStoreMethod(authStore, 'createTenantUsershipForUser', 'authStore');
    let createdMembership = null;
    try {
      createdMembership = await authStore.createTenantUsershipForUser({
        userId: String(userId),
        tenantId: normalizedTenantId,
        tenantName
      });
    } catch (error) {
      if (isDataTooLongRoleFactError(error)) {
        throw errors.invalidPayload();
      }
      throw error;
    }
    if (!createdMembership || createdMembership.created !== true) {
      throw errors.provisionConflict();
    }

    try {
      await ensureTenantDomainAccessForUser({
        requestId,
        userId,
        entryDomain: 'tenant'
      });
      const updatedDomainAccess = await getDomainAccessForUser(userId);
      if (!updatedDomainAccess.tenant) {
        throw errors.provisionConflict();
      }
    } catch (error) {
      await rollbackProvisionedTenantUsership({
        requestId,
        userId,
        tenantId: normalizedTenantId
      });
      throw error;
    }

    return normalizedTenantId;
  };

  const resolveProvisionTenantName = async ({
    operatorUserId,
    activeTenantId,
    requestedTenantName
  }) => {
    const normalizedActiveTenantId = normalizeTenantId(activeTenantId);
    if (!normalizedActiveTenantId) {
      return null;
    }
    const operatorTenantOptions = await getTenantOptionsForUser(operatorUserId);
    const activeTenantOption = operatorTenantOptions.find(
      (option) => option.tenant_id === normalizedActiveTenantId
    );
    const canonicalTenantName = activeTenantOption?.tenant_name
      ? String(activeTenantOption.tenant_name).trim() || null
      : null;
    if (!canonicalTenantName) {
      throw errors.invalidPayload();
    }
    if (
      requestedTenantName
      && canonicalTenantName !== requestedTenantName
    ) {
      throw errors.invalidPayload();
    }
    return canonicalTenantName;
  };

  const recoverTenantProvisioningOutcomeAfterConflict = async ({
    error,
    createdUser,
    userId,
    activeTenantId
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
    const normalizedTenantId = normalizeTenantId(activeTenantId);
    if (!normalizedTenantId || !domainAccess.tenant) {
      return null;
    }
    const tenantOptions = await getTenantOptionsForUser(normalizedUserId);
    if (!tenantOptions.some((option) => option.tenant_id === normalizedTenantId)) {
      return null;
    }
    return { active_tenant_id: normalizedTenantId };
  };

  const provisionTenantUserByPhone = async ({
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
      scope: 'tenant'
    });
    if (!parsedPayload.valid) {
      throw errors.invalidPayload();
    }
    const normalizedPhone = normalizePhone(parsedPayload.phone);
    const parsedTenantName = parseOptionalTenantName(parsedPayload.tenantName);
    if (!normalizedPhone || !parsedTenantName.valid) {
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
        || normalizedAuthorizedRoute.entry_domain !== 'tenant'
      ) {
        throw errors.forbidden();
      }
      resolvedAuthorizedRoute = normalizedAuthorizedRoute;
    } else {
      resolvedAuthorizedRoute = await authorizeRoute({
        requestId,
        accessToken,
        permissionCode: TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
        scope: 'tenant',
        authorizationContext
      });
    }

    const operatorUserId = String(resolvedAuthorizedRoute?.user_id || '').trim() || 'unknown';
    const operatorSessionId = String(resolvedAuthorizedRoute?.session_id || '').trim() || 'unknown';
    const sessionEntryDomain = String(
      resolvedAuthorizedRoute?.entry_domain || ''
    ).trim().toLowerCase();
    const activeTenantId = normalizeTenantId(resolvedAuthorizedRoute?.active_tenant_id);
    const resolvedTenantName = await resolveProvisionTenantName({
      operatorUserId,
      activeTenantId,
      requestedTenantName: parsedTenantName.value
    });

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
      relationTenantId = await ensureTenantProvisioningRelationship({
        requestId,
        activeTenantId,
        userId: provisionedUser.id,
        tenantName: resolvedTenantName
      });
    } catch (error) {
      let recoveredOutcome = null;
      try {
        recoveredOutcome = await recoverTenantProvisioningOutcomeAfterConflict({
          error,
          createdUser,
          userId: provisionedUser?.id,
          activeTenantId
        });
      } catch (recoveryError) {
        log('warn', 'Post-conflict tenant provisioning recovery check failed', {
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
          detail: 'tenant user provisioning rejected after rollback',
          metadata: {
            operator_user_id: operatorUserId,
            phone_masked: maskPhone(normalizedPhone),
            entry_domain: sessionEntryDomain,
            tenant_id: activeTenantId,
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
          detail: 'tenant user provisioning rejected',
          metadata: {
            operator_user_id: operatorUserId,
            phone_masked: maskPhone(normalizedPhone),
            entry_domain: sessionEntryDomain,
            tenant_id: activeTenantId,
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
    provisionTenantUserByPhone
  };
};

module.exports = {
  createTenantProvisioningOrchestrationCapabilities
};

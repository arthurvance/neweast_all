'use strict';

const createTenantSessionNavigationCapabilities = ({
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
} = {}) => {
  const tenantOptions = async ({
    requestId,
    accessToken,
    authorizationContext = null
  }) => {
    const { session, user } = await resolveAuthorizedSession({
      requestId,
      accessToken,
      authorizationContext
    });
    const sessionId = session.sessionId || session.session_id;
    let sessionContext = buildSessionContext(session);
    if (sessionContext.entry_domain !== 'tenant') {
      rejectNoDomainAccess({
        requestId,
        userId: user.id,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        tenantId: null,
        detail: `tenant options rejected for entry domain ${sessionContext.entry_domain}`
      });
    }

    const options = await getTenantOptionsForUser(user.id);
    sessionContext = await reconcileTenantSessionContext({
      requestId,
      userId: user.id,
      sessionId,
      sessionContext,
      options
    });
    const selectionRequired = sessionContext.entry_domain === 'tenant'
      && options.length > 1
      && !sessionContext.active_tenant_id;

    const tenantPermissionContext = await getTenantPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: sessionContext.active_tenant_id
    });
    const userName = await resolveLoginUserName({
      userId: user.id,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: sessionContext.active_tenant_id
    });

    return {
      session_id: sessionId,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: sessionContext.active_tenant_id,
      tenant_selection_required: selectionRequired,
      tenant_options: options,
      user_name: userName,
      tenant_permission_context: tenantPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  const selectOrSwitchTenant = async ({
    requestId,
    accessToken,
    tenantId,
    eventType,
    authorizationContext = null
  }) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedTenantId) {
      throw errors.invalidPayload();
    }

    const { session, user } = await resolveAuthorizedSession({
      requestId,
      accessToken,
      authorizationContext
    });
    const sessionId = session.sessionId || session.session_id;
    const sessionContext = buildSessionContext(session);

    await assertDomainAccess({
      requestId,
      userId: user.id,
      entryDomain: 'tenant'
    });

    if (sessionContext.entry_domain !== 'tenant') {
      addAuditEvent({
        type: 'auth.domain.rejected',
        requestId,
        userId: user.id,
        sessionId,
        detail: `tenant selection rejected for entry domain ${sessionContext.entry_domain}`,
        metadata: {
          permission_code: null,
          entry_domain: sessionContext.entry_domain,
          tenant_id: normalizedTenantId
        }
      });
      throw errors.noDomainAccess();
    }

    const options = await getTenantOptionsForUser(user.id);
    const matched = options.find((item) => item.tenant_id === normalizedTenantId);
    if (!matched) {
      addAuditEvent({
        type: 'auth.domain.rejected',
        requestId,
        userId: user.id,
        sessionId,
        detail: `tenant selection rejected: ${normalizedTenantId}`,
        metadata: {
          permission_code: null,
          entry_domain: sessionContext.entry_domain,
          tenant_id: normalizedTenantId
        }
      });
      throw errors.noDomainAccess();
    }

    if (typeof sessionRepository.updateSessionContext !== 'function') {
      throw new Error('sessionRepository.updateSessionContext is required');
    }
    await sessionRepository.updateSessionContext({
      sessionId,
      entryDomain: 'tenant',
      activeTenantId: normalizedTenantId
    });
    invalidateSessionCacheBySessionId(sessionId);

    addAuditEvent({
      type: eventType,
      requestId,
      userId: user.id,
      sessionId,
      detail: `active tenant updated: ${normalizedTenantId}`,
      metadata: {
        entry_domain: 'tenant',
        tenant_id: normalizedTenantId
      }
    });

    const tenantPermissionContext = await getTenantPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: 'tenant',
      activeTenantId: normalizedTenantId
    });
    const userName = await resolveLoginUserName({
      userId: user.id,
      entryDomain: 'tenant',
      activeTenantId: normalizedTenantId
    });

    return {
      session_id: sessionId,
      entry_domain: 'tenant',
      active_tenant_id: normalizedTenantId,
      tenant_selection_required: false,
      user_name: userName,
      tenant_permission_context: tenantPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  const switchTenant = async ({
    requestId,
    accessToken,
    tenantId,
    authorizationContext = null
  }) =>
    selectOrSwitchTenant({
      requestId,
      accessToken,
      tenantId,
      eventType: 'auth.tenant.switched',
      authorizationContext
    });

  return {
    tenantOptions,
    switchTenant
  };
};

module.exports = {
  createTenantSessionNavigationCapabilities
};

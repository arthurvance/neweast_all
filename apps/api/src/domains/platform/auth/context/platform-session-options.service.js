'use strict';

const createPlatformSessionOptionsCapabilities = ({
  resolveAuthorizedSession,
  buildSessionContext,
  rejectNoDomainAccess,
  getPlatformPermissionContext,
  resolveLoginUserName
} = {}) => {
  const platformOptions = async ({
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
    const sessionContext = buildSessionContext(session);
    if (sessionContext.entry_domain !== 'platform') {
      rejectNoDomainAccess({
        requestId,
        userId: user.id,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        tenantId: null,
        detail: `platform options rejected for entry domain ${sessionContext.entry_domain}`
      });
    }

    const platformPermissionContext = await getPlatformPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: sessionContext.entry_domain
    });
    const userName = await resolveLoginUserName({
      userId: user.id,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: null
    });

    return {
      session_id: sessionId,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: sessionContext.active_tenant_id,
      user_name: userName,
      platform_permission_context: platformPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  return {
    platformOptions
  };
};

module.exports = {
  createPlatformSessionOptionsCapabilities
};

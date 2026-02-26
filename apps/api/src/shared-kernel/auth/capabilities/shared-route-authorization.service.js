'use strict';

const createSharedRouteAuthorizationCapabilities = ({
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
} = {}) => {
  const authorizeRoute = async ({
    requestId,
    accessToken,
    permissionCode,
    scope = 'session',
    authorizationContext = null,
    authorizedSession = null
  }) => {
    const normalizedPermissionCode = String(permissionCode || '').trim();
    if (normalizedPermissionCode.length === 0) {
      throw errors.forbidden();
    }

    const resolvedSession = authorizedSession && typeof authorizedSession === 'object'
      ? authorizedSession
      : await resolveAuthorizedSession({
        requestId,
        accessToken,
        authorizationContext
      });
    const { session, user } = resolvedSession;
    const sessionId = session.sessionId || session.session_id;
    const sessionContext = buildSessionContext(session);
    const normalizedScope = String(scope || 'session').trim().toLowerCase();
    const normalizedActiveTenantId = normalizeTenantId(sessionContext.active_tenant_id);

    if (normalizedScope === 'tenant' && sessionContext.entry_domain !== 'tenant') {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: `tenant scoped route blocked in ${sessionContext.entry_domain} entry`,
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: sessionContext.active_tenant_id
        }
      });
      throw errors.noDomainAccess();
    }
    if (normalizedScope === 'platform' && sessionContext.entry_domain !== 'platform') {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: `platform scoped route blocked in ${sessionContext.entry_domain} entry`,
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: sessionContext.active_tenant_id
        }
      });
      throw errors.noDomainAccess();
    }
    if (
      normalizedScope === 'tenant'
      && sessionContext.entry_domain === 'tenant'
      && !normalizedActiveTenantId
      && !TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT.has(normalizedPermissionCode)
    ) {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: 'tenant scoped route blocked without active tenant context',
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: null
        }
      });
      throw errors.noDomainAccess();
    }

    const shouldResolveTenantPermissionContext =
      normalizedScope === 'tenant'
      && !TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT.has(normalizedPermissionCode);
    const shouldResolvePlatformPermissionContext = normalizedScope === 'platform';

    const tenantPermissionContext = shouldResolveTenantPermissionContext
      ? await getTenantPermissionContext({
        requestId,
        userId: user.id,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        activeTenantId: normalizedActiveTenantId
      })
      : null;
    const platformPermissionContext = shouldResolvePlatformPermissionContext
      ? await getPlatformPermissionContext({
        requestId,
        userId: user.id,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        permissionCode: normalizedPermissionCode
      })
      : null;

    const evaluator = ROUTE_PERMISSION_EVALUATORS[normalizedPermissionCode];
    if (typeof evaluator !== 'function') {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: `unknown permission code declaration: ${normalizedPermissionCode}`,
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: normalizedActiveTenantId
        }
      });
      throw errors.forbidden();
    }

    let allowed = evaluator({
      platformPermissionContext,
      tenantPermissionContext,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: normalizedActiveTenantId
    });
    const normalizedPermissionCodeKey = toPlatformPermissionCodeKey(
      normalizedPermissionCode
    );
    if (
      normalizedScope === 'platform'
      && ROLE_MANAGEMENT_PERMISSION_CODE_KEY_SET.has(normalizedPermissionCodeKey)
    ) {
      const grant = await resolveSystemConfigPermissionGrant({
        requestId,
        userId: user.id,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        permissionCode: normalizedPermissionCode
      });
      if (platformPermissionContext && typeof platformPermissionContext === 'object') {
        platformPermissionContext.can_view_role_management = grant.can_view_role_management;
        platformPermissionContext.can_operate_role_management = grant.can_operate_role_management;
      }
      allowed = grant.granted;
    }
    if (!allowed) {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: `permission denied: ${normalizedPermissionCode}`,
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: normalizedActiveTenantId
        }
      });
      throw errors.forbidden();
    }

    return {
      session_id: sessionId,
      user_id: user.id,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: normalizedActiveTenantId || null,
      platform_permission_context: platformPermissionContext,
      tenant_permission_context: tenantPermissionContext,
      session,
      user
    };
  };

  return {
    authorizeRoute
  };
};

module.exports = {
  createSharedRouteAuthorizationCapabilities
};

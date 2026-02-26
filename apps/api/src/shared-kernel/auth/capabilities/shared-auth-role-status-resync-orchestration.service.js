'use strict';

const createSharedAuthRoleStatusResyncOrchestration = ({
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
} = {}) => {
  const resyncRoleStatusAffectedSnapshots = async ({
    requestId = 'request_id_unset',
    traceparent = null,
    roleId,
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null,
    previousStatus = null,
    currentStatus = null,
    operatorUserId = null,
    operatorSessionId = null
  } = {}) => {
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedTenantId = normalizedScope === TENANT_ROLE_SCOPE
      ? normalizeTenantId(tenantId)
      : null;
    if (normalizedScope === TENANT_ROLE_SCOPE && !normalizedTenantId) {
      throw errors.invalidPayload();
    }

    let affectedUserCount = 0;
    let affectedMembershipCount = 0;
    if (normalizedScope === TENANT_ROLE_SCOPE) {
      const result = await resyncTenantRoleStatusAffectedSnapshots({
        tenantId: normalizedTenantId,
        roleId: normalizedRoleId,
        requestId,
        operatorUserId,
        operatorSessionId
      });
      affectedUserCount = Number(result?.affectedUserCount || 0);
      affectedMembershipCount = Number(result?.affectedMembershipCount || 0);
    } else {
      const result = await resyncPlatformRoleStatusAffectedSnapshots({
        roleId: normalizedRoleId,
        requestId
      });
      affectedUserCount = Number(result?.affectedUserCount || 0);
      affectedMembershipCount = Number(result?.affectedMembershipCount || 0);
    }

    await recordPersistentAuditEvent({
      domain: normalizedScope === TENANT_ROLE_SCOPE ? 'tenant' : 'platform',
      tenantId: normalizedScope === TENANT_ROLE_SCOPE ? normalizedTenantId : null,
      requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
      traceparent: normalizeAuditStringOrNull(traceparent, 128),
      eventType: 'auth.role.catalog.status_synced',
      actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
      actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
      targetType: 'role',
      targetId: normalizedRoleId,
      result: 'success',
      beforeState: {
        status: normalizeRoleCatalogStatusForResync(previousStatus),
        scope: normalizedScope,
        tenant_id: normalizedScope === TENANT_ROLE_SCOPE ? normalizedTenantId : null
      },
      afterState: {
        status: normalizeRoleCatalogStatusForResync(currentStatus),
        scope: normalizedScope,
        tenant_id: normalizedScope === TENANT_ROLE_SCOPE ? normalizedTenantId : null
      },
      metadata: {
        affected_user_count: affectedUserCount,
        affected_membership_count: affectedMembershipCount
      }
    });

    return {
      affectedUserCount,
      affectedMembershipCount
    };
  };

  return {
    resyncRoleStatusAffectedSnapshots
  };
};

module.exports = {
  createSharedAuthRoleStatusResyncOrchestration
};

const normalizeOptionalTenantOwnerField = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  const normalized = String(value).trim();
  return normalized.length > 0 ? normalized : null;
};

const createTenantContextService = ({
  sessionRepository,
  tenantMembershipRepository,
  normalizeTenantId,
  addAuditEvent,
  invalidateSessionCacheBySessionId
} = {}) => {
  const getTenantOptionsForUser = async (userId) => {
    if (typeof tenantMembershipRepository.listTenantOptionsByUserId !== 'function') {
      return [];
    }
    const options = await tenantMembershipRepository.listTenantOptionsByUserId(
      String(userId)
    );
    if (!Array.isArray(options)) {
      return [];
    }
    return options
      .map((option) => {
        const ownerName = normalizeOptionalTenantOwnerField(
          option.ownerName || option.owner_name
        );
        const ownerPhone = normalizeOptionalTenantOwnerField(
          option.ownerPhone || option.owner_phone
        );
        return {
          tenant_id: normalizeTenantId(option.tenantId || option.tenant_id),
          tenant_name: option.tenantName || option.tenant_name || null,
          ...(ownerName ? { owner_name: ownerName } : {}),
          ...(ownerPhone ? { owner_phone: ownerPhone } : {})
        };
      })
      .filter((option) => option.tenant_id);
  };

  const reconcileTenantSessionContext = async ({
    requestId,
    userId,
    sessionId,
    sessionContext,
    options,
    rejectNoDomainAccess
  }) => {
    if (sessionContext.entry_domain !== 'tenant') {
      return sessionContext;
    }

    if (!Array.isArray(options) || options.length === 0) {
      rejectNoDomainAccess({
        requestId,
        userId,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        tenantId: null,
        detail: 'tenant entry without active tenant relationship'
      });
    }

    const optionTenantIds = new Set(options.map((option) => option.tenant_id));
    const currentActiveTenantId = normalizeTenantId(sessionContext.active_tenant_id);

    if (currentActiveTenantId && optionTenantIds.has(currentActiveTenantId)) {
      return sessionContext;
    }

    const nextActiveTenantId = options.length === 1 ? options[0].tenant_id : null;
    if (currentActiveTenantId && !optionTenantIds.has(currentActiveTenantId)) {
      addAuditEvent({
        type: 'auth.tenant.context.invalidated',
        requestId,
        userId,
        sessionId,
        detail: `active tenant no longer allowed: ${currentActiveTenantId}`,
        metadata: {
          entry_domain: sessionContext.entry_domain,
          tenant_id: currentActiveTenantId
        }
      });
    }

    if (currentActiveTenantId !== nextActiveTenantId) {
      if (typeof sessionRepository.updateSessionContext !== 'function') {
        throw new Error('sessionRepository.updateSessionContext is required');
      }
      await sessionRepository.updateSessionContext({
        sessionId,
        entryDomain: 'tenant',
        activeTenantId: nextActiveTenantId
      });
      invalidateSessionCacheBySessionId(sessionId);
    }

    return {
      entry_domain: 'tenant',
      active_tenant_id: nextActiveTenantId
    };
  };

  return {
    getTenantOptionsForUser,
    reconcileTenantSessionContext
  };
};

module.exports = {
  createTenantContextService
};

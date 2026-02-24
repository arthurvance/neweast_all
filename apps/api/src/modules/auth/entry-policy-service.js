const createEntryPolicyService = ({
  domainAccessRepository,
  addAuditEvent,
  errors,
  normalizeTenantId,
  getTenantOptionsForUser
} = {}) => {
  const getDomainAccessForUser = async (userId) => {
    if (typeof domainAccessRepository.findDomainAccessByUserId === 'function') {
      const access = await domainAccessRepository.findDomainAccessByUserId(
        String(userId)
      );
      return {
        platform: Boolean(access?.platform),
        tenant: Boolean(access?.tenant)
      };
    }
    return { platform: false, tenant: false };
  };

  const ensureDefaultDomainAccessForUser = async ({ requestId, userId }) => {
    if (
      typeof domainAccessRepository.ensureDefaultDomainAccessForUser !== 'function'
    ) {
      return { inserted: false };
    }
    const result = await domainAccessRepository.ensureDefaultDomainAccessForUser(
      String(userId)
    );
    if (result?.inserted === true) {
      addAuditEvent({
        type: 'auth.domain.default_granted',
        requestId,
        userId,
        detail: 'default platform domain access provisioned',
        metadata: {
          entry_domain: 'platform',
          tenant_id: null
        }
      });
    }
    return {
      inserted: result?.inserted === true
    };
  };

  const ensureTenantDomainAccessForUser = async ({ requestId, userId, entryDomain }) => {
    if (entryDomain !== 'tenant') {
      return;
    }
    if (
      typeof domainAccessRepository.ensureTenantDomainAccessForUser !== 'function'
    ) {
      return;
    }
    const result = await domainAccessRepository.ensureTenantDomainAccessForUser(
      String(userId)
    );
    if (result?.inserted === true) {
      addAuditEvent({
        type: 'auth.domain.tenant_granted',
        requestId,
        userId,
        detail: 'tenant domain access provisioned from active tenant membership',
        metadata: {
          entry_domain: 'tenant',
          tenant_id: null
        }
      });
    }
  };

  const shouldProvisionDefaultPlatformDomainAccess = async ({ userId }) => {
    const access = await getDomainAccessForUser(userId);
    if (access.platform || access.tenant) {
      return false;
    }

    if (
      typeof domainAccessRepository.hasAnyTenantRelationshipByUserId !== 'function'
    ) {
      return false;
    }

    const hasAnyTenantRelationship =
      await domainAccessRepository.hasAnyTenantRelationshipByUserId(String(userId));
    if (hasAnyTenantRelationship) {
      return false;
    }

    const tenantOptions = typeof getTenantOptionsForUser === 'function'
      ? await getTenantOptionsForUser(userId)
      : [];
    return tenantOptions.length === 0;
  };

  const rejectNoDomainAccess = ({
    requestId,
    userId,
    sessionId = 'unknown',
    entryDomain,
    tenantId,
    detail,
    permissionCode = null
  }) => {
    addAuditEvent({
      type: 'auth.domain.rejected',
      requestId,
      userId,
      sessionId,
      detail,
      metadata: {
        permission_code: permissionCode,
        entry_domain: entryDomain,
        tenant_id: normalizeTenantId(tenantId)
      }
    });
    throw errors.noDomainAccess();
  };

  const assertDomainAccess = async ({ requestId, userId, entryDomain }) => {
    const access = await getDomainAccessForUser(userId);
    const allowed = entryDomain === 'platform' ? access.platform : access.tenant;
    if (!allowed) {
      addAuditEvent({
        type: 'auth.domain.rejected',
        requestId,
        userId,
        detail: `domain access denied: ${entryDomain}`,
        metadata: {
          permission_code: null,
          entry_domain: entryDomain,
          tenant_id: null
        }
      });
      throw errors.noDomainAccess();
    }
    return access;
  };

  return {
    getDomainAccessForUser,
    ensureDefaultDomainAccessForUser,
    ensureTenantDomainAccessForUser,
    shouldProvisionDefaultPlatformDomainAccess,
    rejectNoDomainAccess,
    assertDomainAccess
  };
};

module.exports = {
  createEntryPolicyService
};

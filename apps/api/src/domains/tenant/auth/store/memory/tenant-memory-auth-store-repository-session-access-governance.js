'use strict';

const createTenantMemoryAuthStoreRepositorySessionAccessGovernance = ({
  domainsByUserId,
  isTenantUsershipActiveForAuth,
  tenantsByUserId
} = {}) => ({
  ensureTenantDomainAccessForUser: async (userId) => {
    const normalizedUserId = String(userId);
    const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
    if (userDomains.has('tenant')) {
      domainsByUserId.set(normalizedUserId, userDomains);
      return { inserted: false };
    }

    const hasActiveTenantUsership = (tenantsByUserId.get(normalizedUserId) || []).some(
      (tenant) => isTenantUsershipActiveForAuth(tenant)
    );
    if (!hasActiveTenantUsership) {
      domainsByUserId.set(normalizedUserId, userDomains);
      return { inserted: false };
    }

    userDomains.add('tenant');
    domainsByUserId.set(normalizedUserId, userDomains);
    return { inserted: true };
  },

  listTenantOptionsByUserId: async (userId) =>
    (tenantsByUserId.get(String(userId)) || [])
      .filter((tenant) => isTenantUsershipActiveForAuth(tenant))
      .map((tenant) => ({ ...tenant })),

  hasAnyTenantRelationshipByUserId: async (userId) =>
    (tenantsByUserId.get(String(userId)) || []).length > 0,

  findTenantPermissionByUserAndTenantId: async ({ userId, tenantId }) => {
    const normalizedTenantId = String(tenantId || '').trim();
    if (!normalizedTenantId) {
      return null;
    }

    const tenant = (tenantsByUserId.get(String(userId)) || []).find(
      (item) =>
        String(item.tenantId) === normalizedTenantId
        && isTenantUsershipActiveForAuth(item)
    );
    if (!tenant) {
      return null;
    }
    if (tenant.permission) {
      return {
        scopeLabel: tenant.permission.scopeLabel || `组织权限（${tenant.tenantName || tenant.tenantId}）`,
        canViewUserManagement: Boolean(tenant.permission.canViewUserManagement),
        canOperateUserManagement: Boolean(tenant.permission.canOperateUserManagement),
        canViewRoleManagement: Boolean(tenant.permission.canViewRoleManagement),
        canOperateRoleManagement: Boolean(tenant.permission.canOperateRoleManagement)
      };
    }
    return null;
  },
});

module.exports = {
  createTenantMemoryAuthStoreRepositorySessionAccessGovernance
};

'use strict';

const createTenantMysqlAuthStoreUsershipGovernanceRemoveTenantDomainAccessForUser = ({
  runTenantUsershipQuery
} = {}) => ({
removeTenantDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { removed: false };
      }
      const tenantCountRows = await runTenantUsershipQuery({
        sqlWithOrgGuard: `
          SELECT COUNT(*) AS tenant_count
          FROM tenant_memberships ut
          LEFT JOIN tenants o ON o.id = ut.tenant_id
          WHERE ut.user_id = ?
            AND ut.status IN ('active', 'enabled')
            AND o.status IN ('active', 'enabled')
        `,
        sqlWithoutOrgGuard: `
          SELECT COUNT(*) AS tenant_count
          FROM tenant_memberships ut
          WHERE ut.user_id = ?
            AND ut.status IN ('active', 'enabled')
        `,
        params: [normalizedUserId]
      });
      const tenantCount = Number(tenantCountRows?.[0]?.tenant_count || 0);
      return { removed: tenantCount <= 0 };
    }
});

module.exports = {
  createTenantMysqlAuthStoreUsershipGovernanceRemoveTenantDomainAccessForUser
};

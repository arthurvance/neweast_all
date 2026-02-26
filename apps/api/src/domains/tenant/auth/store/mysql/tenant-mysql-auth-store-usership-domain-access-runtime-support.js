'use strict';

const createTenantMysqlAuthStoreUsershipDomainAccessRuntimeSupport = ({
  dbClient,
  isMissingTenantsTableError
} = {}) => {
  let orgStatusGuardAvailable = true;

  const runTenantUsershipQuery = async ({
    txClient = dbClient,
    sqlWithOrgGuard,
    sqlWithoutOrgGuard,
    params = []
  }) => {
    const queryClient = txClient || dbClient;
    if (!orgStatusGuardAvailable) {
      return queryClient.query(sqlWithoutOrgGuard, params);
    }
    try {
      return await queryClient.query(sqlWithOrgGuard, params);
    } catch (error) {
      if (!isMissingTenantsTableError(error)) {
        throw error;
      }
      orgStatusGuardAvailable = false;
      return queryClient.query(sqlWithoutOrgGuard, params);
    }
  };

  const ensureTenantDomainAccessForUserTx = async ({
    txClient,
    userId,
    skipMembershipCheck = false
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return { inserted: false };
    }
    if (skipMembershipCheck) {
      return { inserted: false };
    }
    const tenantCountRows = await runTenantUsershipQuery({
      txClient,
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
    return {
      inserted: false,
      has_active_tenant_membership: tenantCount > 0
    };
  };

  const removeTenantDomainAccessForUserTx = async ({
    txClient,
    userId
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return { removed: false };
    }
    const tenantCountRows = await runTenantUsershipQuery({
      txClient,
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
  };

  const isOrgStatusGuardAvailable = () => orgStatusGuardAvailable;

  return {
    runTenantUsershipQuery,
    ensureTenantDomainAccessForUserTx,
    removeTenantDomainAccessForUserTx,
    isOrgStatusGuardAvailable
  };
};

module.exports = {
  createTenantMysqlAuthStoreUsershipDomainAccessRuntimeSupport
};

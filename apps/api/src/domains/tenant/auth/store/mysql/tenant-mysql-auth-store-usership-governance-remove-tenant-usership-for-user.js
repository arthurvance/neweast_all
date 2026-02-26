'use strict';

const createTenantMysqlAuthStoreUsershipGovernanceRemoveTenantUsershipForUser = ({
  dbClient
} = {}) => ({
removeTenantUsershipForUser: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('removeTenantUsershipForUser requires userId and tenantId');
      }
      const result = await dbClient.query(
        `
          DELETE FROM tenant_memberships
          WHERE user_id = ? AND tenant_id = ?
        `,
        [normalizedUserId, normalizedTenantId]
      );
      return { removed: Number(result?.affectedRows || 0) > 0 };
    }
});

module.exports = {
  createTenantMysqlAuthStoreUsershipGovernanceRemoveTenantUsershipForUser
};

'use strict';

const createTenantMemoryAuthStoreUsershipGovernanceRemoveTenantUsershipForUser = ({
  tenantUsershipRolesByMembershipId,
  tenantsByUserId
} = {}) => ({
removeTenantUsershipForUser: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('removeTenantUsershipForUser requires userId and tenantId');
      }
      const tenantUserships = tenantsByUserId.get(normalizedUserId);
      if (!Array.isArray(tenantUserships) || tenantUserships.length === 0) {
        return { removed: false };
      }
      const retainedMemberships = tenantUserships.filter(
        (tenant) => String(tenant?.tenantId || '').trim() !== normalizedTenantId
      );
      const removed = retainedMemberships.length !== tenantUserships.length;
      if (removed) {
        for (const membership of tenantUserships) {
          if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
            continue;
          }
          const membershipId = String(membership?.membershipId || '').trim();
          if (!membershipId) {
            continue;
          }
          tenantUsershipRolesByMembershipId.delete(membershipId);
        }
        tenantsByUserId.set(normalizedUserId, retainedMemberships);
      }
      return { removed };
    }
});

module.exports = {
  createTenantMemoryAuthStoreUsershipGovernanceRemoveTenantUsershipForUser
};

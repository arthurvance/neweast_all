'use strict';

const createTenantMemoryAuthStoreUsershipGovernanceRemoveTenantDomainAccessForUser = ({
  domainsByUserId,
  isTenantUsershipActiveForAuth,
  tenantsByUserId
} = {}) => ({
removeTenantDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { removed: false };
      }
      const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
      if (!userDomains.has('tenant')) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { removed: false };
      }
      const hasActiveTenantUsership = (tenantsByUserId.get(normalizedUserId) || []).some(
        (tenant) => isTenantUsershipActiveForAuth(tenant)
      );
      if (hasActiveTenantUsership) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { removed: false };
      }
      userDomains.delete('tenant');
      domainsByUserId.set(normalizedUserId, userDomains);
      return { removed: true };
    }
});

module.exports = {
  createTenantMemoryAuthStoreUsershipGovernanceRemoveTenantDomainAccessForUser
};

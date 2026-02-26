'use strict';

const createTenantMemoryAuthStoreUsershipGovernanceEnsureTenantDomainAccessForUser = ({
  repositoryMethods
} = {}) => ({
ensureTenantDomainAccessForUser: repositoryMethods.ensureTenantDomainAccessForUser
});

module.exports = {
  createTenantMemoryAuthStoreUsershipGovernanceEnsureTenantDomainAccessForUser
};

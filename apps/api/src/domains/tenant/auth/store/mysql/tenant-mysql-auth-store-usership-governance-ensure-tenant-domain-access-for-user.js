'use strict';

const createTenantMysqlAuthStoreUsershipGovernanceEnsureTenantDomainAccessForUser = ({
  repositoryMethods
} = {}) => ({
ensureTenantDomainAccessForUser: repositoryMethods.ensureTenantDomainAccessForUser
});

module.exports = {
  createTenantMysqlAuthStoreUsershipGovernanceEnsureTenantDomainAccessForUser
};

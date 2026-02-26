'use strict';

const createTenantMysqlAuthStoreUsershipGovernanceReadRepositoryProjection = ({
  repositoryMethods
} = {}) => ({
  listTenantOptionsByUserId: repositoryMethods.listTenantOptionsByUserId,
  hasAnyTenantRelationshipByUserId: repositoryMethods.hasAnyTenantRelationshipByUserId,
  findTenantPermissionByUserAndTenantId: repositoryMethods.findTenantPermissionByUserAndTenantId
});

module.exports = {
  createTenantMysqlAuthStoreUsershipGovernanceReadRepositoryProjection
};

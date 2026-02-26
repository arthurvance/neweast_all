'use strict';

const createTenantMemoryAuthStoreUsershipGovernanceReadRepositoryProjection = ({
  repositoryMethods
} = {}) => ({
  listTenantOptionsByUserId: repositoryMethods.listTenantOptionsByUserId,
  hasAnyTenantRelationshipByUserId: repositoryMethods.hasAnyTenantRelationshipByUserId,
  findTenantPermissionByUserAndTenantId: repositoryMethods.findTenantPermissionByUserAndTenantId
});

module.exports = {
  createTenantMemoryAuthStoreUsershipGovernanceReadRepositoryProjection
};

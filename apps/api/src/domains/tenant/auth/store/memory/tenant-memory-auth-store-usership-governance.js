'use strict';

const {
  createTenantMemoryAuthStoreUsershipGovernanceCreateTenantUsershipForUser
} = require('./tenant-memory-auth-store-usership-governance-create-tenant-usership-for-user.js');
const {
  createTenantMemoryAuthStoreUsershipGovernanceRemoveTenantUsershipForUser
} = require('./tenant-memory-auth-store-usership-governance-remove-tenant-usership-for-user.js');
const {
  createTenantMemoryAuthStoreUsershipGovernanceRemoveTenantDomainAccessForUser
} = require('./tenant-memory-auth-store-usership-governance-remove-tenant-domain-access-for-user.js');
const {
  createTenantMemoryAuthStoreUsershipGovernanceEnsureTenantDomainAccessForUser
} = require('./tenant-memory-auth-store-usership-governance-ensure-tenant-domain-access-for-user.js');
const {
  createTenantMemoryAuthStoreUsershipGovernanceReadRepositoryProjection
} = require('./tenant-memory-auth-store-usership-governance-read-repository-projection.js');
const {
  createTenantMemoryAuthStoreUsershipGovernanceFindTenantUsershipByUserAndTenantId
} = require('./tenant-memory-auth-store-usership-governance-find-tenant-usership-by-user-and-tenant-id.js');
const {
  createTenantMemoryAuthStoreUsershipGovernanceFindTenantUsershipByMembershipIdAndTenantId
} = require('./tenant-memory-auth-store-usership-governance-find-tenant-usership-by-membership-id-and-tenant-id.js');
const {
  createTenantMemoryAuthStoreUsershipGovernanceListTenantUsersByTenantId
} = require('./tenant-memory-auth-store-usership-governance-list-tenant-users-by-tenant-id.js');
const {
  createTenantMemoryAuthStoreUsershipGovernanceUpdateTenantUsershipProfile
} = require('./tenant-memory-auth-store-usership-governance-update-tenant-usership-profile.js');
const {
  createTenantMemoryAuthStoreUsershipGovernanceUpdateTenantUsershipStatus
} = require('./tenant-memory-auth-store-usership-governance-update-tenant-usership-status.js');
const {
  createTenantMemoryAuthStoreUsershipGovernanceReplaceTenantUsershipRoleBindingsAndSyncSnapshot
} = require('./tenant-memory-auth-store-usership-governance-replace-tenant-usership-role-bindings-and-sync-snapshot.js');

const createTenantMemoryAuthStoreUsershipGovernance = (dependencies = {}) => ({
  ...createTenantMemoryAuthStoreUsershipGovernanceCreateTenantUsershipForUser(dependencies),
  ...createTenantMemoryAuthStoreUsershipGovernanceRemoveTenantUsershipForUser(dependencies),
  ...createTenantMemoryAuthStoreUsershipGovernanceRemoveTenantDomainAccessForUser(dependencies),
  ...createTenantMemoryAuthStoreUsershipGovernanceEnsureTenantDomainAccessForUser(dependencies),
  ...createTenantMemoryAuthStoreUsershipGovernanceReadRepositoryProjection(dependencies),
  ...createTenantMemoryAuthStoreUsershipGovernanceFindTenantUsershipByUserAndTenantId(dependencies),
  ...createTenantMemoryAuthStoreUsershipGovernanceFindTenantUsershipByMembershipIdAndTenantId(dependencies),
  ...createTenantMemoryAuthStoreUsershipGovernanceListTenantUsersByTenantId(dependencies),
  ...createTenantMemoryAuthStoreUsershipGovernanceUpdateTenantUsershipProfile(dependencies),
  ...createTenantMemoryAuthStoreUsershipGovernanceUpdateTenantUsershipStatus(dependencies),
  listTenantUsershipRoleBindings: async ({
    membershipId,
    tenantId
  } = {}) =>
    dependencies.listTenantUsershipRoleBindingsForMembershipId({
      membershipId,
      tenantId
    }),
  ...createTenantMemoryAuthStoreUsershipGovernanceReplaceTenantUsershipRoleBindingsAndSyncSnapshot(dependencies),
});

module.exports = {
  createTenantMemoryAuthStoreUsershipGovernance
};

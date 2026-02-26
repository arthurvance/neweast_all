'use strict';

const {
  createTenantMysqlAuthStoreUsershipGovernanceCreateTenantUsershipForUser
} = require('./tenant-mysql-auth-store-usership-governance-create-tenant-usership-for-user.js');
const {
  createTenantMysqlAuthStoreUsershipGovernanceRemoveTenantUsershipForUser
} = require('./tenant-mysql-auth-store-usership-governance-remove-tenant-usership-for-user.js');
const {
  createTenantMysqlAuthStoreUsershipGovernanceRemoveTenantDomainAccessForUser
} = require('./tenant-mysql-auth-store-usership-governance-remove-tenant-domain-access-for-user.js');
const {
  createTenantMysqlAuthStoreUsershipGovernanceEnsureTenantDomainAccessForUser
} = require('./tenant-mysql-auth-store-usership-governance-ensure-tenant-domain-access-for-user.js');
const {
  createTenantMysqlAuthStoreUsershipGovernanceReadRepositoryProjection
} = require('./tenant-mysql-auth-store-usership-governance-read-repository-projection.js');
const {
  createTenantMysqlAuthStoreUsershipGovernanceFindTenantUsershipByUserAndTenantId
} = require('./tenant-mysql-auth-store-usership-governance-find-tenant-usership-by-user-and-tenant-id.js');
const {
  createTenantMysqlAuthStoreUsershipGovernanceFindTenantUsershipByMembershipIdAndTenantId
} = require('./tenant-mysql-auth-store-usership-governance-find-tenant-usership-by-membership-id-and-tenant-id.js');
const {
  createTenantMysqlAuthStoreUsershipGovernanceListTenantUsersByTenantId
} = require('./tenant-mysql-auth-store-usership-governance-list-tenant-users-by-tenant-id.js');
const {
  createTenantMysqlAuthStoreUsershipGovernanceUpdateTenantUsershipProfile
} = require('./tenant-mysql-auth-store-usership-governance-update-tenant-usership-profile.js');
const {
  createTenantMysqlAuthStoreUsershipGovernanceUpdateTenantUsershipStatus
} = require('./tenant-mysql-auth-store-usership-governance-update-tenant-usership-status.js');
const {
  createTenantMysqlAuthStoreUsershipGovernanceListTenantUsershipRoleBindings
} = require('./tenant-mysql-auth-store-usership-governance-list-tenant-usership-role-bindings.js');
const {
  createTenantMysqlAuthStoreUsershipGovernanceReplaceTenantUsershipRoleBindingsAndSyncSnapshot
} = require('./tenant-mysql-auth-store-usership-governance-replace-tenant-usership-role-bindings-and-sync-snapshot.js');

const createTenantMysqlAuthStoreUsershipGovernance = (dependencies = {}) => ({
  ...createTenantMysqlAuthStoreUsershipGovernanceCreateTenantUsershipForUser(dependencies),
  ...createTenantMysqlAuthStoreUsershipGovernanceRemoveTenantUsershipForUser(dependencies),
  ...createTenantMysqlAuthStoreUsershipGovernanceRemoveTenantDomainAccessForUser(dependencies),
  ...createTenantMysqlAuthStoreUsershipGovernanceEnsureTenantDomainAccessForUser(dependencies),
  ...createTenantMysqlAuthStoreUsershipGovernanceReadRepositoryProjection(dependencies),
  ...createTenantMysqlAuthStoreUsershipGovernanceFindTenantUsershipByUserAndTenantId(dependencies),
  ...createTenantMysqlAuthStoreUsershipGovernanceFindTenantUsershipByMembershipIdAndTenantId(dependencies),
  ...createTenantMysqlAuthStoreUsershipGovernanceListTenantUsersByTenantId(dependencies),
  ...createTenantMysqlAuthStoreUsershipGovernanceUpdateTenantUsershipProfile(dependencies),
  ...createTenantMysqlAuthStoreUsershipGovernanceUpdateTenantUsershipStatus(dependencies),
  ...createTenantMysqlAuthStoreUsershipGovernanceListTenantUsershipRoleBindings(dependencies),
  ...createTenantMysqlAuthStoreUsershipGovernanceReplaceTenantUsershipRoleBindingsAndSyncSnapshot(dependencies),
});

module.exports = {
  createTenantMysqlAuthStoreUsershipGovernance
};

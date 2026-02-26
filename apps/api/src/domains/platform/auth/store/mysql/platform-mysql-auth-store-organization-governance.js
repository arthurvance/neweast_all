'use strict';

const {
  createPlatformMysqlAuthStoreOrganizationGovernanceCreateOrganizationWithOwner
} = require('./platform-mysql-auth-store-organization-governance-create-organization-with-owner.js');
const {
  createPlatformMysqlAuthStoreOrganizationGovernanceFindOrganizationById
} = require('./platform-mysql-auth-store-organization-governance-find-organization-by-id.js');
const {
  createPlatformMysqlAuthStoreOrganizationGovernanceAcquireOwnerTransferLock
} = require('./platform-mysql-auth-store-organization-governance-acquire-owner-transfer-lock.js');
const {
  createPlatformMysqlAuthStoreOrganizationGovernanceReleaseOwnerTransferLock
} = require('./platform-mysql-auth-store-organization-governance-release-owner-transfer-lock.js');
const {
  createPlatformMysqlAuthStoreOrganizationGovernanceExecuteOwnerTransferTakeover
} = require('./platform-mysql-auth-store-organization-governance-execute-owner-transfer-takeover.js');
const {
  createPlatformMysqlAuthStoreOrganizationGovernanceUpdateOrganizationStatus
} = require('./platform-mysql-auth-store-organization-governance-update-organization-status.js');

const createPlatformMysqlAuthStoreOrganizationGovernance = (dependencies = {}) => ({
  ...createPlatformMysqlAuthStoreOrganizationGovernanceCreateOrganizationWithOwner(dependencies),
  ...createPlatformMysqlAuthStoreOrganizationGovernanceFindOrganizationById(dependencies),
  ...createPlatformMysqlAuthStoreOrganizationGovernanceAcquireOwnerTransferLock(dependencies),
  ...createPlatformMysqlAuthStoreOrganizationGovernanceReleaseOwnerTransferLock(dependencies),
  ...createPlatformMysqlAuthStoreOrganizationGovernanceExecuteOwnerTransferTakeover(dependencies),
  ...createPlatformMysqlAuthStoreOrganizationGovernanceUpdateOrganizationStatus(dependencies),
});

module.exports = {
  createPlatformMysqlAuthStoreOrganizationGovernance
};

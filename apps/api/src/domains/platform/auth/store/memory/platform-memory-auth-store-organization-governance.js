'use strict';

const {
  createPlatformMemoryAuthStoreOrganizationGovernanceCreateOrganizationWithOwner
} = require('./platform-memory-auth-store-organization-governance-create-organization-with-owner.js');
const {
  createPlatformMemoryAuthStoreOrganizationGovernanceFindOrganizationById
} = require('./platform-memory-auth-store-organization-governance-find-organization-by-id.js');
const {
  createPlatformMemoryAuthStoreOrganizationGovernanceAcquireOwnerTransferLock
} = require('./platform-memory-auth-store-organization-governance-acquire-owner-transfer-lock.js');
const {
  createPlatformMemoryAuthStoreOrganizationGovernanceReleaseOwnerTransferLock
} = require('./platform-memory-auth-store-organization-governance-release-owner-transfer-lock.js');
const {
  createPlatformMemoryAuthStoreOrganizationGovernanceExecuteOwnerTransferTakeover
} = require('./platform-memory-auth-store-organization-governance-execute-owner-transfer-takeover.js');
const {
  createPlatformMemoryAuthStoreOrganizationGovernanceUpdateOrganizationStatus
} = require('./platform-memory-auth-store-organization-governance-update-organization-status.js');

const createPlatformMemoryAuthStoreOrganizationGovernance = (dependencies = {}) => ({
  ...createPlatformMemoryAuthStoreOrganizationGovernanceCreateOrganizationWithOwner(dependencies),
  ...createPlatformMemoryAuthStoreOrganizationGovernanceFindOrganizationById(dependencies),
  ...createPlatformMemoryAuthStoreOrganizationGovernanceAcquireOwnerTransferLock(dependencies),
  ...createPlatformMemoryAuthStoreOrganizationGovernanceReleaseOwnerTransferLock(dependencies),
  ...createPlatformMemoryAuthStoreOrganizationGovernanceExecuteOwnerTransferTakeover(dependencies),
  ...createPlatformMemoryAuthStoreOrganizationGovernanceUpdateOrganizationStatus(dependencies),
});

module.exports = {
  createPlatformMemoryAuthStoreOrganizationGovernance
};

'use strict';

const {
  createPlatformMemoryAuthStoreIdentityGovernance
} = require('./platform-memory-auth-store-identity-governance.js');
const {
  createPlatformMemoryAuthStoreOrganizationGovernance
} = require('./platform-memory-auth-store-organization-governance.js');
const {
  createPlatformMemoryAuthStoreSystemConfigCapability
} = require('./platform-memory-auth-store-system-config-capability.js');
const {
  createPlatformMemoryAuthStoreRoleCatalog
} = require('./platform-memory-auth-store-role-catalog.js');
const {
  createPlatformMemoryAuthStoreRolePermissionSync
} = require('./platform-memory-auth-store-role-permission-sync.js');
const {
  createPlatformMemoryAuthStoreIntegrationCatalog
} = require('./platform-memory-auth-store-integration-catalog.js');
const {
  createPlatformMemoryAuthStoreIntegrationFreeze
} = require('./platform-memory-auth-store-integration-freeze.js');
const {
  createPlatformMemoryAuthStoreIntegrationContract
} = require('./platform-memory-auth-store-integration-contract.js');
const {
  createPlatformMemoryAuthStoreIntegrationRecovery
} = require('./platform-memory-auth-store-integration-recovery.js');

const createPlatformMemoryAuthStoreCapabilityComposition = (dependencies = {}) => ({
  ...createPlatformMemoryAuthStoreIdentityGovernance(dependencies),
  ...createPlatformMemoryAuthStoreOrganizationGovernance(dependencies),
  ...createPlatformMemoryAuthStoreSystemConfigCapability(dependencies),
  ...createPlatformMemoryAuthStoreRoleCatalog(dependencies),
  ...createPlatformMemoryAuthStoreRolePermissionSync(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationCatalog(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationFreeze(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationContract(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationRecovery(dependencies),
});

module.exports = {
  createPlatformMemoryAuthStoreCapabilityComposition
};

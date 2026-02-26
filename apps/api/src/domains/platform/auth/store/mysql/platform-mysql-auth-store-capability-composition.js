'use strict';

const {
  createPlatformMysqlAuthStoreIdentityGovernance
} = require('./platform-mysql-auth-store-identity-governance.js');
const {
  createPlatformMysqlAuthStoreOrganizationGovernance
} = require('./platform-mysql-auth-store-organization-governance.js');
const {
  createPlatformMysqlAuthStoreSystemConfigCapability
} = require('./platform-mysql-auth-store-system-config-capability.js');
const {
  createPlatformMysqlAuthStoreRoleCatalog
} = require('./platform-mysql-auth-store-role-catalog.js');
const {
  createPlatformMysqlAuthStoreRolePermissionSync
} = require('./platform-mysql-auth-store-role-permission-sync.js');
const {
  createPlatformMysqlAuthStoreIntegrationCatalog
} = require('./platform-mysql-auth-store-integration-catalog.js');
const {
  createPlatformMysqlAuthStoreIntegrationFreeze
} = require('./platform-mysql-auth-store-integration-freeze.js');
const {
  createPlatformMysqlAuthStoreIntegrationContract
} = require('./platform-mysql-auth-store-integration-contract.js');
const {
  createPlatformMysqlAuthStoreIntegrationRecovery
} = require('./platform-mysql-auth-store-integration-recovery.js');

const createPlatformMysqlAuthStoreCapabilityComposition = (dependencies = {}) => ({
  ...createPlatformMysqlAuthStoreIdentityGovernance(dependencies),
  ...createPlatformMysqlAuthStoreOrganizationGovernance(dependencies),
  ...createPlatformMysqlAuthStoreSystemConfigCapability(dependencies),
  ...createPlatformMysqlAuthStoreRoleCatalog(dependencies),
  ...createPlatformMysqlAuthStoreRolePermissionSync(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationCatalog(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationFreeze(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationContract(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationRecovery(dependencies),
});

module.exports = {
  createPlatformMysqlAuthStoreCapabilityComposition
};

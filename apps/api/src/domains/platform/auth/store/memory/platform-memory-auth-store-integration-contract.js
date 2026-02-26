'use strict';

const {
  createPlatformMemoryAuthStoreIntegrationContractListPlatformIntegrationContractVersions
} = require('./platform-memory-auth-store-integration-contract-list-platform-integration-contract-versions.js');
const {
  createPlatformMemoryAuthStoreIntegrationContractFindPlatformIntegrationContractVersion
} = require('./platform-memory-auth-store-integration-contract-find-platform-integration-contract-version.js');
const {
  createPlatformMemoryAuthStoreIntegrationContractFindLatestActivePlatformIntegrationContractVersion
} = require('./platform-memory-auth-store-integration-contract-find-latest-active-platform-integration-contract-version.js');
const {
  createPlatformMemoryAuthStoreIntegrationContractCreatePlatformIntegrationContractVersion
} = require('./platform-memory-auth-store-integration-contract-create-platform-integration-contract-version.js');
const {
  createPlatformMemoryAuthStoreIntegrationContractCreatePlatformIntegrationContractCompatibilityCheck
} = require('./platform-memory-auth-store-integration-contract-create-platform-integration-contract-compatibility-check.js');
const {
  createPlatformMemoryAuthStoreIntegrationContractFindLatestPlatformIntegrationContractCompatibilityCheck
} = require('./platform-memory-auth-store-integration-contract-find-latest-platform-integration-contract-compatibility-check.js');
const {
  createPlatformMemoryAuthStoreIntegrationContractActivatePlatformIntegrationContractVersion
} = require('./platform-memory-auth-store-integration-contract-activate-platform-integration-contract-version.js');

const createPlatformMemoryAuthStoreIntegrationContract = (dependencies = {}) => ({
  ...createPlatformMemoryAuthStoreIntegrationContractListPlatformIntegrationContractVersions(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationContractFindPlatformIntegrationContractVersion(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationContractFindLatestActivePlatformIntegrationContractVersion(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationContractCreatePlatformIntegrationContractVersion(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationContractCreatePlatformIntegrationContractCompatibilityCheck(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationContractFindLatestPlatformIntegrationContractCompatibilityCheck(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationContractActivatePlatformIntegrationContractVersion(dependencies),
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationContract
};

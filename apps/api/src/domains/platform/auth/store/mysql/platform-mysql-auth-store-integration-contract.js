'use strict';

const {
  createPlatformMysqlAuthStoreIntegrationContractListPlatformIntegrationContractVersions
} = require('./platform-mysql-auth-store-integration-contract-list-platform-integration-contract-versions.js');
const {
  createPlatformMysqlAuthStoreIntegrationContractFindPlatformIntegrationContractVersion
} = require('./platform-mysql-auth-store-integration-contract-find-platform-integration-contract-version.js');
const {
  createPlatformMysqlAuthStoreIntegrationContractFindLatestActivePlatformIntegrationContractVersion
} = require('./platform-mysql-auth-store-integration-contract-find-latest-active-platform-integration-contract-version.js');
const {
  createPlatformMysqlAuthStoreIntegrationContractCreatePlatformIntegrationContractVersion
} = require('./platform-mysql-auth-store-integration-contract-create-platform-integration-contract-version.js');
const {
  createPlatformMysqlAuthStoreIntegrationContractCreatePlatformIntegrationContractCompatibilityCheck
} = require('./platform-mysql-auth-store-integration-contract-create-platform-integration-contract-compatibility-check.js');
const {
  createPlatformMysqlAuthStoreIntegrationContractFindLatestPlatformIntegrationContractCompatibilityCheck
} = require('./platform-mysql-auth-store-integration-contract-find-latest-platform-integration-contract-compatibility-check.js');
const {
  createPlatformMysqlAuthStoreIntegrationContractActivatePlatformIntegrationContractVersion
} = require('./platform-mysql-auth-store-integration-contract-activate-platform-integration-contract-version.js');

const createPlatformMysqlAuthStoreIntegrationContract = (dependencies = {}) => ({
  ...createPlatformMysqlAuthStoreIntegrationContractListPlatformIntegrationContractVersions(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationContractFindPlatformIntegrationContractVersion(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationContractFindLatestActivePlatformIntegrationContractVersion(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationContractCreatePlatformIntegrationContractVersion(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationContractCreatePlatformIntegrationContractCompatibilityCheck(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationContractFindLatestPlatformIntegrationContractCompatibilityCheck(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationContractActivatePlatformIntegrationContractVersion(dependencies),
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationContract
};

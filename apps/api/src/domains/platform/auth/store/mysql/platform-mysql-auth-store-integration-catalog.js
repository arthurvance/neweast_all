'use strict';

const {
  createPlatformMysqlAuthStoreIntegrationCatalogListPlatformIntegrationCatalogEntries
} = require('./platform-mysql-auth-store-integration-catalog-list-platform-integration-catalog-entries.js');
const {
  createPlatformMysqlAuthStoreIntegrationCatalogFindPlatformIntegrationCatalogEntryByIntegrationId
} = require('./platform-mysql-auth-store-integration-catalog-find-platform-integration-catalog-entry-by-integration-id.js');
const {
  createPlatformMysqlAuthStoreIntegrationCatalogCreatePlatformIntegrationCatalogEntry
} = require('./platform-mysql-auth-store-integration-catalog-create-platform-integration-catalog-entry.js');
const {
  createPlatformMysqlAuthStoreIntegrationCatalogUpdatePlatformIntegrationCatalogEntry
} = require('./platform-mysql-auth-store-integration-catalog-update-platform-integration-catalog-entry.js');
const {
  createPlatformMysqlAuthStoreIntegrationCatalogTransitionPlatformIntegrationLifecycle
} = require('./platform-mysql-auth-store-integration-catalog-transition-platform-integration-lifecycle.js');

const createPlatformMysqlAuthStoreIntegrationCatalog = (dependencies = {}) => ({
  ...createPlatformMysqlAuthStoreIntegrationCatalogListPlatformIntegrationCatalogEntries(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationCatalogFindPlatformIntegrationCatalogEntryByIntegrationId(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationCatalogCreatePlatformIntegrationCatalogEntry(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationCatalogUpdatePlatformIntegrationCatalogEntry(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationCatalogTransitionPlatformIntegrationLifecycle(dependencies),
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationCatalog
};

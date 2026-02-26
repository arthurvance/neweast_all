'use strict';

const {
  createPlatformMemoryAuthStoreIntegrationCatalogListPlatformIntegrationCatalogEntries
} = require('./platform-memory-auth-store-integration-catalog-list-platform-integration-catalog-entries.js');
const {
  createPlatformMemoryAuthStoreIntegrationCatalogFindPlatformIntegrationCatalogEntryByIntegrationId
} = require('./platform-memory-auth-store-integration-catalog-find-platform-integration-catalog-entry-by-integration-id.js');
const {
  createPlatformMemoryAuthStoreIntegrationCatalogCreatePlatformIntegrationCatalogEntry
} = require('./platform-memory-auth-store-integration-catalog-create-platform-integration-catalog-entry.js');
const {
  createPlatformMemoryAuthStoreIntegrationCatalogUpdatePlatformIntegrationCatalogEntry
} = require('./platform-memory-auth-store-integration-catalog-update-platform-integration-catalog-entry.js');
const {
  createPlatformMemoryAuthStoreIntegrationCatalogTransitionPlatformIntegrationLifecycle
} = require('./platform-memory-auth-store-integration-catalog-transition-platform-integration-lifecycle.js');

const createPlatformMemoryAuthStoreIntegrationCatalog = (dependencies = {}) => ({
  ...createPlatformMemoryAuthStoreIntegrationCatalogListPlatformIntegrationCatalogEntries(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationCatalogFindPlatformIntegrationCatalogEntryByIntegrationId(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationCatalogCreatePlatformIntegrationCatalogEntry(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationCatalogUpdatePlatformIntegrationCatalogEntry(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationCatalogTransitionPlatformIntegrationLifecycle(dependencies),
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationCatalog
};

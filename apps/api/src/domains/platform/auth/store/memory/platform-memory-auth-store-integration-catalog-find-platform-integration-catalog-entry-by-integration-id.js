'use strict';

const createPlatformMemoryAuthStoreIntegrationCatalogFindPlatformIntegrationCatalogEntryByIntegrationId = ({
  clonePlatformIntegrationCatalogRecord,
  findPlatformIntegrationCatalogRecordStateByIntegrationId,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId
} = {}) => ({
findPlatformIntegrationCatalogEntryByIntegrationId: async ({
      integrationId
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
        return null;
      }
      const existingState = findPlatformIntegrationCatalogRecordStateByIntegrationId(
        normalizedIntegrationId
      );
      return clonePlatformIntegrationCatalogRecord(existingState?.record || null);
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationCatalogFindPlatformIntegrationCatalogEntryByIntegrationId
};

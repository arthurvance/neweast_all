'use strict';

const createPlatformMemoryAuthStoreIntegrationCatalogListPlatformIntegrationCatalogEntries = ({
  VALID_PLATFORM_INTEGRATION_DIRECTION,
  VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS,
  clonePlatformIntegrationCatalogRecord,
  normalizePlatformIntegrationDirection,
  normalizePlatformIntegrationLifecycleStatus,
  platformIntegrationCatalogById
} = {}) => ({
listPlatformIntegrationCatalogEntries: async ({
      direction = null,
      protocol = null,
      authMode = null,
      lifecycleStatus = null,
      keyword = null
    } = {}) =>
      [...platformIntegrationCatalogById.values()]
        .filter((entry) => {
          if (direction !== null && direction !== undefined) {
            const normalizedDirection = normalizePlatformIntegrationDirection(direction);
            if (!VALID_PLATFORM_INTEGRATION_DIRECTION.has(normalizedDirection)) {
              throw new Error(
                'listPlatformIntegrationCatalogEntries received unsupported direction'
              );
            }
            if (entry.direction !== normalizedDirection) {
              return false;
            }
          }
          if (lifecycleStatus !== null && lifecycleStatus !== undefined) {
            const normalizedLifecycleStatus = normalizePlatformIntegrationLifecycleStatus(
              lifecycleStatus
            );
            if (
              !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedLifecycleStatus)
            ) {
              throw new Error(
                'listPlatformIntegrationCatalogEntries received unsupported lifecycleStatus'
              );
            }
            if (entry.lifecycleStatus !== normalizedLifecycleStatus) {
              return false;
            }
          }
          if (protocol !== null && protocol !== undefined) {
            const normalizedProtocol = String(protocol || '').trim();
            if (!normalizedProtocol) {
              throw new Error(
                'listPlatformIntegrationCatalogEntries received unsupported protocol'
              );
            }
            if (entry.protocol !== normalizedProtocol) {
              return false;
            }
          }
          if (authMode !== null && authMode !== undefined) {
            const normalizedAuthMode = String(authMode || '').trim();
            if (!normalizedAuthMode) {
              throw new Error(
                'listPlatformIntegrationCatalogEntries received unsupported authMode'
              );
            }
            if (entry.authMode !== normalizedAuthMode) {
              return false;
            }
          }
          if (keyword !== null && keyword !== undefined) {
            const normalizedKeyword = String(keyword || '').trim().toLowerCase();
            if (normalizedKeyword) {
              const searchable = [
                entry.codeNormalized,
                String(entry.name || '').toLowerCase()
              ];
              if (!searchable.some((value) => String(value || '').includes(normalizedKeyword))) {
                return false;
              }
            }
          }
          return true;
        })
        .sort((left, right) => {
          const leftCreatedAt = new Date(left.createdAt).getTime();
          const rightCreatedAt = new Date(right.createdAt).getTime();
          if (leftCreatedAt !== rightCreatedAt) {
            return leftCreatedAt - rightCreatedAt;
          }
          return String(left.integrationId || '').localeCompare(
            String(right.integrationId || '')
          );
        })
        .map((entry) => clonePlatformIntegrationCatalogRecord(entry))
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationCatalogListPlatformIntegrationCatalogEntries
};

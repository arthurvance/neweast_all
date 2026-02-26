'use strict';

const createPlatformMysqlAuthStoreIntegrationCatalogFindPlatformIntegrationCatalogEntryByIntegrationId = ({
  dbClient,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  toPlatformIntegrationCatalogRecord
} = {}) => ({
findPlatformIntegrationCatalogEntryByIntegrationId: async ({
      integrationId
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT integration_id,
                 code,
                 code_normalized,
                 name,
                 direction,
                 protocol,
                 auth_mode,
                 endpoint,
                 base_url,
                 timeout_ms,
                 retry_policy,
                 idempotency_policy,
                 version_strategy,
                 runbook_url,
                 lifecycle_status,
                 lifecycle_reason,
                 created_by_user_id,
                 updated_by_user_id,
                 created_at,
                 updated_at
          FROM platform_integration_catalog
          WHERE integration_id = ?
          LIMIT 1
        `,
        [normalizedIntegrationId]
      );
      if (!Array.isArray(rows)) {
        throw new Error('findPlatformIntegrationCatalogEntryByIntegrationId result malformed');
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRecord = toPlatformIntegrationCatalogRecord(rows[0]);
      if (!normalizedRecord) {
        throw new Error('findPlatformIntegrationCatalogEntryByIntegrationId result malformed');
      }
      return normalizedRecord;
    }
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationCatalogFindPlatformIntegrationCatalogEntryByIntegrationId
};

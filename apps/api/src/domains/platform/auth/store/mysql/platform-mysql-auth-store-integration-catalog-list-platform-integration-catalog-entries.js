'use strict';

const createPlatformMysqlAuthStoreIntegrationCatalogListPlatformIntegrationCatalogEntries = ({
  VALID_PLATFORM_INTEGRATION_DIRECTION,
  VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS,
  dbClient,
  escapeSqlLikePattern,
  normalizePlatformIntegrationDirection,
  normalizePlatformIntegrationLifecycleStatus,
  toPlatformIntegrationCatalogRecord
} = {}) => ({
listPlatformIntegrationCatalogEntries: async ({
      direction = null,
      protocol = null,
      authMode = null,
      lifecycleStatus = null,
      keyword = null
    } = {}) => {
      const whereClauses = [];
      const queryArgs = [];
      if (direction !== null && direction !== undefined) {
        const normalizedDirection = normalizePlatformIntegrationDirection(direction);
        if (!VALID_PLATFORM_INTEGRATION_DIRECTION.has(normalizedDirection)) {
          throw new Error('listPlatformIntegrationCatalogEntries received unsupported direction');
        }
        whereClauses.push('direction = ?');
        queryArgs.push(normalizedDirection);
      }
      if (lifecycleStatus !== null && lifecycleStatus !== undefined) {
        const normalizedLifecycleStatus = normalizePlatformIntegrationLifecycleStatus(
          lifecycleStatus
        );
        if (!VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedLifecycleStatus)) {
          throw new Error(
            'listPlatformIntegrationCatalogEntries received unsupported lifecycleStatus'
          );
        }
        whereClauses.push('lifecycle_status = ?');
        queryArgs.push(normalizedLifecycleStatus);
      }
      if (protocol !== null && protocol !== undefined) {
        const normalizedProtocol = String(protocol || '').trim();
        if (!normalizedProtocol) {
          throw new Error('listPlatformIntegrationCatalogEntries received unsupported protocol');
        }
        whereClauses.push('protocol = ?');
        queryArgs.push(normalizedProtocol);
      }
      if (authMode !== null && authMode !== undefined) {
        const normalizedAuthMode = String(authMode || '').trim();
        if (!normalizedAuthMode) {
          throw new Error('listPlatformIntegrationCatalogEntries received unsupported authMode');
        }
        whereClauses.push('auth_mode = ?');
        queryArgs.push(normalizedAuthMode);
      }
      if (keyword !== null && keyword !== undefined) {
        const normalizedKeyword = String(keyword || '').trim();
        if (normalizedKeyword) {
          const keywordLike = `%${escapeSqlLikePattern(
            normalizedKeyword.toLowerCase()
          )}%`;
          whereClauses.push(
            "(code_normalized LIKE ? ESCAPE '\\\\' OR LOWER(name) LIKE ? ESCAPE '\\\\')"
          );
          queryArgs.push(keywordLike, keywordLike);
        }
      }
      const whereSql = whereClauses.length > 0
        ? `WHERE ${whereClauses.join(' AND ')}`
        : '';
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
          ${whereSql}
          ORDER BY created_at ASC, integration_id ASC
        `,
        queryArgs
      );
      if (!Array.isArray(rows)) {
        throw new Error('listPlatformIntegrationCatalogEntries result malformed');
      }
      const normalizedRows = rows.map((row) => toPlatformIntegrationCatalogRecord(row));
      if (normalizedRows.some((row) => !row)) {
        throw new Error('listPlatformIntegrationCatalogEntries result malformed');
      }
      return normalizedRows;
    }
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationCatalogListPlatformIntegrationCatalogEntries
};

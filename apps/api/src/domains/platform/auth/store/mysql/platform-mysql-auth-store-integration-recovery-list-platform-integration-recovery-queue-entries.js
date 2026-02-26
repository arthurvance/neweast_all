'use strict';

const createPlatformMysqlAuthStoreIntegrationRecoveryListPlatformIntegrationRecoveryQueueEntries = ({
  MAX_PLATFORM_INTEGRATION_RECOVERY_LIST_LIMIT,
  VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS,
  dbClient,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationRecoveryStatus,
  toPlatformIntegrationRecoveryQueueRecord
} = {}) => ({
listPlatformIntegrationRecoveryQueueEntries: async ({
      integrationId,
      status = null,
      limit = 50
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      const normalizedStatus = status === null || status === undefined
        ? null
        : normalizePlatformIntegrationRecoveryStatus(status);
      const normalizedLimit = Number(limit);
      if (
        !isValidPlatformIntegrationId(normalizedIntegrationId)
        || (
          normalizedStatus !== null
          && !VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS.has(normalizedStatus)
        )
        || !Number.isInteger(normalizedLimit)
        || normalizedLimit < 1
        || normalizedLimit > MAX_PLATFORM_INTEGRATION_RECOVERY_LIST_LIMIT
      ) {
        throw new Error('listPlatformIntegrationRecoveryQueueEntries received invalid input');
      }
      const whereClauses = ['integration_id = ?'];
      const queryArgs = [normalizedIntegrationId];
      if (normalizedStatus !== null) {
        whereClauses.push('status = ?');
        queryArgs.push(normalizedStatus);
      }
      queryArgs.push(normalizedLimit);
      const rows = await dbClient.query(
        `
          SELECT recovery_id,
                 integration_id,
                 contract_type,
                 contract_version,
                 request_id,
                 traceparent,
                 idempotency_key,
                 attempt_count,
                 max_attempts,
                 next_retry_at,
                 last_attempt_at,
                 status,
                 failure_code,
                 failure_detail,
                 last_http_status,
                 retryable,
                 payload_snapshot,
                 response_snapshot,
                 created_by_user_id,
                 updated_by_user_id,
                 created_at,
                 updated_at
          FROM platform_integration_retry_recovery_queue
          WHERE ${whereClauses.join(' AND ')}
          ORDER BY created_at DESC, recovery_id DESC
          LIMIT ?
        `,
        queryArgs
      );
      if (!Array.isArray(rows)) {
        throw new Error('listPlatformIntegrationRecoveryQueueEntries result malformed');
      }
      const normalizedRows = rows.map((row) =>
        toPlatformIntegrationRecoveryQueueRecord(row)
      );
      if (normalizedRows.some((row) => !row)) {
        throw new Error('listPlatformIntegrationRecoveryQueueEntries result malformed');
      }
      return normalizedRows;
    }
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationRecoveryListPlatformIntegrationRecoveryQueueEntries
};

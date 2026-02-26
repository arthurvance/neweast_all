'use strict';

const createPlatformMysqlAuthStoreIntegrationRecoveryFindPlatformIntegrationRecoveryQueueEntryByRecoveryId = ({
  MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH,
  dbClient,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationRecoveryId,
  toPlatformIntegrationRecoveryQueueRecord
} = {}) => ({
findPlatformIntegrationRecoveryQueueEntryByRecoveryId: async ({
      integrationId,
      recoveryId
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(recoveryId);
      if (
        !isValidPlatformIntegrationId(normalizedIntegrationId)
        || !normalizedRecoveryId
        || normalizedRecoveryId.length > MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH
      ) {
        return null;
      }
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
          WHERE integration_id = ?
            AND recovery_id = ?
          LIMIT 1
        `,
        [
          normalizedIntegrationId,
          normalizedRecoveryId
        ]
      );
      if (!Array.isArray(rows)) {
        throw new Error('findPlatformIntegrationRecoveryQueueEntryByRecoveryId result malformed');
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRecord = toPlatformIntegrationRecoveryQueueRecord(rows[0]);
      if (!normalizedRecord) {
        throw new Error('findPlatformIntegrationRecoveryQueueEntryByRecoveryId result malformed');
      }
      return normalizedRecord;
    }
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationRecoveryFindPlatformIntegrationRecoveryQueueEntryByRecoveryId
};

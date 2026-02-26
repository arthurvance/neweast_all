'use strict';

const createPlatformMysqlAuthStoreIntegrationRecoveryReplayPlatformIntegrationRecoveryQueueEntry = ({
  MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_REASON_LENGTH,
  createPlatformIntegrationRecoveryReplayConflictError,
  dbClient,
  executeWithDeadlockRetry,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationOptionalText,
  normalizePlatformIntegrationRecoveryId,
  recordAuditEventWithQueryClient,
  toPlatformIntegrationRecoveryQueueRecord
} = {}) => ({
replayPlatformIntegrationRecoveryQueueEntry: async ({
      integrationId,
      recoveryId,
      reason = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'replayPlatformIntegrationRecoveryQueueEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(recoveryId);
            const normalizedReason = normalizePlatformIntegrationOptionalText(reason);
            const normalizedOperatorUserId = normalizePlatformIntegrationOptionalText(
              operatorUserId
            );
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !normalizedRecoveryId
              || normalizedRecoveryId.length > MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH
              || (
                normalizedReason !== null
                && normalizedReason.length > MAX_PLATFORM_INTEGRATION_RECOVERY_REASON_LENGTH
              )
            ) {
              throw new Error('replayPlatformIntegrationRecoveryQueueEntry received invalid input');
            }
            const existingRows = await tx.query(
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
                FOR UPDATE
              `,
              [
                normalizedIntegrationId,
                normalizedRecoveryId
              ]
            );
            if (!Array.isArray(existingRows)) {
              throw new Error(
                'replayPlatformIntegrationRecoveryQueueEntry existing query malformed'
              );
            }
            if (existingRows.length === 0) {
              return null;
            }
            const existingRecord = toPlatformIntegrationRecoveryQueueRecord(
              existingRows[0]
            );
            if (!existingRecord) {
              throw new Error(
                'replayPlatformIntegrationRecoveryQueueEntry existing row malformed'
              );
            }
            if (
              existingRecord.status !== 'failed'
              && existingRecord.status !== 'dlq'
            ) {
              throw createPlatformIntegrationRecoveryReplayConflictError({
                integrationId: normalizedIntegrationId,
                recoveryId: normalizedRecoveryId,
                previousStatus: existingRecord.status,
                requestedStatus: 'replayed'
              });
            }
            await tx.query(
              `
                UPDATE platform_integration_retry_recovery_queue
                SET status = 'replayed',
                    attempt_count = 0,
                    next_retry_at = CURRENT_TIMESTAMP(3),
                    last_attempt_at = NULL,
                    failure_code = NULL,
                    failure_detail = NULL,
                    last_http_status = NULL,
                    retryable = 1,
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE integration_id = ?
                  AND recovery_id = ?
              `,
              [
                normalizedOperatorUserId,
                normalizedIntegrationId,
                normalizedRecoveryId
              ]
            );
            const updatedRows = await tx.query(
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
            const updatedRecord = toPlatformIntegrationRecoveryQueueRecord(
              updatedRows?.[0] || null
            );
            if (!updatedRecord) {
              throw new Error(
                'replayPlatformIntegrationRecoveryQueueEntry result unavailable'
              );
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.recovery.replayed',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_recovery',
                  targetId: normalizedRecoveryId,
                  result: 'success',
                  beforeState: {
                    status: existingRecord.status
                  },
                  afterState: {
                    status: updatedRecord.status,
                    reason: normalizedReason
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration recovery replay audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...updatedRecord,
              previousStatus: existingRecord.status,
              currentStatus: updatedRecord.status,
              reason: normalizedReason,
              auditRecorded
            };
          })
      })
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationRecoveryReplayPlatformIntegrationRecoveryQueueEntry
};

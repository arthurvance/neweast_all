'use strict';

const createPlatformMysqlAuthStoreIntegrationRecoveryCompletePlatformIntegrationRecoveryQueueAttempt = ({
  MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH,
  computeRetrySchedule,
  dbClient,
  executeWithDeadlockRetry,
  isPlatformIntegrationRecoveryFailureRetryable,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationJsonForStorage,
  normalizePlatformIntegrationOptionalText,
  normalizePlatformIntegrationRecoveryId,
  recordAuditEventWithQueryClient,
  toPlatformIntegrationRecoveryQueueRecord
} = {}) => ({
completePlatformIntegrationRecoveryQueueAttempt: async ({
      integrationId,
      recoveryId,
      succeeded = false,
      retryable = true,
      nextRetryAt = null,
      failureCode = null,
      failureDetail = null,
      lastHttpStatus = null,
      responseSnapshot = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'completePlatformIntegrationRecoveryQueueAttempt',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(recoveryId);
            const normalizedFailureCode = normalizePlatformIntegrationOptionalText(failureCode);
            const normalizedFailureDetail = normalizePlatformIntegrationOptionalText(
              failureDetail
            );
            const normalizedLastHttpStatus = lastHttpStatus === null || lastHttpStatus === undefined
              ? null
              : Number(lastHttpStatus);
            const normalizedResponseSnapshot = normalizePlatformIntegrationJsonForStorage({
              value: responseSnapshot
            });
            const normalizedNextRetryAt = nextRetryAt === null || nextRetryAt === undefined
              ? null
              : new Date(nextRetryAt).toISOString();
            const normalizedOperatorUserId = normalizePlatformIntegrationOptionalText(
              operatorUserId
            );
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !normalizedRecoveryId
              || normalizedRecoveryId.length > MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH
              || (
                normalizedFailureCode !== null
                && normalizedFailureCode.length > MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH
              )
              || (
                normalizedFailureDetail !== null
                && normalizedFailureDetail.length > MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH
              )
              || (
                normalizedLastHttpStatus !== null
                && (
                  !Number.isInteger(normalizedLastHttpStatus)
                  || normalizedLastHttpStatus < 100
                  || normalizedLastHttpStatus > 599
                )
              )
              || normalizedResponseSnapshot === undefined
              || (
                normalizedNextRetryAt !== null
                && Number.isNaN(new Date(normalizedNextRetryAt).getTime())
              )
            ) {
              throw new Error(
                'completePlatformIntegrationRecoveryQueueAttempt received invalid input'
              );
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
                'completePlatformIntegrationRecoveryQueueAttempt existing query malformed'
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
                'completePlatformIntegrationRecoveryQueueAttempt existing row malformed'
              );
            }
            let nextStatus = 'succeeded';
            let persistedRetryable = false;
            let persistedFailureCode = null;
            let persistedFailureDetail = null;
            let persistedLastHttpStatus = null;
            let persistedNextRetryAt = null;
            const completionNowIso = new Date().toISOString();
            if (!succeeded) {
              persistedRetryable = isPlatformIntegrationRecoveryFailureRetryable({
                retryable,
                lastHttpStatus: normalizedLastHttpStatus,
                failureCode: normalizedFailureCode,
                responseSnapshot: normalizedResponseSnapshot
              });
              persistedFailureCode = normalizedFailureCode;
              persistedFailureDetail = normalizedFailureDetail;
              persistedLastHttpStatus = normalizedLastHttpStatus;
              const retrySchedule = persistedRetryable
                ? computeRetrySchedule({
                  attemptCount: existingRecord.attemptCount,
                  maxAttempts: existingRecord.maxAttempts,
                  now: completionNowIso
                })
                : {
                  exhausted: true,
                  nextRetryAt: null
                };
              nextStatus = retrySchedule.exhausted ? 'dlq' : 'pending';
              persistedNextRetryAt = retrySchedule.exhausted
                ? null
                : (normalizedNextRetryAt || retrySchedule.nextRetryAt || completionNowIso);
            }
            await tx.query(
              `
                UPDATE platform_integration_retry_recovery_queue
                SET status = ?,
                    next_retry_at = ?,
                    failure_code = ?,
                    failure_detail = ?,
                    last_http_status = ?,
                    retryable = ?,
                    response_snapshot = CAST(? AS JSON),
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE integration_id = ?
                  AND recovery_id = ?
              `,
              [
                nextStatus,
                persistedNextRetryAt,
                persistedFailureCode,
                persistedFailureDetail,
                persistedLastHttpStatus,
                persistedRetryable ? 1 : 0,
                normalizedResponseSnapshot,
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
                'completePlatformIntegrationRecoveryQueueAttempt result unavailable'
              );
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              const emitAuditEvent = async (eventType) =>
                recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType,
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_recovery',
                  targetId: normalizedRecoveryId,
                  result: updatedRecord.status === 'succeeded' ? 'success' : 'failed',
                  beforeState: {
                    status: existingRecord.status
                  },
                  afterState: {
                    status: updatedRecord.status,
                    attempt_count: updatedRecord.attemptCount,
                    next_retry_at: updatedRecord.nextRetryAt
                  }
                });
              try {
                if (updatedRecord.status === 'succeeded') {
                  await emitAuditEvent('platform.integration.recovery.reprocess_succeeded');
                } else {
                  await emitAuditEvent('platform.integration.recovery.reprocess_failed');
                  if (updatedRecord.status === 'dlq') {
                    await emitAuditEvent('platform.integration.recovery.retry_exhausted');
                  }
                }
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration recovery completion audit write failed'
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
              exhausted: updatedRecord.status === 'dlq',
              auditRecorded
            };
          })
      })
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationRecoveryCompletePlatformIntegrationRecoveryQueueAttempt
};

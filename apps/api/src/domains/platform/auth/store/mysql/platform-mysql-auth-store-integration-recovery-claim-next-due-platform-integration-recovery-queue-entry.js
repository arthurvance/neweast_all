'use strict';

const createPlatformMysqlAuthStoreIntegrationRecoveryClaimNextDuePlatformIntegrationRecoveryQueueEntry = ({
  DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS,
  buildSqlInPlaceholders,
  dbClient,
  executeWithDeadlockRetry,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationOptionalText,
  recordAuditEventWithQueryClient,
  toPlatformIntegrationRecoveryQueueRecord
} = {}) => ({
claimNextDuePlatformIntegrationRecoveryQueueEntry: async ({
      integrationId = null,
      now = new Date().toISOString(),
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'claimNextDuePlatformIntegrationRecoveryQueueEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedNow = new Date(now);
            if (Number.isNaN(normalizedNow.getTime())) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry received invalid now'
              );
            }
            const normalizedNowIso = normalizedNow.toISOString();
            const staleRetryingThresholdIso = new Date(
              normalizedNow.getTime() - DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS
            ).toISOString();
            const claimLeaseExpiresAtIso = new Date(
              normalizedNow.getTime() + DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS
            ).toISOString();
            const normalizedOperatorUserId = normalizePlatformIntegrationOptionalText(
              operatorUserId
            );
            const normalizedOperatorSessionId = normalizePlatformIntegrationOptionalText(
              operatorSessionId
            );
            const normalizedAuditContext = auditContext && typeof auditContext === 'object'
              ? auditContext
              : null;
            const auditRequestId = String(normalizedAuditContext?.requestId || '').trim()
              || 'request_id_unset';
            const auditTraceparent = normalizedAuditContext?.traceparent || null;
            const auditActorUserId = normalizePlatformIntegrationOptionalText(
              normalizedAuditContext?.actorUserId || normalizedOperatorUserId
            );
            const auditActorSessionId = normalizePlatformIntegrationOptionalText(
              normalizedAuditContext?.actorSessionId || normalizedOperatorSessionId
            );
            const normalizedIntegrationId = integrationId === null || integrationId === undefined
              ? null
              : normalizePlatformIntegrationId(integrationId);
            if (
              normalizedIntegrationId !== null
              && !isValidPlatformIntegrationId(normalizedIntegrationId)
            ) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry received invalid integrationId'
              );
            }
            const staleRetryingWhereClauses = [
              "status = 'retrying'",
              'attempt_count >= max_attempts',
              `(
                (next_retry_at IS NOT NULL AND next_retry_at <= ?)
                OR (
                  next_retry_at IS NULL
                  AND (last_attempt_at IS NULL OR last_attempt_at <= ?)
                )
              )`
            ];
            const staleRetryingArgs = [
              normalizedNowIso,
              staleRetryingThresholdIso
            ];
            if (normalizedIntegrationId !== null) {
              staleRetryingWhereClauses.push('integration_id = ?');
              staleRetryingArgs.push(normalizedIntegrationId);
            }
            const staleRetryingRows = await tx.query(
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
                WHERE ${staleRetryingWhereClauses.join(' AND ')}
                FOR UPDATE SKIP LOCKED
              `,
              staleRetryingArgs
            );
            if (!Array.isArray(staleRetryingRows)) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry stale retrying query malformed'
              );
            }
            const staleRetryingRecords = staleRetryingRows.map((row) =>
              toPlatformIntegrationRecoveryQueueRecord(row)
            );
            if (staleRetryingRecords.some((record) => !record)) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry stale retrying row malformed'
              );
            }
            if (staleRetryingRecords.length > 0) {
              const staleRecoveryIds = staleRetryingRecords.map((record) => record.recoveryId);
              await tx.query(
                `
                  UPDATE platform_integration_retry_recovery_queue
                  SET status = 'dlq',
                      next_retry_at = NULL,
                      updated_by_user_id = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE recovery_id IN (${buildSqlInPlaceholders(staleRecoveryIds.length)})
                `,
                [
                  normalizedOperatorUserId,
                  ...staleRecoveryIds
                ]
              );
              try {
                for (const staleRecord of staleRetryingRecords) {
                  await recordAuditEventWithQueryClient({
                    queryClient: tx,
                    domain: 'platform',
                    requestId: auditRequestId,
                    traceparent: auditTraceparent,
                    eventType: 'platform.integration.recovery.retry_exhausted',
                    actorUserId: auditActorUserId,
                    actorSessionId: auditActorSessionId,
                    targetType: 'integration_recovery',
                    targetId: staleRecord.recoveryId,
                    result: 'failed',
                    beforeState: {
                      status: staleRecord.status,
                      attempt_count: staleRecord.attemptCount,
                      max_attempts: staleRecord.maxAttempts,
                      next_retry_at: staleRecord.nextRetryAt,
                      last_attempt_at: staleRecord.lastAttemptAt
                    },
                    afterState: {
                      status: 'dlq',
                      attempt_count: staleRecord.attemptCount,
                      max_attempts: staleRecord.maxAttempts,
                      next_retry_at: null,
                      last_attempt_at: staleRecord.lastAttemptAt
                    },
                    metadata: {
                      exhausted_by: 'stale-retrying-claim-sweep'
                    }
                  });
                }
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration recovery claim sweep audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            const whereClauses = [
              'attempt_count < max_attempts',
              `(
                (status IN ('pending', 'replayed') AND (next_retry_at IS NULL OR next_retry_at <= ?))
                OR (
                  status = 'retrying'
                  AND (
                    (next_retry_at IS NOT NULL AND next_retry_at <= ?)
                    OR (
                      next_retry_at IS NULL
                      AND (last_attempt_at IS NULL OR last_attempt_at <= ?)
                    )
                  )
                )
              )`
            ];
            const queryArgs = [
              normalizedNowIso,
              normalizedNowIso,
              staleRetryingThresholdIso
            ];
            if (normalizedIntegrationId !== null) {
              whereClauses.push('integration_id = ?');
              queryArgs.push(normalizedIntegrationId);
            }
            const candidateRows = await tx.query(
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
                ORDER BY COALESCE(next_retry_at, created_at) ASC, created_at ASC, recovery_id ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
              `,
              queryArgs
            );
            if (!Array.isArray(candidateRows)) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry candidate query malformed'
              );
            }
            if (candidateRows.length === 0) {
              return null;
            }
            const candidateRecord = toPlatformIntegrationRecoveryQueueRecord(
              candidateRows[0]
            );
            if (!candidateRecord) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry candidate row malformed'
              );
            }
            const nextAttemptCount = Math.min(
              candidateRecord.maxAttempts,
              candidateRecord.attemptCount + 1
            );
            await tx.query(
              `
                UPDATE platform_integration_retry_recovery_queue
                SET status = 'retrying',
                    attempt_count = ?,
                    next_retry_at = ?,
                    last_attempt_at = ?,
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE recovery_id = ?
              `,
              [
                nextAttemptCount,
                claimLeaseExpiresAtIso,
                normalizedNowIso,
                normalizedOperatorUserId,
                candidateRecord.recoveryId
              ]
            );
            const claimedRows = await tx.query(
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
                WHERE recovery_id = ?
                LIMIT 1
              `,
              [candidateRecord.recoveryId]
            );
            const claimedRecord = toPlatformIntegrationRecoveryQueueRecord(
              claimedRows?.[0] || null
            );
            if (!claimedRecord) {
              throw new Error(
                'claimNextDuePlatformIntegrationRecoveryQueueEntry result unavailable'
              );
            }
            return {
              ...claimedRecord,
              previousStatus: candidateRecord.status,
              currentStatus: claimedRecord.status
            };
          })
      })
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationRecoveryClaimNextDuePlatformIntegrationRecoveryQueueEntry
};

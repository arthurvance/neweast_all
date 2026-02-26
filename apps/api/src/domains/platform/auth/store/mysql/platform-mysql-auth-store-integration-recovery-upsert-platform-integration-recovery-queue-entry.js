'use strict';

const createPlatformMysqlAuthStoreIntegrationRecoveryUpsertPlatformIntegrationRecoveryQueueEntry = ({
  MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS,
  dbClient,
  executeWithDeadlockRetry,
  isDuplicateEntryError,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationJsonForStorage,
  normalizePlatformIntegrationOptionalText,
  normalizePlatformIntegrationRecoveryId,
  normalizePlatformIntegrationRecoveryIdempotencyKey,
  normalizePlatformIntegrationRecoveryStatus,
  randomUUID,
  recordAuditEventWithQueryClient,
  toPlatformIntegrationRecoveryQueueRecord
} = {}) => ({
upsertPlatformIntegrationRecoveryQueueEntry: async ({
      recoveryId = randomUUID(),
      integrationId,
      contractType,
      contractVersion,
      requestId,
      traceparent = null,
      idempotencyKey = '',
      attemptCount = 0,
      maxAttempts = 5,
      nextRetryAt = null,
      lastAttemptAt = null,
      status = 'pending',
      failureCode = null,
      failureDetail = null,
      lastHttpStatus = null,
      retryable = true,
      payloadSnapshot,
      responseSnapshot = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'upsertPlatformIntegrationRecoveryQueueEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(recoveryId);
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedContractType =
              normalizePlatformIntegrationContractType(contractType);
            const normalizedContractVersion =
              normalizePlatformIntegrationContractVersion(contractVersion);
            const normalizedRequestId = String(requestId || '').trim();
            const normalizedTraceparent =
              normalizePlatformIntegrationOptionalText(traceparent);
            const normalizedIdempotencyKey =
              normalizePlatformIntegrationRecoveryIdempotencyKey(idempotencyKey);
            const normalizedAttemptCount = Number(attemptCount);
            const normalizedMaxAttempts = Number(maxAttempts);
            const normalizedNextRetryAt = nextRetryAt === null || nextRetryAt === undefined
              ? null
              : new Date(nextRetryAt).toISOString();
            const normalizedLastAttemptAt = lastAttemptAt === null || lastAttemptAt === undefined
              ? null
              : new Date(lastAttemptAt).toISOString();
            const normalizedStatus = normalizePlatformIntegrationRecoveryStatus(status);
            const normalizedFailureCode = normalizePlatformIntegrationOptionalText(failureCode);
            const normalizedFailureDetail = normalizePlatformIntegrationOptionalText(
              failureDetail
            );
            const normalizedLastHttpStatus = lastHttpStatus === null || lastHttpStatus === undefined
              ? null
              : Number(lastHttpStatus);
            const normalizedPayloadSnapshot = normalizePlatformIntegrationJsonForStorage({
              value: payloadSnapshot
            });
            const normalizedResponseSnapshot = normalizePlatformIntegrationJsonForStorage({
              value: responseSnapshot
            });
            const normalizedOperatorUserId = normalizePlatformIntegrationOptionalText(
              operatorUserId
            );
            if (
              !normalizedRecoveryId
              || normalizedRecoveryId.length > MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH
              || !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
              || !normalizedContractVersion
              || normalizedContractVersion.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
              || !normalizedRequestId
              || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
              || (
                normalizedTraceparent !== null
                && normalizedTraceparent.length > MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH
              )
              || normalizedIdempotencyKey.length
                > MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH
              || !Number.isInteger(normalizedAttemptCount)
              || normalizedAttemptCount < 0
              || !Number.isInteger(normalizedMaxAttempts)
              || normalizedMaxAttempts < 1
              || normalizedMaxAttempts > 5
              || (
                normalizedNextRetryAt !== null
                && Number.isNaN(new Date(normalizedNextRetryAt).getTime())
              )
              || (
                normalizedLastAttemptAt !== null
                && Number.isNaN(new Date(normalizedLastAttemptAt).getTime())
              )
              || !VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS.has(normalizedStatus)
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
              || normalizedPayloadSnapshot === null
              || normalizedPayloadSnapshot === undefined
              || normalizedResponseSnapshot === undefined
            ) {
              throw new Error('upsertPlatformIntegrationRecoveryQueueEntry received invalid input');
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
                  AND contract_type = ?
                  AND contract_version = ?
                  AND request_id = ?
                  AND idempotency_key = ?
                LIMIT 1
                FOR UPDATE
              `,
              [
                normalizedIntegrationId,
                normalizedContractType,
                normalizedContractVersion,
                normalizedRequestId,
                normalizedIdempotencyKey
              ]
            );
            if (!Array.isArray(existingRows)) {
              throw new Error(
                'upsertPlatformIntegrationRecoveryQueueEntry existing query malformed'
              );
            }
            const existingRecord = existingRows.length > 0
              ? toPlatformIntegrationRecoveryQueueRecord(existingRows[0])
              : null;
            if (existingRows.length > 0 && !existingRecord) {
              throw new Error(
                'upsertPlatformIntegrationRecoveryQueueEntry existing row malformed'
              );
            }
            if (
              existingRecord
              && (
                existingRecord.status === 'succeeded'
                || existingRecord.status === 'replayed'
              )
            ) {
              return {
                ...existingRecord,
                inserted: false,
                auditRecorded: false
              };
            }
            let persistedRecoveryId = existingRecord?.recoveryId || normalizedRecoveryId;
            if (!existingRecord) {
              try {
                await tx.query(
                  `
                    INSERT INTO platform_integration_retry_recovery_queue (
                      recovery_id,
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
                      updated_by_user_id
                    )
                    VALUES (
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), CAST(? AS JSON), ?, ?
                    )
                  `,
                  [
                    persistedRecoveryId,
                    normalizedIntegrationId,
                    normalizedContractType,
                    normalizedContractVersion,
                    normalizedRequestId,
                    normalizedTraceparent,
                    normalizedIdempotencyKey,
                    normalizedAttemptCount,
                    normalizedMaxAttempts,
                    normalizedNextRetryAt,
                    normalizedLastAttemptAt,
                    normalizedStatus,
                    normalizedFailureCode,
                    normalizedFailureDetail,
                    normalizedLastHttpStatus,
                    retryable ? 1 : 0,
                    normalizedPayloadSnapshot,
                    normalizedResponseSnapshot,
                    normalizedOperatorUserId,
                    normalizedOperatorUserId
                  ]
                );
              } catch (error) {
                if (!isDuplicateEntryError(error)) {
                  throw error;
                }
              }
            }
            await tx.query(
              `
                UPDATE platform_integration_retry_recovery_queue
                SET attempt_count = ?,
                    max_attempts = ?,
                    next_retry_at = ?,
                    last_attempt_at = ?,
                    status = CASE
                      WHEN status IN ('succeeded', 'replayed') THEN status
                      ELSE ?
                    END,
                    failure_code = ?,
                    failure_detail = ?,
                    last_http_status = ?,
                    retryable = ?,
                    payload_snapshot = CAST(? AS JSON),
                    response_snapshot = CAST(? AS JSON),
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE integration_id = ?
                  AND contract_type = ?
                  AND contract_version = ?
                  AND request_id = ?
                  AND idempotency_key = ?
              `,
              [
                normalizedAttemptCount,
                normalizedMaxAttempts,
                normalizedNextRetryAt,
                normalizedLastAttemptAt,
                normalizedStatus,
                normalizedFailureCode,
                normalizedFailureDetail,
                normalizedLastHttpStatus,
                retryable ? 1 : 0,
                normalizedPayloadSnapshot,
                normalizedResponseSnapshot,
                normalizedOperatorUserId,
                normalizedIntegrationId,
                normalizedContractType,
                normalizedContractVersion,
                normalizedRequestId,
                normalizedIdempotencyKey
              ]
            );
            const persistedRows = await tx.query(
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
                  AND contract_type = ?
                  AND contract_version = ?
                  AND request_id = ?
                  AND idempotency_key = ?
                LIMIT 1
              `,
              [
                normalizedIntegrationId,
                normalizedContractType,
                normalizedContractVersion,
                normalizedRequestId,
                normalizedIdempotencyKey
              ]
            );
            const persistedRecord = toPlatformIntegrationRecoveryQueueRecord(
              persistedRows?.[0] || null
            );
            if (!persistedRecord) {
              throw new Error('upsertPlatformIntegrationRecoveryQueueEntry result unavailable');
            }
            persistedRecoveryId = persistedRecord.recoveryId;
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.recovery.retry_scheduled',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_recovery',
                  targetId: persistedRecoveryId,
                  result: 'success',
                  beforeState: existingRecord
                    ? {
                      status: existingRecord.status,
                      attempt_count: existingRecord.attemptCount,
                      next_retry_at: existingRecord.nextRetryAt
                    }
                    : null,
                  afterState: {
                    status: persistedRecord.status,
                    attempt_count: persistedRecord.attemptCount,
                    next_retry_at: persistedRecord.nextRetryAt
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration recovery schedule audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...persistedRecord,
              inserted: !existingRecord,
              auditRecorded
            };
          })
      })
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationRecoveryUpsertPlatformIntegrationRecoveryQueueEntry
};

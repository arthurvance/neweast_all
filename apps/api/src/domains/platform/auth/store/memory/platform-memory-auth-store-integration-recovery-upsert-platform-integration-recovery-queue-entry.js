'use strict';

const createPlatformMemoryAuthStoreIntegrationRecoveryUpsertPlatformIntegrationRecoveryQueueEntry = ({
  MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS,
  auditEvents,
  clonePlatformIntegrationRecoveryQueueRecord,
  findPlatformIntegrationCatalogRecordStateByIntegrationId,
  findPlatformIntegrationRecoveryQueueRecordStateByDedupKey,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationJsonForStorage,
  normalizePlatformIntegrationOptionalText,
  normalizePlatformIntegrationRecoveryId,
  normalizePlatformIntegrationRecoveryIdempotencyKey,
  normalizePlatformIntegrationRecoveryStatus,
  persistAuditEvent,
  platformIntegrationRecoveryDedupIndex,
  platformIntegrationRecoveryQueueByRecoveryId,
  randomUUID,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  upsertPlatformIntegrationRecoveryQueueRecord
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
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationRecoveryQueueByRecoveryId: structuredClone(
            platformIntegrationRecoveryQueueByRecoveryId
          ),
          platformIntegrationRecoveryDedupIndex: structuredClone(
            platformIntegrationRecoveryDedupIndex
          ),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(recoveryId);
        const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
        const normalizedContractType =
          normalizePlatformIntegrationContractType(contractType);
        const normalizedContractVersion =
          normalizePlatformIntegrationContractVersion(contractVersion);
        const normalizedRequestId = String(requestId || '').trim();
        const normalizedTraceparent = normalizePlatformIntegrationOptionalText(traceparent);
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
          || !findPlatformIntegrationCatalogRecordStateByIntegrationId(
            normalizedIntegrationId
          )
          || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
          || !normalizedContractVersion
          || normalizedContractVersion.length
            > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
          || !normalizedRequestId
          || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
          || (
            normalizedTraceparent !== null
            && normalizedTraceparent.length
              > MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH
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
        const existingState = findPlatformIntegrationRecoveryQueueRecordStateByDedupKey({
          integrationId: normalizedIntegrationId,
          contractType: normalizedContractType,
          contractVersion: normalizedContractVersion,
          requestId: normalizedRequestId,
          idempotencyKey: normalizedIdempotencyKey
        });
        const existingRecord = existingState?.record || null;
        if (
          existingRecord
          && (
            existingRecord.status === 'succeeded'
            || existingRecord.status === 'replayed'
          )
        ) {
          return {
            ...clonePlatformIntegrationRecoveryQueueRecord(existingRecord),
            inserted: false,
            auditRecorded: false
          };
        }
        const persistedRecord = upsertPlatformIntegrationRecoveryQueueRecord({
          entry: {
            recoveryId: normalizedRecoveryId,
            integrationId: normalizedIntegrationId,
            contractType: normalizedContractType,
            contractVersion: normalizedContractVersion,
            requestId: normalizedRequestId,
            traceparent: normalizedTraceparent,
            idempotencyKey: normalizedIdempotencyKey,
            attemptCount: normalizedAttemptCount,
            maxAttempts: normalizedMaxAttempts,
            nextRetryAt: normalizedNextRetryAt,
            lastAttemptAt: normalizedLastAttemptAt,
            status: normalizedStatus,
            failureCode: normalizedFailureCode,
            failureDetail: normalizedFailureDetail,
            lastHttpStatus: normalizedLastHttpStatus,
            retryable: Boolean(retryable),
            payloadSnapshot: normalizedPayloadSnapshot,
            responseSnapshot: normalizedResponseSnapshot,
            createdByUserId:
              existingRecord?.createdByUserId || normalizedOperatorUserId,
            updatedByUserId: normalizedOperatorUserId
          },
          preserveTerminalStatus: true
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.recovery.retry_scheduled',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration_recovery',
              targetId: persistedRecord.recoveryId,
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationRecoveryQueueByRecoveryId,
            snapshot.platformIntegrationRecoveryQueueByRecoveryId
          );
          restoreMapFromSnapshot(
            platformIntegrationRecoveryDedupIndex,
            snapshot.platformIntegrationRecoveryDedupIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationRecoveryUpsertPlatformIntegrationRecoveryQueueEntry
};

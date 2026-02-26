'use strict';

const createPlatformMemoryAuthStoreIntegrationRecoveryCompletePlatformIntegrationRecoveryQueueAttempt = ({
  MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH,
  auditEvents,
  computeRetrySchedule,
  findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId,
  isPlatformIntegrationRecoveryFailureRetryable,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationJsonForStorage,
  normalizePlatformIntegrationOptionalText,
  normalizePlatformIntegrationRecoveryId,
  persistAuditEvent,
  platformIntegrationRecoveryDedupIndex,
  platformIntegrationRecoveryQueueByRecoveryId,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  upsertPlatformIntegrationRecoveryQueueRecord
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
        const existingState = findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId(
          normalizedRecoveryId
        );
        const existingRecord = existingState?.record || null;
        if (!existingRecord || existingRecord.integrationId !== normalizedIntegrationId) {
          return null;
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
        const updatedRecord = upsertPlatformIntegrationRecoveryQueueRecord({
          entry: {
            ...existingRecord,
            status: nextStatus,
            nextRetryAt: persistedNextRetryAt,
            failureCode: persistedFailureCode,
            failureDetail: persistedFailureDetail,
            lastHttpStatus: persistedLastHttpStatus,
            retryable: persistedRetryable,
            responseSnapshot: normalizedResponseSnapshot,
            updatedByUserId: normalizedOperatorUserId,
            updatedAt: completionNowIso
          }
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          const emitAuditEvent = (eventType) =>
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType,
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
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
              emitAuditEvent('platform.integration.recovery.reprocess_succeeded');
            } else {
              emitAuditEvent('platform.integration.recovery.reprocess_failed');
              if (updatedRecord.status === 'dlq') {
                emitAuditEvent('platform.integration.recovery.retry_exhausted');
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
  createPlatformMemoryAuthStoreIntegrationRecoveryCompletePlatformIntegrationRecoveryQueueAttempt
};

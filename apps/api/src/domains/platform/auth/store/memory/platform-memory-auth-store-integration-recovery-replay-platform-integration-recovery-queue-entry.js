'use strict';

const createPlatformMemoryAuthStoreIntegrationRecoveryReplayPlatformIntegrationRecoveryQueueEntry = ({
  MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_REASON_LENGTH,
  auditEvents,
  createPlatformIntegrationRecoveryReplayConflictError,
  findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationOptionalText,
  normalizePlatformIntegrationRecoveryId,
  persistAuditEvent,
  platformIntegrationRecoveryDedupIndex,
  platformIntegrationRecoveryQueueByRecoveryId,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  upsertPlatformIntegrationRecoveryQueueRecord
} = {}) => ({
replayPlatformIntegrationRecoveryQueueEntry: async ({
      integrationId,
      recoveryId,
      reason = null,
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
        const existingState = findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId(
          normalizedRecoveryId
        );
        const existingRecord = existingState?.record || null;
        if (!existingRecord || existingRecord.integrationId !== normalizedIntegrationId) {
          return null;
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
        const updatedRecord = upsertPlatformIntegrationRecoveryQueueRecord({
          entry: {
            ...existingRecord,
            status: 'replayed',
            attemptCount: 0,
            nextRetryAt: new Date().toISOString(),
            lastAttemptAt: null,
            failureCode: null,
            failureDetail: null,
            lastHttpStatus: null,
            retryable: true,
            updatedByUserId: normalizedOperatorUserId,
            updatedAt: new Date().toISOString()
          }
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.recovery.replayed',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
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
  createPlatformMemoryAuthStoreIntegrationRecoveryReplayPlatformIntegrationRecoveryQueueEntry
};

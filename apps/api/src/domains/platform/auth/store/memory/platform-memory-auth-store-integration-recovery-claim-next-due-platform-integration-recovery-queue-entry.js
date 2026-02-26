'use strict';

const createPlatformMemoryAuthStoreIntegrationRecoveryClaimNextDuePlatformIntegrationRecoveryQueueEntry = ({
  DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS,
  auditEvents,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationOptionalText,
  persistAuditEvent,
  platformIntegrationRecoveryDedupIndex,
  platformIntegrationRecoveryQueueByRecoveryId,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  upsertPlatformIntegrationRecoveryQueueRecord
} = {}) => ({
claimNextDuePlatformIntegrationRecoveryQueueEntry: async ({
      integrationId = null,
      now = new Date().toISOString(),
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) => {
      const normalizedNow = new Date(now);
      if (Number.isNaN(normalizedNow.getTime())) {
        throw new Error(
          'claimNextDuePlatformIntegrationRecoveryQueueEntry received invalid now'
        );
      }
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
      const normalizedNowIso = normalizedNow.toISOString();
      const normalizedNowEpochMs = normalizedNow.getTime();
      const staleRetryingThresholdMs =
        normalizedNow.getTime() - DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS;
      const claimLeaseExpiresAtIso = new Date(
        normalizedNow.getTime() + DEFAULT_PLATFORM_INTEGRATION_RECOVERY_CLAIM_LEASE_MS
      ).toISOString();
      const normalizedOperatorUserId = normalizePlatformIntegrationOptionalText(operatorUserId);
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
      const isStaleRetryingEntry = (entry) => {
        if (entry.status !== 'retrying') {
          return false;
        }
        if (entry.nextRetryAt !== null) {
          return new Date(entry.nextRetryAt).getTime() <= normalizedNowEpochMs;
        }
        if (entry.lastAttemptAt === null) {
          return true;
        }
        return new Date(entry.lastAttemptAt).getTime() <= staleRetryingThresholdMs;
      };
      const staleRetryingRecords = [];
      for (const entry of [...platformIntegrationRecoveryQueueByRecoveryId.values()]) {
        if (
          normalizedIntegrationId !== null
          && entry.integrationId !== normalizedIntegrationId
        ) {
          continue;
        }
        if (!isStaleRetryingEntry(entry) || entry.attemptCount < entry.maxAttempts) {
          continue;
        }
        staleRetryingRecords.push(entry);
      }
      if (staleRetryingRecords.length > 0) {
        const staleSweepSnapshot = {
          platformIntegrationRecoveryQueueByRecoveryId: structuredClone(
            platformIntegrationRecoveryQueueByRecoveryId
          ),
          platformIntegrationRecoveryDedupIndex: structuredClone(
            platformIntegrationRecoveryDedupIndex
          ),
          auditEvents: structuredClone(auditEvents)
        };
        try {
          for (const staleEntry of staleRetryingRecords) {
            upsertPlatformIntegrationRecoveryQueueRecord({
              entry: {
                ...staleEntry,
                status: 'dlq',
                nextRetryAt: null,
                updatedByUserId: normalizedOperatorUserId,
                updatedAt: normalizedNowIso
              }
            });
            persistAuditEvent({
              domain: 'platform',
              requestId: auditRequestId,
              traceparent: auditTraceparent,
              eventType: 'platform.integration.recovery.retry_exhausted',
              actorUserId: auditActorUserId,
              actorSessionId: auditActorSessionId,
              targetType: 'integration_recovery',
              targetId: staleEntry.recoveryId,
              result: 'failed',
              beforeState: {
                status: staleEntry.status,
                attempt_count: staleEntry.attemptCount,
                max_attempts: staleEntry.maxAttempts,
                next_retry_at: staleEntry.nextRetryAt,
                last_attempt_at: staleEntry.lastAttemptAt
              },
              afterState: {
                status: 'dlq',
                attempt_count: staleEntry.attemptCount,
                max_attempts: staleEntry.maxAttempts,
                next_retry_at: null,
                last_attempt_at: staleEntry.lastAttemptAt
              },
              metadata: {
                exhausted_by: 'stale-retrying-claim-sweep'
              }
            });
          }
        } catch (error) {
          restoreMapFromSnapshot(
            platformIntegrationRecoveryQueueByRecoveryId,
            staleSweepSnapshot.platformIntegrationRecoveryQueueByRecoveryId
          );
          restoreMapFromSnapshot(
            platformIntegrationRecoveryDedupIndex,
            staleSweepSnapshot.platformIntegrationRecoveryDedupIndex
          );
          restoreAuditEventsFromSnapshot(staleSweepSnapshot.auditEvents);
          const auditWriteError = new Error(
            'platform integration recovery claim sweep audit write failed'
          );
          auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
          auditWriteError.cause = error;
          throw auditWriteError;
        }
      }
      const candidateRecord = [...platformIntegrationRecoveryQueueByRecoveryId.values()]
        .filter((entry) => {
          if (entry.status === 'pending') {
            if (
              entry.nextRetryAt !== null
              && new Date(entry.nextRetryAt).getTime() > normalizedNowEpochMs
            ) {
              return false;
            }
          } else if (entry.status === 'replayed') {
            if (
              entry.nextRetryAt !== null
              && new Date(entry.nextRetryAt).getTime() > normalizedNowEpochMs
            ) {
              return false;
            }
          } else if (entry.status === 'retrying') {
            if (!isStaleRetryingEntry(entry)) {
              return false;
            }
          } else {
            return false;
          }
          if (entry.attemptCount >= entry.maxAttempts) {
            return false;
          }
          if (
            normalizedIntegrationId !== null
            && entry.integrationId !== normalizedIntegrationId
          ) {
            return false;
          }
          return true;
        })
        .sort((left, right) => {
          const leftDueAt = new Date(left.nextRetryAt || left.createdAt).getTime();
          const rightDueAt = new Date(right.nextRetryAt || right.createdAt).getTime();
          if (leftDueAt !== rightDueAt) {
            return leftDueAt - rightDueAt;
          }
          const leftCreatedAt = new Date(left.createdAt).getTime();
          const rightCreatedAt = new Date(right.createdAt).getTime();
          if (leftCreatedAt !== rightCreatedAt) {
            return leftCreatedAt - rightCreatedAt;
          }
          return String(left.recoveryId || '').localeCompare(
            String(right.recoveryId || '')
          );
        })[0] || null;
      if (!candidateRecord) {
        return null;
      }
      const updatedRecord = upsertPlatformIntegrationRecoveryQueueRecord({
        entry: {
          ...candidateRecord,
          attemptCount: Math.min(
            candidateRecord.maxAttempts,
            candidateRecord.attemptCount + 1
          ),
          status: 'retrying',
          nextRetryAt: claimLeaseExpiresAtIso,
          lastAttemptAt: normalizedNowIso,
          updatedByUserId: normalizedOperatorUserId,
          updatedAt: normalizedNowIso
        }
      });
      return {
        ...updatedRecord,
        previousStatus: candidateRecord.status,
        currentStatus: updatedRecord.status
      };
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationRecoveryClaimNextDuePlatformIntegrationRecoveryQueueEntry
};

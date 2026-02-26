'use strict';

const createPlatformMemoryAuthStoreIntegrationFreeze = ({
  MAX_PLATFORM_INTEGRATION_FREEZE_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH,
  MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH,
  auditEvents,
  clonePlatformIntegrationFreezeRecord,
  createPlatformIntegrationFreezeActiveConflictError,
  createPlatformIntegrationFreezeReleaseConflictError,
  findActivePlatformIntegrationFreezeRecordState,
  findLatestPlatformIntegrationFreezeRecordState,
  invokeFaultInjector,
  normalizePlatformIntegrationFreezeId,
  normalizePlatformIntegrationOptionalText,
  persistAuditEvent,
  platformIntegrationFreezeById,
  randomUUID,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  toPlatformIntegrationFreezeRecord,
  upsertPlatformIntegrationFreezeRecord
} = {}) => ({
findActivePlatformIntegrationFreeze: async () => {
      const activeState = findActivePlatformIntegrationFreezeRecordState();
      if (!activeState?.record) {
        return null;
      }
      const normalizedRecord = toPlatformIntegrationFreezeRecord(activeState.record);
      if (!normalizedRecord) {
        throw new Error('findActivePlatformIntegrationFreeze result malformed');
      }
      return clonePlatformIntegrationFreezeRecord(normalizedRecord);
    },

findLatestPlatformIntegrationFreeze: async () => {
      const latestState = findLatestPlatformIntegrationFreezeRecordState();
      if (!latestState?.record) {
        return null;
      }
      const normalizedRecord = toPlatformIntegrationFreezeRecord(latestState.record);
      if (!normalizedRecord) {
        throw new Error('findLatestPlatformIntegrationFreeze result malformed');
      }
      return clonePlatformIntegrationFreezeRecord(normalizedRecord);
    },

activatePlatformIntegrationFreeze: async ({
      freezeId = randomUUID(),
      freezeReason,
      operatorUserId = null,
      operatorSessionId = null,
      requestId,
      traceparent = null,
      auditContext = null
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationFreezeById: structuredClone(platformIntegrationFreezeById),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const freezeIdProvided = freezeId !== undefined && freezeId !== null;
        const normalizedRequestedFreezeId =
          normalizePlatformIntegrationFreezeId(freezeId);
        if (
          freezeIdProvided
          && (
            !normalizedRequestedFreezeId
            || normalizedRequestedFreezeId.length > MAX_PLATFORM_INTEGRATION_FREEZE_ID_LENGTH
          )
        ) {
          throw new Error('activatePlatformIntegrationFreeze received invalid freezeId');
        }
        const normalizedFreezeId =
          normalizedRequestedFreezeId && normalizedRequestedFreezeId.length > 0
            ? normalizedRequestedFreezeId
            : randomUUID();
        const normalizedFreezeReason =
          normalizePlatformIntegrationOptionalText(freezeReason);
        const normalizedRequestId = String(requestId || '').trim();
        const normalizedTraceparent = normalizePlatformIntegrationOptionalText(traceparent);
        if (
          !normalizedFreezeReason
          || normalizedFreezeReason.length > MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH
          || !normalizedRequestId
          || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH
          || (
            normalizedTraceparent !== null
            && normalizedTraceparent.length > MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH
          )
        ) {
          throw new Error('activatePlatformIntegrationFreeze received invalid input');
        }
        const activeState = findActivePlatformIntegrationFreezeRecordState();
        if (activeState?.record) {
          const activeFreeze = toPlatformIntegrationFreezeRecord(activeState.record);
          if (!activeFreeze) {
            throw new Error('activatePlatformIntegrationFreeze active row malformed');
          }
          throw createPlatformIntegrationFreezeActiveConflictError({
            freezeId: activeFreeze.freezeId,
            frozenAt: activeFreeze.frozenAt,
            freezeReason: activeFreeze.freezeReason
          });
        }
        if (platformIntegrationFreezeById.has(normalizedFreezeId)) {
          throw createPlatformIntegrationFreezeActiveConflictError();
        }
        const nowIso = new Date().toISOString();
        const createdRecord = upsertPlatformIntegrationFreezeRecord({
          freezeId: normalizedFreezeId,
          status: 'active',
          freezeReason: normalizedFreezeReason,
          rollbackReason: null,
          frozenAt: nowIso,
          releasedAt: null,
          frozenByUserId: normalizePlatformIntegrationOptionalText(operatorUserId),
          releasedByUserId: null,
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          createdAt: nowIso,
          updatedAt: nowIso
        });
        if (!createdRecord) {
          throw new Error('activatePlatformIntegrationFreeze result unavailable');
        }
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            invokeFaultInjector('beforePlatformIntegrationFreezeActivateAuditWrite', {
              freezeId: normalizedFreezeId,
              requestId: normalizedRequestId
            });
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || normalizedRequestId).trim()
                || 'request_id_unset',
              traceparent: auditContext.traceparent ?? normalizedTraceparent,
              eventType: 'platform.integration.freeze.activated',
              actorUserId: auditContext.actorUserId || operatorUserId,
              actorSessionId: auditContext.actorSessionId || operatorSessionId,
              targetType: 'integration_freeze',
              targetId: normalizedFreezeId,
              result: 'success',
              beforeState: null,
              afterState: {
                freeze_id: createdRecord.freezeId,
                status: createdRecord.status,
                freeze_reason: createdRecord.freezeReason,
                frozen_at: createdRecord.frozenAt
              }
            });
            auditRecorded = true;
          } catch (error) {
            const auditWriteError = new Error(
              'platform integration freeze activate audit write failed'
            );
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
        }
        return {
          ...createdRecord,
          auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationFreezeById,
            snapshot.platformIntegrationFreezeById
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

releasePlatformIntegrationFreeze: async ({
      rollbackReason = null,
      operatorUserId = null,
      operatorSessionId = null,
      requestId = 'request_id_unset',
      traceparent = null,
      auditContext = null
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationFreezeById: structuredClone(platformIntegrationFreezeById),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedRollbackReason =
          normalizePlatformIntegrationOptionalText(rollbackReason);
        const normalizedRequestId = String(requestId || '').trim();
        const normalizedTraceparent = normalizePlatformIntegrationOptionalText(traceparent);
        if (
          (
            normalizedRollbackReason !== null
            && normalizedRollbackReason.length > MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH
          )
          || !normalizedRequestId
          || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH
          || (
            normalizedTraceparent !== null
            && normalizedTraceparent.length > MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH
          )
        ) {
          throw new Error('releasePlatformIntegrationFreeze received invalid input');
        }
        const activeState = findActivePlatformIntegrationFreezeRecordState();
        if (!activeState?.record) {
          throw createPlatformIntegrationFreezeReleaseConflictError();
        }
        const activeRecord = toPlatformIntegrationFreezeRecord(activeState.record);
        if (!activeRecord) {
          throw new Error('releasePlatformIntegrationFreeze active row malformed');
        }
        const nowIso = new Date().toISOString();
        const releasedRecord = upsertPlatformIntegrationFreezeRecord({
          ...activeRecord,
          status: 'released',
          rollbackReason: normalizedRollbackReason,
          releasedAt: nowIso,
          releasedByUserId: normalizePlatformIntegrationOptionalText(operatorUserId),
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          updatedAt: nowIso
        });
        if (!releasedRecord) {
          throw new Error('releasePlatformIntegrationFreeze result unavailable');
        }
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            invokeFaultInjector('beforePlatformIntegrationFreezeReleaseAuditWrite', {
              freezeId: activeRecord.freezeId,
              requestId: normalizedRequestId
            });
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || normalizedRequestId).trim()
                || 'request_id_unset',
              traceparent: auditContext.traceparent ?? normalizedTraceparent,
              eventType: 'platform.integration.freeze.released',
              actorUserId: auditContext.actorUserId || operatorUserId,
              actorSessionId: auditContext.actorSessionId || operatorSessionId,
              targetType: 'integration_freeze',
              targetId: activeRecord.freezeId,
              result: 'success',
              beforeState: {
                status: activeRecord.status,
                freeze_reason: activeRecord.freezeReason,
                frozen_at: activeRecord.frozenAt
              },
              afterState: {
                status: releasedRecord.status,
                rollback_reason: releasedRecord.rollbackReason,
                released_at: releasedRecord.releasedAt
              }
            });
            auditRecorded = true;
          } catch (error) {
            const auditWriteError = new Error(
              'platform integration freeze release audit write failed'
            );
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
        }
        return {
          ...releasedRecord,
          previousStatus: activeRecord.status,
          currentStatus: releasedRecord.status,
          released: true,
          auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationFreezeById,
            snapshot.platformIntegrationFreezeById
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationFreeze
};

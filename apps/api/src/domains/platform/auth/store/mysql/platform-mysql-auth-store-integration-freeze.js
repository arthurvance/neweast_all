'use strict';

const createPlatformMysqlAuthStoreIntegrationFreeze = ({
  MAX_PLATFORM_INTEGRATION_FREEZE_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH,
  MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH,
  createPlatformIntegrationFreezeActiveConflictError,
  createPlatformIntegrationFreezeReleaseConflictError,
  dbClient,
  executeWithDeadlockRetry,
  isDuplicateEntryError,
  normalizePlatformIntegrationFreezeId,
  normalizePlatformIntegrationOptionalText,
  randomUUID,
  recordAuditEventWithQueryClient,
  toPlatformIntegrationFreezeRecord
} = {}) => ({
findActivePlatformIntegrationFreeze: async () => {
      const rows = await dbClient.query(
        `
          SELECT freeze_id,
                 status,
                 freeze_reason,
                 rollback_reason,
                 frozen_at,
                 released_at,
                 frozen_by_user_id,
                 released_by_user_id,
                 request_id,
                 traceparent,
                 created_at,
                 updated_at
          FROM platform_integration_freeze_control
          WHERE status = 'active'
          ORDER BY frozen_at DESC, freeze_id DESC
          LIMIT 1
        `
      );
      if (!Array.isArray(rows)) {
        throw new Error('findActivePlatformIntegrationFreeze result malformed');
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRow = toPlatformIntegrationFreezeRecord(rows[0]);
      if (!normalizedRow) {
        throw new Error('findActivePlatformIntegrationFreeze result malformed');
      }
      return normalizedRow;
    },

findLatestPlatformIntegrationFreeze: async () => {
      const rows = await dbClient.query(
        `
          SELECT freeze_id,
                 status,
                 freeze_reason,
                 rollback_reason,
                 frozen_at,
                 released_at,
                 frozen_by_user_id,
                 released_by_user_id,
                 request_id,
                 traceparent,
                 created_at,
                 updated_at
          FROM platform_integration_freeze_control
          ORDER BY frozen_at DESC, updated_at DESC, freeze_id DESC
          LIMIT 1
        `
      );
      if (!Array.isArray(rows)) {
        throw new Error('findLatestPlatformIntegrationFreeze result malformed');
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRow = toPlatformIntegrationFreezeRecord(rows[0]);
      if (!normalizedRow) {
        throw new Error('findLatestPlatformIntegrationFreeze result malformed');
      }
      return normalizedRow;
    },

activatePlatformIntegrationFreeze: async ({
      freezeId = randomUUID(),
      freezeReason,
      operatorUserId = null,
      operatorSessionId = null,
      requestId,
      traceparent = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'activatePlatformIntegrationFreeze',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
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
            const normalizedTraceparent =
              normalizePlatformIntegrationOptionalText(traceparent);
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
            const activeRows = await tx.query(
              `
                SELECT freeze_id,
                       status,
                       freeze_reason,
                       rollback_reason,
                       frozen_at,
                       released_at,
                       frozen_by_user_id,
                       released_by_user_id,
                       request_id,
                       traceparent,
                       created_at,
                       updated_at
                FROM platform_integration_freeze_control
                WHERE status = 'active'
                ORDER BY frozen_at DESC, freeze_id DESC
                LIMIT 1
                FOR UPDATE
              `
            );
            if (!Array.isArray(activeRows)) {
              throw new Error('activatePlatformIntegrationFreeze active query malformed');
            }
            if (activeRows.length > 0) {
              const activeFreeze = toPlatformIntegrationFreezeRecord(activeRows[0]);
              if (!activeFreeze) {
                throw new Error('activatePlatformIntegrationFreeze active row malformed');
              }
              throw createPlatformIntegrationFreezeActiveConflictError({
                freezeId: activeFreeze.freezeId,
                frozenAt: activeFreeze.frozenAt
              });
            }
            try {
              await tx.query(
                `
                  INSERT INTO platform_integration_freeze_control (
                    freeze_id,
                    status,
                    freeze_reason,
                    rollback_reason,
                    frozen_by_user_id,
                    released_by_user_id,
                    request_id,
                    traceparent
                  )
                  VALUES (?, 'active', ?, NULL, ?, NULL, ?, ?)
                `,
                [
                  normalizedFreezeId,
                  normalizedFreezeReason,
                  normalizePlatformIntegrationOptionalText(operatorUserId),
                  normalizedRequestId,
                  normalizedTraceparent
                ]
              );
            } catch (error) {
              if (isDuplicateEntryError(error)) {
                const conflictRows = await tx.query(
                  `
                    SELECT freeze_id,
                           status,
                           freeze_reason,
                           rollback_reason,
                           frozen_at,
                           released_at,
                           frozen_by_user_id,
                           released_by_user_id,
                           request_id,
                           traceparent,
                           created_at,
                           updated_at
                    FROM platform_integration_freeze_control
                    WHERE status = 'active'
                    ORDER BY frozen_at DESC, freeze_id DESC
                    LIMIT 1
                  `
                );
                const activeFreeze = Array.isArray(conflictRows)
                  ? toPlatformIntegrationFreezeRecord(conflictRows[0] || null)
                  : null;
                throw createPlatformIntegrationFreezeActiveConflictError({
                  freezeId: activeFreeze?.freezeId || null,
                  frozenAt: activeFreeze?.frozenAt || null
                });
              }
              throw error;
            }
            const createdRows = await tx.query(
              `
                SELECT freeze_id,
                       status,
                       freeze_reason,
                       rollback_reason,
                       frozen_at,
                       released_at,
                       frozen_by_user_id,
                       released_by_user_id,
                       request_id,
                       traceparent,
                       created_at,
                       updated_at
                FROM platform_integration_freeze_control
                WHERE freeze_id = ?
                LIMIT 1
              `,
              [normalizedFreezeId]
            );
            const createdRecord = toPlatformIntegrationFreezeRecord(
              createdRows?.[0] || null
            );
            if (!createdRecord) {
              throw new Error('activatePlatformIntegrationFreeze result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
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
          })
      }),

releasePlatformIntegrationFreeze: async ({
      rollbackReason = null,
      operatorUserId = null,
      operatorSessionId = null,
      requestId = 'request_id_unset',
      traceparent = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'releasePlatformIntegrationFreeze',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedRollbackReason =
              normalizePlatformIntegrationOptionalText(rollbackReason);
            const normalizedRequestId = String(requestId || '').trim();
            const normalizedTraceparent =
              normalizePlatformIntegrationOptionalText(traceparent);
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
            const activeRows = await tx.query(
              `
                SELECT freeze_id,
                       status,
                       freeze_reason,
                       rollback_reason,
                       frozen_at,
                       released_at,
                       frozen_by_user_id,
                       released_by_user_id,
                       request_id,
                       traceparent,
                       created_at,
                       updated_at
                FROM platform_integration_freeze_control
                WHERE status = 'active'
                ORDER BY frozen_at DESC, freeze_id DESC
                LIMIT 1
                FOR UPDATE
              `
            );
            if (!Array.isArray(activeRows)) {
              throw new Error('releasePlatformIntegrationFreeze active query malformed');
            }
            if (activeRows.length === 0) {
              throw createPlatformIntegrationFreezeReleaseConflictError();
            }
            const activeRecord = toPlatformIntegrationFreezeRecord(activeRows[0]);
            if (!activeRecord) {
              throw new Error('releasePlatformIntegrationFreeze active row malformed');
            }
            const updateResult = await tx.query(
              `
                UPDATE platform_integration_freeze_control
                SET status = 'released',
                    rollback_reason = ?,
                    released_at = CURRENT_TIMESTAMP(3),
                    released_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE freeze_id = ?
                  AND status = 'active'
              `,
              [
                normalizedRollbackReason,
                normalizePlatformIntegrationOptionalText(operatorUserId),
                activeRecord.freezeId
              ]
            );
            if (
              updateResult
              && Object.prototype.hasOwnProperty.call(updateResult, 'affectedRows')
              && Number(updateResult.affectedRows || 0) < 1
            ) {
              throw createPlatformIntegrationFreezeReleaseConflictError();
            }
            const updatedRows = await tx.query(
              `
                SELECT freeze_id,
                       status,
                       freeze_reason,
                       rollback_reason,
                       frozen_at,
                       released_at,
                       frozen_by_user_id,
                       released_by_user_id,
                       request_id,
                       traceparent,
                       created_at,
                       updated_at
                FROM platform_integration_freeze_control
                WHERE freeze_id = ?
                LIMIT 1
              `,
              [activeRecord.freezeId]
            );
            const releasedRecord = toPlatformIntegrationFreezeRecord(
              updatedRows?.[0] || null
            );
            if (!releasedRecord) {
              throw new Error('releasePlatformIntegrationFreeze result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
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
          })
      })
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationFreeze
};

'use strict';

const createPlatformMemoryAuthStoreIntegrationCatalogUpdatePlatformIntegrationCatalogEntry = ({
  assertPlatformIntegrationWriteAllowedByFreezeGate,
  auditEvents,
  findPlatformIntegrationCatalogRecordStateByIntegrationId,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationOptionalText,
  persistAuditEvent,
  platformIntegrationCatalogById,
  platformIntegrationCatalogCodeIndex,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  upsertPlatformIntegrationCatalogRecord
} = {}) => ({
updatePlatformIntegrationCatalogEntry: async ({
      integrationId,
      code = undefined,
      name = undefined,
      direction = undefined,
      protocol = undefined,
      authMode = undefined,
      endpoint = undefined,
      baseUrl = undefined,
      timeoutMs = undefined,
      retryPolicy = undefined,
      idempotencyPolicy = undefined,
      versionStrategy = undefined,
      runbookUrl = undefined,
      lifecycleReason = undefined,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationCatalogById: structuredClone(platformIntegrationCatalogById),
          platformIntegrationCatalogCodeIndex: structuredClone(
            platformIntegrationCatalogCodeIndex
          ),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
        if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
          throw new Error('updatePlatformIntegrationCatalogEntry requires integrationId');
        }
        const existingState = findPlatformIntegrationCatalogRecordStateByIntegrationId(
          normalizedIntegrationId
        );
        const existingRecord = existingState?.record || null;
        if (!existingRecord) {
          return null;
        }
        const hasUpdates = [
          code,
          name,
          direction,
          protocol,
          authMode,
          endpoint,
          baseUrl,
          timeoutMs,
          retryPolicy,
          idempotencyPolicy,
          versionStrategy,
          runbookUrl,
          lifecycleReason
        ].some((value) => value !== undefined);
        if (!hasUpdates) {
          throw new Error('updatePlatformIntegrationCatalogEntry requires update fields');
        }
        assertPlatformIntegrationWriteAllowedByFreezeGate();
        const updatedRecord = upsertPlatformIntegrationCatalogRecord({
          ...existingRecord,
          integrationId: existingRecord.integrationId,
          code: code === undefined ? existingRecord.code : code,
          name: name === undefined ? existingRecord.name : name,
          direction: direction === undefined ? existingRecord.direction : direction,
          protocol: protocol === undefined ? existingRecord.protocol : protocol,
          authMode: authMode === undefined ? existingRecord.authMode : authMode,
          endpoint: endpoint === undefined ? existingRecord.endpoint : endpoint,
          baseUrl: baseUrl === undefined ? existingRecord.baseUrl : baseUrl,
          timeoutMs: timeoutMs === undefined ? existingRecord.timeoutMs : timeoutMs,
          retryPolicy: retryPolicy === undefined
            ? existingRecord.retryPolicy
            : retryPolicy,
          idempotencyPolicy: idempotencyPolicy === undefined
            ? existingRecord.idempotencyPolicy
            : idempotencyPolicy,
          versionStrategy: versionStrategy === undefined
            ? existingRecord.versionStrategy
            : versionStrategy,
          runbookUrl: runbookUrl === undefined
            ? existingRecord.runbookUrl
            : runbookUrl,
          lifecycleReason: lifecycleReason === undefined
            ? existingRecord.lifecycleReason
            : lifecycleReason,
          updatedByUserId:
            normalizePlatformIntegrationOptionalText(operatorUserId)
            || existingRecord.updatedByUserId,
          updatedAt: new Date().toISOString()
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.updated',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration',
              targetId: updatedRecord.integrationId,
              result: 'success',
              beforeState: {
                code: existingRecord.code,
                direction: existingRecord.direction,
                protocol: existingRecord.protocol,
                auth_mode: existingRecord.authMode
              },
              afterState: {
                code: updatedRecord.code,
                direction: updatedRecord.direction,
                protocol: updatedRecord.protocol,
                auth_mode: updatedRecord.authMode
              }
            });
            auditRecorded = true;
          } catch (error) {
            const auditWriteError = new Error(
              'platform integration update audit write failed'
            );
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
        }
        return {
          ...updatedRecord,
          auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationCatalogById,
            snapshot.platformIntegrationCatalogById
          );
          restoreMapFromSnapshot(
            platformIntegrationCatalogCodeIndex,
            snapshot.platformIntegrationCatalogCodeIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationCatalogUpdatePlatformIntegrationCatalogEntry
};

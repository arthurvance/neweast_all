'use strict';

const createPlatformMemoryAuthStoreIntegrationCatalogCreatePlatformIntegrationCatalogEntry = ({
  PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS,
  assertPlatformIntegrationWriteAllowedByFreezeGate,
  auditEvents,
  createDuplicatePlatformIntegrationCatalogEntryError,
  findPlatformIntegrationCatalogRecordStateByIntegrationId,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationOptionalText,
  persistAuditEvent,
  platformIntegrationCatalogById,
  platformIntegrationCatalogCodeIndex,
  randomUUID,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  upsertPlatformIntegrationCatalogRecord
} = {}) => ({
createPlatformIntegrationCatalogEntry: async ({
      integrationId = randomUUID(),
      code,
      name,
      direction,
      protocol,
      authMode,
      endpoint = null,
      baseUrl = null,
      timeoutMs = PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS,
      retryPolicy = null,
      idempotencyPolicy = null,
      versionStrategy = null,
      runbookUrl = null,
      lifecycleStatus = 'draft',
      lifecycleReason = null,
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
        const integrationIdProvided =
          integrationId !== undefined && integrationId !== null;
        const normalizedRequestedIntegrationId =
          normalizePlatformIntegrationId(integrationId);
        if (
          integrationIdProvided
          && !isValidPlatformIntegrationId(normalizedRequestedIntegrationId)
        ) {
          throw new Error('createPlatformIntegrationCatalogEntry received invalid integrationId');
        }
        const normalizedIntegrationId = isValidPlatformIntegrationId(
          normalizedRequestedIntegrationId
        )
          ? normalizedRequestedIntegrationId
          : randomUUID();
        assertPlatformIntegrationWriteAllowedByFreezeGate();
        if (
          findPlatformIntegrationCatalogRecordStateByIntegrationId(
            normalizedIntegrationId
          )
        ) {
          throw createDuplicatePlatformIntegrationCatalogEntryError({
            target: 'integration_id'
          });
        }
        const createdRecord = upsertPlatformIntegrationCatalogRecord({
          integrationId: normalizedIntegrationId,
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
          lifecycleStatus,
          lifecycleReason,
          createdByUserId: normalizePlatformIntegrationOptionalText(operatorUserId),
          updatedByUserId: normalizePlatformIntegrationOptionalText(operatorUserId)
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.created',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration',
              targetId: createdRecord.integrationId,
              result: 'success',
              beforeState: null,
              afterState: {
                integration_id: createdRecord.integrationId,
                code: createdRecord.code,
                direction: createdRecord.direction,
                protocol: createdRecord.protocol,
                auth_mode: createdRecord.authMode,
                lifecycle_status: createdRecord.lifecycleStatus
              }
            });
            auditRecorded = true;
          } catch (error) {
            const auditWriteError = new Error(
              'platform integration create audit write failed'
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
  createPlatformMemoryAuthStoreIntegrationCatalogCreatePlatformIntegrationCatalogEntry
};

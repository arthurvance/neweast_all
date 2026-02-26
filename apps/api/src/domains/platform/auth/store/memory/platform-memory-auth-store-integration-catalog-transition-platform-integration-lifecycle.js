'use strict';

const createPlatformMemoryAuthStoreIntegrationCatalogTransitionPlatformIntegrationLifecycle = ({
  VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS,
  assertPlatformIntegrationWriteAllowedByFreezeGate,
  auditEvents,
  createPlatformIntegrationLifecycleConflictError,
  findPlatformIntegrationCatalogRecordStateByIntegrationId,
  isPlatformIntegrationLifecycleTransitionAllowed,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationLifecycleStatus,
  normalizePlatformIntegrationOptionalText,
  persistAuditEvent,
  platformIntegrationCatalogById,
  platformIntegrationCatalogCodeIndex,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  upsertPlatformIntegrationCatalogRecord
} = {}) => ({
transitionPlatformIntegrationLifecycle: async ({
      integrationId,
      nextStatus,
      reason = null,
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
        const normalizedNextStatus = normalizePlatformIntegrationLifecycleStatus(nextStatus);
        if (
          !isValidPlatformIntegrationId(normalizedIntegrationId)
          || !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedNextStatus)
        ) {
          throw new Error('transitionPlatformIntegrationLifecycle received invalid input');
        }
        assertPlatformIntegrationWriteAllowedByFreezeGate();
        const existingState = findPlatformIntegrationCatalogRecordStateByIntegrationId(
          normalizedIntegrationId
        );
        const existingRecord = existingState?.record || null;
        if (!existingRecord) {
          return null;
        }
        if (
          !isPlatformIntegrationLifecycleTransitionAllowed({
            previousStatus: existingRecord.lifecycleStatus,
            nextStatus: normalizedNextStatus
          })
        ) {
          throw createPlatformIntegrationLifecycleConflictError({
            integrationId: normalizedIntegrationId,
            previousStatus: existingRecord.lifecycleStatus,
            requestedStatus: normalizedNextStatus
          });
        }
        const updatedRecord = upsertPlatformIntegrationCatalogRecord({
          ...existingRecord,
          lifecycleStatus: normalizedNextStatus,
          lifecycleReason: reason,
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
              eventType: 'platform.integration.lifecycle_changed',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration',
              targetId: updatedRecord.integrationId,
              result: 'success',
              beforeState: {
                lifecycle_status: existingRecord.lifecycleStatus
              },
              afterState: {
                lifecycle_status: updatedRecord.lifecycleStatus
              }
            });
            auditRecorded = true;
          } catch (error) {
            const auditWriteError = new Error(
              'platform integration lifecycle audit write failed'
            );
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
        }
        return {
          ...updatedRecord,
          previousStatus: existingRecord.lifecycleStatus,
          currentStatus: updatedRecord.lifecycleStatus,
          effectiveInvocationEnabled: updatedRecord.lifecycleStatus === 'active',
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
  createPlatformMemoryAuthStoreIntegrationCatalogTransitionPlatformIntegrationLifecycle
};

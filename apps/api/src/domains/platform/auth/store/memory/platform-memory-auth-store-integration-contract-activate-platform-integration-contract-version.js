'use strict';

const createPlatformMemoryAuthStoreIntegrationContractActivatePlatformIntegrationContractVersion = ({
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  assertPlatformIntegrationWriteAllowedByFreezeGate,
  auditEvents,
  clonePlatformIntegrationContractVersionRecord,
  createPlatformIntegrationContractActivationBlockedError,
  findPlatformIntegrationContractVersionRecordState,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationOptionalText,
  persistAuditEvent,
  platformIntegrationContractVersionsByKey,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  toPlatformIntegrationContractScopeKey,
  toPlatformIntegrationContractVersionRecord
} = {}) => ({
activatePlatformIntegrationContractVersion: async ({
      integrationId,
      contractType,
      contractVersion,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationContractVersionsByKey:
            structuredClone(platformIntegrationContractVersionsByKey),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
        const normalizedContractType = normalizePlatformIntegrationContractType(contractType);
        const normalizedContractVersion =
          normalizePlatformIntegrationContractVersion(contractVersion);
        if (
          !isValidPlatformIntegrationId(normalizedIntegrationId)
          || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
          || !normalizedContractVersion
          || normalizedContractVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
        ) {
          throw new Error('activatePlatformIntegrationContractVersion received invalid input');
        }
        assertPlatformIntegrationWriteAllowedByFreezeGate();
        const targetState = findPlatformIntegrationContractVersionRecordState({
          integrationId: normalizedIntegrationId,
          contractType: normalizedContractType,
          contractVersion: normalizedContractVersion
        });
        if (!targetState?.record) {
          return null;
        }
        const targetRecord = targetState.record;
        if (targetRecord.status === 'retired') {
          throw createPlatformIntegrationContractActivationBlockedError({
            integrationId: normalizedIntegrationId,
            contractType: normalizedContractType,
            contractVersion: normalizedContractVersion,
            reason: 'retired-version'
          });
        }
        const scopeKey = toPlatformIntegrationContractScopeKey({
          integrationId: normalizedIntegrationId,
          contractType: normalizedContractType
        });
        const previousStatus = targetRecord.status;
        for (const [contractKey, entry] of platformIntegrationContractVersionsByKey.entries()) {
          if (!contractKey.startsWith(`${scopeKey}::`)) {
            continue;
          }
          if (
            entry.status === 'active'
            && entry.contractVersion !== normalizedContractVersion
          ) {
            const updatedEntry = toPlatformIntegrationContractVersionRecord({
              ...entry,
              status: 'deprecated',
              updatedByUserId:
                normalizePlatformIntegrationOptionalText(operatorUserId)
                || entry.updatedByUserId,
              updatedAt: new Date().toISOString()
            });
            platformIntegrationContractVersionsByKey.set(contractKey, updatedEntry);
          }
        }
        const activeRecord = toPlatformIntegrationContractVersionRecord({
          ...targetRecord,
          status: 'active',
          updatedByUserId:
            normalizePlatformIntegrationOptionalText(operatorUserId)
            || targetRecord.updatedByUserId,
          updatedAt: new Date().toISOString()
        });
        platformIntegrationContractVersionsByKey.set(targetState.key, activeRecord);
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.contract.activated',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration_contract',
              targetId:
                `${normalizedIntegrationId}:${normalizedContractType}:${normalizedContractVersion}`,
              result: 'success',
              beforeState: {
                status: previousStatus
              },
              afterState: {
                status: activeRecord.status
              }
            });
            auditRecorded = true;
          } catch (error) {
            const auditWriteError = new Error(
              'platform integration contract activation audit write failed'
            );
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
        }
        return {
          ...clonePlatformIntegrationContractVersionRecord(activeRecord),
          previousStatus,
          currentStatus: activeRecord.status,
          switched: previousStatus !== activeRecord.status,
          auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationContractVersionsByKey,
            snapshot.platformIntegrationContractVersionsByKey
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationContractActivatePlatformIntegrationContractVersion
};

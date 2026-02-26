'use strict';

const createPlatformMemoryAuthStoreIntegrationContractCreatePlatformIntegrationContractVersion = ({
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  assertPlatformIntegrationWriteAllowedByFreezeGate,
  auditEvents,
  createDuplicatePlatformIntegrationContractVersionError,
  findPlatformIntegrationCatalogRecordStateByIntegrationId,
  findPlatformIntegrationContractVersionRecordState,
  isValidPlatformIntegrationId,
  nextPlatformIntegrationContractVersionId,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationOptionalText,
  persistAuditEvent,
  platformIntegrationContractVersionsByKey,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  upsertPlatformIntegrationContractVersionRecord
} = {}) => ({
createPlatformIntegrationContractVersion: async ({
      integrationId,
      contractType,
      contractVersion,
      schemaRef,
      schemaChecksum,
      status = 'candidate',
      isBackwardCompatible = false,
      compatibilityNotes = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationContractVersionsByKey:
            structuredClone(platformIntegrationContractVersionsByKey),
          nextPlatformIntegrationContractVersionId,
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
          || typeof isBackwardCompatible !== 'boolean'
        ) {
          throw new Error('createPlatformIntegrationContractVersion received invalid input');
        }
        if (
          !findPlatformIntegrationCatalogRecordStateByIntegrationId(normalizedIntegrationId)
        ) {
          throw new Error('createPlatformIntegrationContractVersion integration not found');
        }
        assertPlatformIntegrationWriteAllowedByFreezeGate();
        if (
          findPlatformIntegrationContractVersionRecordState({
            integrationId: normalizedIntegrationId,
            contractType: normalizedContractType,
            contractVersion: normalizedContractVersion
          })
        ) {
          throw createDuplicatePlatformIntegrationContractVersionError();
        }
        const createdRecord = upsertPlatformIntegrationContractVersionRecord({
          integrationId: normalizedIntegrationId,
          contractType: normalizedContractType,
          contractVersion: normalizedContractVersion,
          schemaRef,
          schemaChecksum,
          status,
          isBackwardCompatible,
          compatibilityNotes,
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
              eventType: 'platform.integration.contract.created',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration_contract',
              targetId:
                `${normalizedIntegrationId}:${normalizedContractType}:${normalizedContractVersion}`,
              result: 'success',
              beforeState: null,
              afterState: {
                integration_id: normalizedIntegrationId,
                contract_type: normalizedContractType,
                contract_version: normalizedContractVersion,
                status: createdRecord.status,
                is_backward_compatible: createdRecord.isBackwardCompatible
              }
            });
            auditRecorded = true;
          } catch (error) {
            const auditWriteError = new Error(
              'platform integration contract create audit write failed'
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
            platformIntegrationContractVersionsByKey,
            snapshot.platformIntegrationContractVersionsByKey
          );
          nextPlatformIntegrationContractVersionId = Number(
            snapshot.nextPlatformIntegrationContractVersionId || 1
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationContractCreatePlatformIntegrationContractVersion
};

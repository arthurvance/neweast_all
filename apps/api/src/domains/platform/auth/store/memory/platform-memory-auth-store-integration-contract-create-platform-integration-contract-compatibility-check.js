'use strict';

const createPlatformMemoryAuthStoreIntegrationContractCreatePlatformIntegrationContractCompatibilityCheck = ({
  MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  auditEvents,
  clonePlatformIntegrationContractCompatibilityCheckRecord,
  findPlatformIntegrationContractVersionRecordState,
  isValidPlatformIntegrationId,
  nextPlatformIntegrationContractCheckId,
  normalizePlatformIntegrationContractEvaluationResult,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationOptionalText,
  persistAuditEvent,
  platformIntegrationContractChecksById,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  toPlatformIntegrationContractCompatibilityCheckRecord
} = {}) => ({
createPlatformIntegrationContractCompatibilityCheck: async ({
      integrationId,
      contractType,
      baselineVersion,
      candidateVersion,
      evaluationResult,
      breakingChangeCount = 0,
      diffSummary = null,
      requestId,
      checkedByUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformIntegrationContractChecksById:
            structuredClone(platformIntegrationContractChecksById),
          nextPlatformIntegrationContractCheckId,
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
        const normalizedContractType = normalizePlatformIntegrationContractType(contractType);
        const normalizedBaselineVersion =
          normalizePlatformIntegrationContractVersion(baselineVersion);
        const normalizedCandidateVersion =
          normalizePlatformIntegrationContractVersion(candidateVersion);
        const normalizedEvaluationResult =
          normalizePlatformIntegrationContractEvaluationResult(evaluationResult);
        const normalizedBreakingChangeCount = Number(breakingChangeCount);
        const normalizedRequestId = String(requestId || '').trim();
        if (
          !isValidPlatformIntegrationId(normalizedIntegrationId)
          || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
          || !normalizedBaselineVersion
          || normalizedBaselineVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
          || !normalizedCandidateVersion
          || normalizedCandidateVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
          || !VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT.has(
            normalizedEvaluationResult
          )
          || !Number.isInteger(normalizedBreakingChangeCount)
          || normalizedBreakingChangeCount < 0
          || !normalizedRequestId
          || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
        ) {
          throw new Error(
            'createPlatformIntegrationContractCompatibilityCheck received invalid input'
          );
        }
        if (
          !findPlatformIntegrationContractVersionRecordState({
            integrationId: normalizedIntegrationId,
            contractType: normalizedContractType,
            contractVersion: normalizedBaselineVersion
          })
          || !findPlatformIntegrationContractVersionRecordState({
            integrationId: normalizedIntegrationId,
            contractType: normalizedContractType,
            contractVersion: normalizedCandidateVersion
          })
        ) {
          throw new Error(
            'createPlatformIntegrationContractCompatibilityCheck contract version not found'
          );
        }
        const checkRecord = toPlatformIntegrationContractCompatibilityCheckRecord({
          checkId: nextPlatformIntegrationContractCheckId,
          integrationId: normalizedIntegrationId,
          contractType: normalizedContractType,
          baselineVersion: normalizedBaselineVersion,
          candidateVersion: normalizedCandidateVersion,
          evaluationResult: normalizedEvaluationResult,
          breakingChangeCount: normalizedBreakingChangeCount,
          diffSummary,
          requestId: normalizedRequestId,
          checkedByUserId: normalizePlatformIntegrationOptionalText(checkedByUserId),
          checkedAt: new Date().toISOString()
        });
        platformIntegrationContractChecksById.set(
          Number(nextPlatformIntegrationContractCheckId),
          checkRecord
        );
        nextPlatformIntegrationContractCheckId += 1;
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              requestId: String(auditContext.requestId || normalizedRequestId).trim()
                || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'platform.integration.contract.compatibility_evaluated',
              actorUserId: auditContext.actorUserId || checkedByUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'integration_contract',
              targetId:
                `${normalizedIntegrationId}:${normalizedContractType}:${normalizedCandidateVersion}`,
              result: 'success',
              beforeState: null,
              afterState: {
                integration_id: normalizedIntegrationId,
                contract_type: normalizedContractType,
                baseline_version: normalizedBaselineVersion,
                candidate_version: normalizedCandidateVersion,
                evaluation_result: normalizedEvaluationResult,
                breaking_change_count: normalizedBreakingChangeCount
              }
            });
            auditRecorded = true;
          } catch (error) {
            const auditWriteError = new Error(
              'platform integration contract compatibility audit write failed'
            );
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
        }
        return {
          ...clonePlatformIntegrationContractCompatibilityCheckRecord(checkRecord),
          auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            platformIntegrationContractChecksById,
            snapshot.platformIntegrationContractChecksById
          );
          nextPlatformIntegrationContractCheckId = Number(
            snapshot.nextPlatformIntegrationContractCheckId || 1
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationContractCreatePlatformIntegrationContractCompatibilityCheck
};

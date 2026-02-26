'use strict';

const createPlatformMysqlAuthStoreIntegrationContractCreatePlatformIntegrationContractCompatibilityCheck = ({
  MAX_PLATFORM_INTEGRATION_CONTRACT_DIFF_SUMMARY_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  dbClient,
  executeWithDeadlockRetry,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractEvaluationResult,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationJsonForStorage,
  normalizePlatformIntegrationOptionalText,
  recordAuditEventWithQueryClient,
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
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'createPlatformIntegrationContractCompatibilityCheck',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedContractType =
              normalizePlatformIntegrationContractType(contractType);
            const normalizedBaselineVersion =
              normalizePlatformIntegrationContractVersion(baselineVersion);
            const normalizedCandidateVersion =
              normalizePlatformIntegrationContractVersion(candidateVersion);
            const normalizedEvaluationResult =
              normalizePlatformIntegrationContractEvaluationResult(evaluationResult);
            const normalizedRequestId = String(requestId || '').trim();
            const normalizedBreakingChangeCount = Number(breakingChangeCount);
            const normalizedDiffSummary = normalizePlatformIntegrationJsonForStorage({
              value: diffSummary
            });
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
              || !normalizedBaselineVersion
              || normalizedBaselineVersion.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
              || !normalizedCandidateVersion
              || normalizedCandidateVersion.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
              || !VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT.has(
                normalizedEvaluationResult
              )
              || !Number.isInteger(normalizedBreakingChangeCount)
              || normalizedBreakingChangeCount < 0
              || !normalizedRequestId
              || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
              || normalizedDiffSummary === undefined
              || (
                normalizedDiffSummary !== null
                && normalizedDiffSummary.length > MAX_PLATFORM_INTEGRATION_CONTRACT_DIFF_SUMMARY_LENGTH
              )
            ) {
              throw new Error(
                'createPlatformIntegrationContractCompatibilityCheck received invalid input'
              );
            }
            const insertResult = await tx.query(
              `
                INSERT INTO platform_integration_contract_compatibility_checks (
                  integration_id,
                  contract_type,
                  baseline_version,
                  candidate_version,
                  evaluation_result,
                  breaking_change_count,
                  diff_summary,
                  request_id,
                  checked_by_user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, CAST(? AS JSON), ?, ?)
              `,
              [
                normalizedIntegrationId,
                normalizedContractType,
                normalizedBaselineVersion,
                normalizedCandidateVersion,
                normalizedEvaluationResult,
                normalizedBreakingChangeCount,
                normalizedDiffSummary,
                normalizedRequestId,
                normalizePlatformIntegrationOptionalText(checkedByUserId)
              ]
            );
            const insertedCheckId = Number(insertResult?.insertId || 0);
            if (!Number.isInteger(insertedCheckId) || insertedCheckId < 1) {
              throw new Error(
                'createPlatformIntegrationContractCompatibilityCheck insert result malformed'
              );
            }
            const rows = await tx.query(
              `
                SELECT check_id,
                       integration_id,
                       contract_type,
                       baseline_version,
                       candidate_version,
                       evaluation_result,
                       breaking_change_count,
                       diff_summary,
                       request_id,
                       checked_by_user_id,
                       checked_at
                FROM platform_integration_contract_compatibility_checks
                WHERE check_id = ?
                LIMIT 1
              `,
              [insertedCheckId]
            );
            const createdRecord = toPlatformIntegrationContractCompatibilityCheckRecord(
              rows?.[0] || null
            );
            if (!createdRecord) {
              throw new Error(
                'createPlatformIntegrationContractCompatibilityCheck result unavailable'
              );
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || normalizedRequestId).trim()
                    || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.contract.compatibility_evaluated',
                  actorUserId: auditContext.actorUserId || checkedByUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_contract',
                  targetId: `${normalizedIntegrationId}:${normalizedContractType}:${normalizedCandidateVersion}`,
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
              ...createdRecord,
              auditRecorded
            };
          })
      })
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationContractCreatePlatformIntegrationContractCompatibilityCheck
};

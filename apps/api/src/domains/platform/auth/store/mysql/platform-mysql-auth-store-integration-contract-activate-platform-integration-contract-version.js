'use strict';

const createPlatformMysqlAuthStoreIntegrationContractActivatePlatformIntegrationContractVersion = ({
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  assertPlatformIntegrationWriteAllowedByFreezeGate,
  createPlatformIntegrationContractActivationBlockedError,
  dbClient,
  executeWithDeadlockRetry,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationOptionalText,
  recordAuditEventWithQueryClient,
  toPlatformIntegrationContractVersionRecord
} = {}) => ({
activatePlatformIntegrationContractVersion: async ({
      integrationId,
      contractType,
      contractVersion,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'activatePlatformIntegrationContractVersion',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedContractType =
              normalizePlatformIntegrationContractType(contractType);
            const normalizedContractVersion =
              normalizePlatformIntegrationContractVersion(contractVersion);
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
              || !normalizedContractVersion
              || normalizedContractVersion.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
            ) {
              throw new Error('activatePlatformIntegrationContractVersion received invalid input');
            }
            await assertPlatformIntegrationWriteAllowedByFreezeGate(tx);
            const scopeLockRows = await tx.query(
              `
                SELECT contract_id
                FROM platform_integration_contract_versions
                WHERE integration_id = ?
                  AND contract_type = ?
                ORDER BY contract_id ASC
                FOR UPDATE
              `,
              [
                normalizedIntegrationId,
                normalizedContractType
              ]
            );
            if (!Array.isArray(scopeLockRows)) {
              throw new Error(
                'activatePlatformIntegrationContractVersion scope lock malformed'
              );
            }
            const targetRows = await tx.query(
              `
                SELECT contract_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       schema_ref,
                       schema_checksum,
                       status,
                       is_backward_compatible,
                       compatibility_notes,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_contract_versions
                WHERE integration_id = ?
                  AND contract_type = ?
                  AND contract_version = ?
                LIMIT 1
                FOR UPDATE
              `,
              [
                normalizedIntegrationId,
                normalizedContractType,
                normalizedContractVersion
              ]
            );
            if (!Array.isArray(targetRows)) {
              throw new Error(
                'activatePlatformIntegrationContractVersion target query malformed'
              );
            }
            if (targetRows.length === 0) {
              return null;
            }
            const targetRecord = toPlatformIntegrationContractVersionRecord(
              targetRows[0]
            );
            if (!targetRecord) {
              throw new Error(
                'activatePlatformIntegrationContractVersion target row malformed'
              );
            }
            if (targetRecord.status === 'retired') {
              throw createPlatformIntegrationContractActivationBlockedError({
                integrationId: normalizedIntegrationId,
                contractType: normalizedContractType,
                contractVersion: normalizedContractVersion,
                reason: 'retired-version'
              });
            }
            if (targetRecord.status !== 'active') {
              await tx.query(
                `
                  UPDATE platform_integration_contract_versions
                  SET status = 'deprecated',
                      updated_by_user_id = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE integration_id = ?
                    AND contract_type = ?
                    AND status = 'active'
                    AND contract_version <> ?
                `,
                [
                  normalizePlatformIntegrationOptionalText(operatorUserId),
                  normalizedIntegrationId,
                  normalizedContractType,
                  normalizedContractVersion
                ]
              );
              await tx.query(
                `
                  UPDATE platform_integration_contract_versions
                  SET status = 'active',
                      updated_by_user_id = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE integration_id = ?
                    AND contract_type = ?
                    AND contract_version = ?
                `,
                [
                  normalizePlatformIntegrationOptionalText(operatorUserId)
                    || targetRecord.updatedByUserId,
                  normalizedIntegrationId,
                  normalizedContractType,
                  normalizedContractVersion
                ]
              );
            }
            const updatedRows = await tx.query(
              `
                SELECT contract_id,
                       integration_id,
                       contract_type,
                       contract_version,
                       schema_ref,
                       schema_checksum,
                       status,
                       is_backward_compatible,
                       compatibility_notes,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_contract_versions
                WHERE integration_id = ?
                  AND contract_type = ?
                  AND contract_version = ?
                LIMIT 1
              `,
              [
                normalizedIntegrationId,
                normalizedContractType,
                normalizedContractVersion
              ]
            );
            const updatedRecord = toPlatformIntegrationContractVersionRecord(
              updatedRows?.[0] || null
            );
            if (!updatedRecord) {
              throw new Error('activatePlatformIntegrationContractVersion result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.contract.activated',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_contract',
                  targetId: `${normalizedIntegrationId}:${normalizedContractType}:${normalizedContractVersion}`,
                  result: 'success',
                  beforeState: {
                    status: targetRecord.status
                  },
                  afterState: {
                    status: updatedRecord.status
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
              ...updatedRecord,
              previousStatus: targetRecord.status,
              currentStatus: updatedRecord.status,
              switched: targetRecord.status !== updatedRecord.status,
              auditRecorded
            };
          })
      })
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationContractActivatePlatformIntegrationContractVersion
};

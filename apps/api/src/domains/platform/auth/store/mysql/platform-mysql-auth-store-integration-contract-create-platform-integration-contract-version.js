'use strict';

const createPlatformMysqlAuthStoreIntegrationContractCreatePlatformIntegrationContractVersion = ({
  MAX_PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_NOTES_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_CHECKSUM_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_REF_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  MYSQL_DUP_ENTRY_ERRNO,
  PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN,
  VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  assertPlatformIntegrationWriteAllowedByFreezeGate,
  dbClient,
  executeWithDeadlockRetry,
  isDuplicateEntryError,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractSchemaChecksum,
  normalizePlatformIntegrationContractStatus,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationOptionalText,
  recordAuditEventWithQueryClient,
  toPlatformIntegrationContractVersionRecord
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
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'createPlatformIntegrationContractVersion',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedContractType =
              normalizePlatformIntegrationContractType(contractType);
            const normalizedContractVersion =
              normalizePlatformIntegrationContractVersion(contractVersion);
            const normalizedSchemaRef = normalizePlatformIntegrationOptionalText(schemaRef);
            const normalizedSchemaChecksum =
              normalizePlatformIntegrationContractSchemaChecksum(schemaChecksum);
            const normalizedStatus = normalizePlatformIntegrationContractStatus(status);
            const normalizedCompatibilityNotes =
              normalizePlatformIntegrationOptionalText(compatibilityNotes);
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
              || !normalizedContractVersion
              || normalizedContractVersion.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
              || !normalizedSchemaRef
              || normalizedSchemaRef.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_REF_LENGTH
              || !normalizedSchemaChecksum
              || normalizedSchemaChecksum.length
                > MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_CHECKSUM_LENGTH
              || !PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN.test(normalizedSchemaChecksum)
              || !VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS.has(normalizedStatus)
              || typeof isBackwardCompatible !== 'boolean'
              || (
                normalizedCompatibilityNotes !== null
                && normalizedCompatibilityNotes.length
                  > MAX_PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_NOTES_LENGTH
              )
            ) {
              throw new Error('createPlatformIntegrationContractVersion received invalid input');
            }
            await assertPlatformIntegrationWriteAllowedByFreezeGate(tx);
            try {
              await tx.query(
                `
                  INSERT INTO platform_integration_contract_versions (
                    integration_id,
                    contract_type,
                    contract_version,
                    schema_ref,
                    schema_checksum,
                    status,
                    is_backward_compatible,
                    compatibility_notes,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `,
                [
                  normalizedIntegrationId,
                  normalizedContractType,
                  normalizedContractVersion,
                  normalizedSchemaRef,
                  normalizedSchemaChecksum,
                  normalizedStatus,
                  isBackwardCompatible ? 1 : 0,
                  normalizedCompatibilityNotes,
                  normalizePlatformIntegrationOptionalText(operatorUserId),
                  normalizePlatformIntegrationOptionalText(operatorUserId)
                ]
              );
            } catch (error) {
              if (isDuplicateEntryError(error)) {
                const duplicateError = new Error(
                  'duplicate platform integration contract version'
                );
                duplicateError.code = 'ER_DUP_ENTRY';
                duplicateError.errno = MYSQL_DUP_ENTRY_ERRNO;
                duplicateError.platformIntegrationContractConflictTarget = 'contract_version';
                throw duplicateError;
              }
              throw error;
            }
            const rows = await tx.query(
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
            const createdRecord = toPlatformIntegrationContractVersionRecord(
              rows?.[0] || null
            );
            if (!createdRecord) {
              throw new Error('createPlatformIntegrationContractVersion result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.contract.created',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration_contract',
                  targetId: `${normalizedIntegrationId}:${normalizedContractType}:${normalizedContractVersion}`,
                  result: 'success',
                  beforeState: null,
                  afterState: {
                    integration_id: normalizedIntegrationId,
                    contract_type: normalizedContractType,
                    contract_version: normalizedContractVersion,
                    status: normalizedStatus,
                    is_backward_compatible: isBackwardCompatible
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
          })
      })
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationContractCreatePlatformIntegrationContractVersion
};

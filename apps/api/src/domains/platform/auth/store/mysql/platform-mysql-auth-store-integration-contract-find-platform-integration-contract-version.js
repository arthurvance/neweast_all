'use strict';

const createPlatformMysqlAuthStoreIntegrationContractFindPlatformIntegrationContractVersion = ({
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  dbClient,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationId,
  toPlatformIntegrationContractVersionRecord
} = {}) => ({
findPlatformIntegrationContractVersion: async ({
      integrationId,
      contractType,
      contractVersion
    } = {}) => {
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
        return null;
      }
      const rows = await dbClient.query(
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
      if (!Array.isArray(rows)) {
        throw new Error('findPlatformIntegrationContractVersion result malformed');
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRow = toPlatformIntegrationContractVersionRecord(rows[0]);
      if (!normalizedRow) {
        throw new Error('findPlatformIntegrationContractVersion result malformed');
      }
      return normalizedRow;
    }
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationContractFindPlatformIntegrationContractVersion
};

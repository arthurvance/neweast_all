'use strict';

const createPlatformMysqlAuthStoreIntegrationContractFindLatestActivePlatformIntegrationContractVersion = ({
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  dbClient,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationId,
  toPlatformIntegrationContractVersionRecord
} = {}) => ({
findLatestActivePlatformIntegrationContractVersion: async ({
      integrationId,
      contractType
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      const normalizedContractType = normalizePlatformIntegrationContractType(contractType);
      if (
        !isValidPlatformIntegrationId(normalizedIntegrationId)
        || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
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
            AND status = 'active'
          ORDER BY updated_at DESC, contract_id DESC
          LIMIT 1
        `,
        [
          normalizedIntegrationId,
          normalizedContractType
        ]
      );
      if (!Array.isArray(rows)) {
        throw new Error('findLatestActivePlatformIntegrationContractVersion result malformed');
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRow = toPlatformIntegrationContractVersionRecord(rows[0]);
      if (!normalizedRow) {
        throw new Error('findLatestActivePlatformIntegrationContractVersion result malformed');
      }
      return normalizedRow;
    }
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationContractFindLatestActivePlatformIntegrationContractVersion
};

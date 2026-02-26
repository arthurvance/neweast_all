'use strict';

const createPlatformMysqlAuthStoreIntegrationContractListPlatformIntegrationContractVersions = ({
  VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  dbClient,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractStatus,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationId,
  toPlatformIntegrationContractVersionRecord
} = {}) => ({
listPlatformIntegrationContractVersions: async ({
      integrationId,
      contractType = null,
      status = null
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
        return [];
      }
      const normalizedContractType = contractType === null || contractType === undefined
        ? null
        : normalizePlatformIntegrationContractType(contractType);
      if (
        normalizedContractType !== null
        && !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
      ) {
        throw new Error('listPlatformIntegrationContractVersions received invalid contractType');
      }
      const normalizedStatus = status === null || status === undefined
        ? null
        : normalizePlatformIntegrationContractStatus(status);
      if (
        normalizedStatus !== null
        && !VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS.has(normalizedStatus)
      ) {
        throw new Error('listPlatformIntegrationContractVersions received invalid status');
      }
      const whereClauses = ['integration_id = ?'];
      const queryArgs = [normalizedIntegrationId];
      if (normalizedContractType !== null) {
        whereClauses.push('contract_type = ?');
        queryArgs.push(normalizedContractType);
      }
      if (normalizedStatus !== null) {
        whereClauses.push('status = ?');
        queryArgs.push(normalizedStatus);
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
          WHERE ${whereClauses.join(' AND ')}
          ORDER BY created_at ASC, contract_id ASC
        `,
        queryArgs
      );
      if (!Array.isArray(rows)) {
        throw new Error('listPlatformIntegrationContractVersions result malformed');
      }
      const normalizedRows = rows.map((row) =>
        toPlatformIntegrationContractVersionRecord(row)
      );
      if (normalizedRows.some((row) => !row)) {
        throw new Error('listPlatformIntegrationContractVersions result malformed');
      }
      return normalizedRows;
    }
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationContractListPlatformIntegrationContractVersions
};

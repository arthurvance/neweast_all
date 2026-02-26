'use strict';

const createPlatformMysqlAuthStoreIntegrationContractFindLatestPlatformIntegrationContractCompatibilityCheck = ({
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  dbClient,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationId,
  toPlatformIntegrationContractCompatibilityCheckRecord
} = {}) => ({
findLatestPlatformIntegrationContractCompatibilityCheck: async ({
      integrationId,
      contractType,
      baselineVersion,
      candidateVersion
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      const normalizedContractType = normalizePlatformIntegrationContractType(contractType);
      const normalizedBaselineVersion =
        normalizePlatformIntegrationContractVersion(baselineVersion);
      const normalizedCandidateVersion =
        normalizePlatformIntegrationContractVersion(candidateVersion);
      if (
        !isValidPlatformIntegrationId(normalizedIntegrationId)
        || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
        || !normalizedBaselineVersion
        || normalizedBaselineVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
        || !normalizedCandidateVersion
        || normalizedCandidateVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      ) {
        return null;
      }
      const rows = await dbClient.query(
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
          WHERE integration_id = ?
            AND contract_type = ?
            AND baseline_version = ?
            AND candidate_version = ?
          ORDER BY checked_at DESC, check_id DESC
          LIMIT 1
        `,
        [
          normalizedIntegrationId,
          normalizedContractType,
          normalizedBaselineVersion,
          normalizedCandidateVersion
        ]
      );
      if (!Array.isArray(rows)) {
        throw new Error(
          'findLatestPlatformIntegrationContractCompatibilityCheck result malformed'
        );
      }
      if (rows.length === 0) {
        return null;
      }
      const normalizedRow = toPlatformIntegrationContractCompatibilityCheckRecord(
        rows[0]
      );
      if (!normalizedRow) {
        throw new Error(
          'findLatestPlatformIntegrationContractCompatibilityCheck result malformed'
        );
      }
      return normalizedRow;
    }
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationContractFindLatestPlatformIntegrationContractCompatibilityCheck
};

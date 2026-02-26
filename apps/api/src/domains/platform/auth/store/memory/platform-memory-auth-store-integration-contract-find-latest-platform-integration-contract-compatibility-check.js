'use strict';

const createPlatformMemoryAuthStoreIntegrationContractFindLatestPlatformIntegrationContractCompatibilityCheck = ({
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  clonePlatformIntegrationContractCompatibilityCheckRecord,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationId,
  platformIntegrationContractChecksById
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
      const matches = [...platformIntegrationContractChecksById.values()]
        .filter((entry) =>
          entry.integrationId === normalizedIntegrationId
          && entry.contractType === normalizedContractType
          && entry.baselineVersion === normalizedBaselineVersion
          && entry.candidateVersion === normalizedCandidateVersion
        )
        .sort((left, right) => {
          const leftCheckedAt = new Date(left.checkedAt).getTime();
          const rightCheckedAt = new Date(right.checkedAt).getTime();
          if (leftCheckedAt !== rightCheckedAt) {
            return rightCheckedAt - leftCheckedAt;
          }
          return Number(right.checkId || 0) - Number(left.checkId || 0);
        });
      return clonePlatformIntegrationContractCompatibilityCheckRecord(matches[0] || null);
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationContractFindLatestPlatformIntegrationContractCompatibilityCheck
};

'use strict';

const createPlatformMemoryAuthStoreIntegrationContractFindLatestActivePlatformIntegrationContractVersion = ({
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  clonePlatformIntegrationContractVersionRecord,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationId,
  platformIntegrationContractVersionsByKey
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
      const activeEntries = [...platformIntegrationContractVersionsByKey.values()]
        .filter((entry) =>
          entry.integrationId === normalizedIntegrationId
          && entry.contractType === normalizedContractType
          && entry.status === 'active'
        )
        .sort((left, right) => {
          const leftUpdatedAt = new Date(left.updatedAt).getTime();
          const rightUpdatedAt = new Date(right.updatedAt).getTime();
          if (leftUpdatedAt !== rightUpdatedAt) {
            return rightUpdatedAt - leftUpdatedAt;
          }
          return Number(right.contractId || 0) - Number(left.contractId || 0);
        });
      return clonePlatformIntegrationContractVersionRecord(activeEntries[0] || null);
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationContractFindLatestActivePlatformIntegrationContractVersion
};

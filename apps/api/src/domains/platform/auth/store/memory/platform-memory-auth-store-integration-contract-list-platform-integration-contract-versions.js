'use strict';

const createPlatformMemoryAuthStoreIntegrationContractListPlatformIntegrationContractVersions = ({
  VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  clonePlatformIntegrationContractVersionRecord,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractStatus,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationId,
  platformIntegrationContractVersionsByKey
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
      return [...platformIntegrationContractVersionsByKey.values()]
        .filter((entry) => {
          if (entry.integrationId !== normalizedIntegrationId) {
            return false;
          }
          if (
            normalizedContractType !== null
            && entry.contractType !== normalizedContractType
          ) {
            return false;
          }
          if (normalizedStatus !== null && entry.status !== normalizedStatus) {
            return false;
          }
          return true;
        })
        .sort((left, right) => {
          const leftCreatedAt = new Date(left.createdAt).getTime();
          const rightCreatedAt = new Date(right.createdAt).getTime();
          if (leftCreatedAt !== rightCreatedAt) {
            return leftCreatedAt - rightCreatedAt;
          }
          return Number(left.contractId || 0) - Number(right.contractId || 0);
        })
        .map((entry) => clonePlatformIntegrationContractVersionRecord(entry));
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationContractListPlatformIntegrationContractVersions
};

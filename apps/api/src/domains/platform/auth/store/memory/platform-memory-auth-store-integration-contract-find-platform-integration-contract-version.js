'use strict';

const createPlatformMemoryAuthStoreIntegrationContractFindPlatformIntegrationContractVersion = ({
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  clonePlatformIntegrationContractVersionRecord,
  findPlatformIntegrationContractVersionRecordState,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationId
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
      const existingState = findPlatformIntegrationContractVersionRecordState({
        integrationId: normalizedIntegrationId,
        contractType: normalizedContractType,
        contractVersion: normalizedContractVersion
      });
      return clonePlatformIntegrationContractVersionRecord(existingState?.record || null);
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationContractFindPlatformIntegrationContractVersion
};

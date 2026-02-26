'use strict';

const createPlatformMemoryAuthStoreIntegrationRecoveryFindPlatformIntegrationRecoveryQueueEntryByRecoveryId = ({
  MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH,
  clonePlatformIntegrationRecoveryQueueRecord,
  findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationRecoveryId
} = {}) => ({
findPlatformIntegrationRecoveryQueueEntryByRecoveryId: async ({
      integrationId,
      recoveryId
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(recoveryId);
      if (
        !isValidPlatformIntegrationId(normalizedIntegrationId)
        || !normalizedRecoveryId
        || normalizedRecoveryId.length > MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH
      ) {
        return null;
      }
      const existingState = findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId(
        normalizedRecoveryId
      );
      if (!existingState?.record) {
        return null;
      }
      if (existingState.record.integrationId !== normalizedIntegrationId) {
        return null;
      }
      return clonePlatformIntegrationRecoveryQueueRecord(existingState.record);
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationRecoveryFindPlatformIntegrationRecoveryQueueEntryByRecoveryId
};

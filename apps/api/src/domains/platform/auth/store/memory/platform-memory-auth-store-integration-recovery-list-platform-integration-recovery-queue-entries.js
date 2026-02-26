'use strict';

const createPlatformMemoryAuthStoreIntegrationRecoveryListPlatformIntegrationRecoveryQueueEntries = ({
  MAX_PLATFORM_INTEGRATION_RECOVERY_LIST_LIMIT,
  VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS,
  clonePlatformIntegrationRecoveryQueueRecord,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationRecoveryStatus,
  platformIntegrationRecoveryQueueByRecoveryId
} = {}) => ({
listPlatformIntegrationRecoveryQueueEntries: async ({
      integrationId,
      status = null,
      limit = 50
    } = {}) => {
      const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
      const normalizedStatus = status === null || status === undefined
        ? null
        : normalizePlatformIntegrationRecoveryStatus(status);
      const normalizedLimit = Number(limit);
      if (
        !isValidPlatformIntegrationId(normalizedIntegrationId)
        || (
          normalizedStatus !== null
          && !VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS.has(normalizedStatus)
        )
        || !Number.isInteger(normalizedLimit)
        || normalizedLimit < 1
        || normalizedLimit > MAX_PLATFORM_INTEGRATION_RECOVERY_LIST_LIMIT
      ) {
        throw new Error('listPlatformIntegrationRecoveryQueueEntries received invalid input');
      }
      return [...platformIntegrationRecoveryQueueByRecoveryId.values()]
        .filter((entry) => {
          if (entry.integrationId !== normalizedIntegrationId) {
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
            return rightCreatedAt - leftCreatedAt;
          }
          return String(right.recoveryId || '').localeCompare(
            String(left.recoveryId || '')
          );
        })
        .slice(0, normalizedLimit)
        .map((entry) => clonePlatformIntegrationRecoveryQueueRecord(entry));
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationRecoveryListPlatformIntegrationRecoveryQueueEntries
};

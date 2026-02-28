'use strict';

const createSharedMemoryAuthStoreSystemSensitiveConfigRuntimeCapability = ({
  VALID_SYSTEM_SENSITIVE_CONFIG_STATUS
} = {}) => {
  const normalizeSystemSensitiveConfigKey = (configKey) =>
    String(configKey || '').trim().toLowerCase();

  const normalizeSystemSensitiveConfigStatus = (status) => {
    const normalizedStatus = String(status || 'active').trim().toLowerCase();
    if (normalizedStatus === 'enabled') {
      return 'active';
    }
    return VALID_SYSTEM_SENSITIVE_CONFIG_STATUS.has(normalizedStatus)
      ? normalizedStatus
      : '';
  };

  const cloneSystemSensitiveConfigRecord = (record = null) =>
    record
      ? {
        key: record.key || record.configKey,
        configKey: record.configKey,
        value: record.value || record.encryptedValue,
        encryptedValue: record.encryptedValue,
        remark: record.remark || null,
        version: Number(record.version),
        previousVersion: Number(record.previousVersion || 0),
        status: record.status,
        updatedByUserId: record.updatedByUserId,
        updatedAt: record.updatedAt,
        createdByUserId: record.createdByUserId,
        createdAt: record.createdAt
      }
      : null;

  return {
    normalizeSystemSensitiveConfigKey,
    normalizeSystemSensitiveConfigStatus,
    cloneSystemSensitiveConfigRecord
  };
};

module.exports = {
  createSharedMemoryAuthStoreSystemSensitiveConfigRuntimeCapability
};

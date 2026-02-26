'use strict';

const createSharedMemoryAuthStorePlatformProfileNormalizationRuntimeCapability = ({
  normalizeOptionalTenantUserProfileField
} = {}) => {
  const normalizeRequiredPlatformUserProfileField = ({
    value,
    maxLength,
    fieldName
  } = {}) => {
    const normalized = normalizeOptionalTenantUserProfileField({
      value,
      maxLength
    });
    if (!normalized) {
      throw new Error(`${fieldName} must be non-empty string within max length`);
    }
    return normalized;
  };

  const normalizeOptionalPlatformUserProfileField = ({
    value,
    maxLength,
    fieldName
  } = {}) => {
    if (value === null || value === undefined) {
      return null;
    }
    if (typeof value !== 'string') {
      throw new Error(`${fieldName} must be string or null`);
    }
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }
    const normalized = normalizeOptionalTenantUserProfileField({
      value: trimmed,
      maxLength
    });
    if (!normalized) {
      throw new Error(`${fieldName} must be valid string`);
    }
    return normalized;
  };

  return {
    normalizeRequiredPlatformUserProfileField,
    normalizeOptionalPlatformUserProfileField
  };
};

module.exports = {
  createSharedMemoryAuthStorePlatformProfileNormalizationRuntimeCapability
};

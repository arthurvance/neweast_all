'use strict';

const {
  CONTROL_CHAR_PATTERN,
  VALID_TENANT_MEMBERSHIP_STATUS
} = require('../../../../../shared-kernel/auth/store/mysql/shared-mysql-auth-store-runtime-domain-constraint-constants');

const normalizeTenantUsershipStatus = (status) => {
  const value = String(status ?? '').trim().toLowerCase();
  if (!value) {
    return 'active';
  }
  if (value === 'enabled') {
    return 'active';
  }
  return VALID_TENANT_MEMBERSHIP_STATUS.has(value) ? value : '';
};

const normalizeTenantUsershipStatusForRead = (status) => {
  const value = String(status ?? '').trim().toLowerCase();
  if (!value) {
    return '';
  }
  if (value === 'enabled') {
    return 'active';
  }
  return VALID_TENANT_MEMBERSHIP_STATUS.has(value) ? value : '';
};

const normalizeOptionalTenantUserProfileField = ({
  value,
  maxLength
} = {}) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    return null;
  }
  const normalized = value.trim();
  if (
    !normalized
    || normalized.length > maxLength
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    return null;
  }
  return normalized;
};

const resolveOptionalTenantUserProfileField = (value) =>
  value === null || value === undefined
    ? null
    : value;

const isStrictOptionalTenantUserProfileField = ({
  value,
  maxLength
} = {}) => {
  const resolvedRawValue = resolveOptionalTenantUserProfileField(value);
  if (resolvedRawValue === null) {
    return true;
  }
  if (typeof resolvedRawValue !== 'string') {
    return false;
  }
  const normalized = normalizeOptionalTenantUserProfileField({
    value: resolvedRawValue,
    maxLength
  });
  return normalized !== null && normalized === resolvedRawValue;
};

module.exports = {
  normalizeTenantUsershipStatus,
  normalizeTenantUsershipStatusForRead,
  normalizeOptionalTenantUserProfileField,
  resolveOptionalTenantUserProfileField,
  isStrictOptionalTenantUserProfileField
};

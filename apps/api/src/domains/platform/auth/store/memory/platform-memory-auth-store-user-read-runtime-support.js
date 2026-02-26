'use strict';

const createPlatformMemoryAuthStoreUserReadRuntimeSupport = ({
  MAX_PLATFORM_ROLE_CODE_LENGTH,
  MAX_PLATFORM_ROLE_NAME_LENGTH,
  MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  VALID_PLATFORM_ROLE_CATALOG_STATUS,
  domainsByUserId,
  findPlatformRoleCatalogRecordStateByRoleId,
  isActiveLikeStatus,
  normalizeOptionalTenantUserProfileField,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleCatalogStatus,
  normalizeRequiredPlatformUserProfileField,
  platformProfilesByUserId,
  platformRolesByUserId
} = {}) => {
  const normalizeDateTimeFilterToEpoch = ({
    value,
    fieldName
  } = {}) => {
    if (value === null || value === undefined) {
      return null;
    }
    const normalizedValue = String(value || '').trim();
    if (!normalizedValue) {
      return null;
    }
    const parsedDate = new Date(normalizedValue);
    if (Number.isNaN(parsedDate.getTime())) {
      throw new Error(`listPlatformUsers ${fieldName} must be valid datetime`);
    }
    return parsedDate.getTime();
  };

  const resolveLatestPlatformProfileByUserId = (userId) => {
    const profile = platformProfilesByUserId.get(String(userId || '').trim()) || null;
    if (profile && typeof profile === 'object') {
      return {
        name: normalizeOptionalTenantUserProfileField({
          value: profile.name ?? null,
          maxLength: MAX_TENANT_USER_DISPLAY_NAME_LENGTH
        }),
        department: normalizeOptionalTenantUserProfileField({
          value: profile.department ?? null,
          maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
        })
      };
    }
    return {
      name: null,
      department: null
    };
  };

  const resolvePlatformUserReadModel = ({
    userId,
    userRecord
  } = {}) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedPhone = String(userRecord?.phone || '').trim();
    const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
    const platformStatus = userDomains.has('platform') ? 'active' : 'disabled';
    const profile = resolveLatestPlatformProfileByUserId(normalizedUserId);
    const createdAtRaw = userRecord?.createdAt ?? userRecord?.created_at ?? null;
    const createdAtDate = createdAtRaw ? new Date(createdAtRaw) : new Date();
    const createdAt = Number.isNaN(createdAtDate.getTime())
      ? new Date().toISOString()
      : createdAtDate.toISOString();
    const rawRoles = Array.isArray(platformRolesByUserId.get(normalizedUserId))
      ? platformRolesByUserId.get(normalizedUserId)
      : [];
    const roles = rawRoles
      .filter((role) => role && isActiveLikeStatus(role.status))
      .map((role) => {
        const normalizedRoleId = normalizePlatformRoleCatalogRoleId(role.roleId);
        if (!normalizedRoleId) {
          return null;
        }
        const roleCatalogEntry = findPlatformRoleCatalogRecordStateByRoleId(
          normalizedRoleId
        )?.record || null;
        const roleCode = roleCatalogEntry?.code === null || roleCatalogEntry?.code === undefined
          ? null
          : normalizeRequiredPlatformUserProfileField({
            value: roleCatalogEntry.code,
            maxLength: MAX_PLATFORM_ROLE_CODE_LENGTH,
            fieldName: 'role_code'
          });
        const roleName = roleCatalogEntry?.name === null || roleCatalogEntry?.name === undefined
          ? null
          : normalizeRequiredPlatformUserProfileField({
            value: roleCatalogEntry.name,
            maxLength: MAX_PLATFORM_ROLE_NAME_LENGTH,
            fieldName: 'role_name'
          });
        const normalizedRoleStatus = normalizePlatformRoleCatalogStatus(
          roleCatalogEntry?.status || 'disabled'
        );
        const roleStatus = VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedRoleStatus)
          ? normalizedRoleStatus
          : 'disabled';
        return {
          role_id: normalizedRoleId,
          code: roleCode,
          name: roleName,
          status: roleStatus
        };
      })
      .filter(Boolean)
      .sort((left, right) => String(left.role_id).localeCompare(String(right.role_id)));
    return {
      user_id: normalizedUserId,
      phone: normalizedPhone,
      name: profile.name,
      department: profile.department,
      status: platformStatus,
      created_at: createdAt,
      roles
    };
  };

  return {
    normalizeDateTimeFilterToEpoch,
    resolveLatestPlatformProfileByUserId,
    resolvePlatformUserReadModel
  };
};

module.exports = {
  createPlatformMemoryAuthStoreUserReadRuntimeSupport
};

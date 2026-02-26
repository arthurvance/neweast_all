'use strict';

const createTenantRoleCatalogDependencyCapabilities = ({
  authStore,
  errors,
  AuthProblemError,
  normalizePlatformRoleCatalogTenantIdForScope,
  normalizeRequiredStringField,
  normalizePlatformRoleIdKey,
  resolveRawCamelSnakeField,
  normalizeStrictRequiredStringField,
  toTenantPermissionCodeKey,
  isTenantPermissionCode,
  VALID_PLATFORM_ROLE_CATALOG_STATUS,
  VALID_PLATFORM_ROLE_CATALOG_SCOPE,
  SUPPORTED_TENANT_PERMISSION_CODE_SET,
  CONTROL_CHAR_PATTERN,
  ROLE_ID_ADDRESSABLE_PATTERN
} = {}) => {
  const loadValidatedTenantRoleCatalogEntries = async ({
    tenantId,
    roleIds = [],
    allowDisabledRoles = false
  }) => {
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: 'tenant',
      tenantId,
      allowEmptyForPlatform: false
    });
    const normalizedRoleIds = [...new Set(
      (Array.isArray(roleIds) ? roleIds : [])
        .map((roleId) => normalizeRequiredStringField(roleId, errors.invalidPayload).toLowerCase())
    )];
    const requestedRoleIdKeySet = new Set(
      normalizedRoleIds.map((roleId) => normalizePlatformRoleIdKey(roleId))
    );

    if (typeof authStore.findPlatformRoleCatalogEntriesByRoleIds !== 'function') {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-role-catalog-lookup-unsupported'
      });
    }

    let catalogEntries = [];
    try {
      catalogEntries = await authStore.findPlatformRoleCatalogEntriesByRoleIds({
        roleIds: normalizedRoleIds
      });
    } catch (_error) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-role-catalog-query-failed'
      });
    }

    const catalogEntriesByRoleIdKey = new Map();
    const seenRequestedRoleIdKeys = new Set();
    for (const catalogEntry of Array.isArray(catalogEntries) ? catalogEntries : []) {
      const rawRoleId = resolveRawCamelSnakeField(
        catalogEntry,
        'roleId',
        'role_id'
      );
      const roleId = normalizeStrictRequiredStringField(rawRoleId).toLowerCase();
      if (!roleId) {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-role-catalog-invalid'
        });
      }
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      if (!requestedRoleIdKeySet.has(roleIdKey)) {
        continue;
      }
      if (seenRequestedRoleIdKeys.has(roleIdKey)) {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-role-catalog-duplicate'
        });
      }
      seenRequestedRoleIdKeys.add(roleIdKey);
      catalogEntriesByRoleIdKey.set(roleIdKey, catalogEntry);
    }

    for (const roleId of normalizedRoleIds) {
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      const catalogEntry = catalogEntriesByRoleIdKey.get(roleIdKey);
      if (!catalogEntry) {
        throw errors.roleNotFound();
      }
      const normalizedStatusCandidate = normalizeStrictRequiredStringField(
        catalogEntry?.status
      ).toLowerCase();
      if (!VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatusCandidate)) {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-role-catalog-invalid'
        });
      }
      const normalizedStatus = normalizedStatusCandidate === 'enabled'
        ? 'active'
        : normalizedStatusCandidate;
      const normalizedScope = normalizeStrictRequiredStringField(
        catalogEntry?.scope
      ).toLowerCase();
      if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-role-catalog-invalid'
        });
      }
      const rawCatalogTenantId = resolveRawCamelSnakeField(
        catalogEntry,
        'tenantId',
        'tenant_id'
      );
      const normalizedCatalogTenantId =
        normalizeStrictRequiredStringField(rawCatalogTenantId);
      if (
        !normalizedCatalogTenantId
        || CONTROL_CHAR_PATTERN.test(normalizedCatalogTenantId)
      ) {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-role-catalog-invalid'
        });
      }
      if (
        (!allowDisabledRoles && normalizedStatus !== 'active')
        || normalizedScope !== 'tenant'
        || normalizedCatalogTenantId !== normalizedTenantId
      ) {
        throw errors.roleNotFound();
      }
    }

    return {
      normalizedTenantId,
      requestedRoleIds: normalizedRoleIds,
      catalogEntriesByRoleIdKey
    };
  };

  const loadTenantRolePermissionGrantsByRoleIds = async ({
    roleIds = []
  }) => {
    const normalizedRoleIds = [...new Set(
      (Array.isArray(roleIds) ? roleIds : [])
        .map((roleId) => normalizeRequiredStringField(roleId, errors.invalidPayload).toLowerCase())
    )];
    if (normalizedRoleIds.length === 0) {
      return new Map();
    }

    let grantEntries = [];
    try {
      if (typeof authStore.listTenantRolePermissionGrantsByRoleIds === 'function') {
        grantEntries = await authStore.listTenantRolePermissionGrantsByRoleIds({
          roleIds: normalizedRoleIds
        });
      } else if (typeof authStore.listTenantRolePermissionGrants === 'function') {
        grantEntries = await Promise.all(
          normalizedRoleIds.map(async (roleId) => ({
            roleId,
            permissionCodes: await authStore.listTenantRolePermissionGrants({
              roleId
            })
          }))
        );
      } else {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-role-permission-grants-unsupported'
        });
      }
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-role-permission-grants-query-failed'
      });
    }

    const grantsByRoleIdKey = new Map();
    for (const roleId of normalizedRoleIds) {
      grantsByRoleIdKey.set(normalizePlatformRoleIdKey(roleId), []);
    }
    const seenGrantEntriesByRoleIdKey = new Set();

    for (const grantEntry of Array.isArray(grantEntries) ? grantEntries : []) {
      const rawRoleId = resolveRawCamelSnakeField(
        grantEntry,
        'roleId',
        'role_id'
      );
      const strictRoleId = normalizeStrictRequiredStringField(rawRoleId);
      const roleId = strictRoleId.toLowerCase();
      if (
        !strictRoleId
        || strictRoleId !== roleId
        || CONTROL_CHAR_PATTERN.test(strictRoleId)
        || !ROLE_ID_ADDRESSABLE_PATTERN.test(roleId)
      ) {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-role-permission-grants-invalid'
        });
      }
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      if (!grantsByRoleIdKey.has(roleIdKey)) {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-role-permission-grants-invalid'
        });
      }
      if (seenGrantEntriesByRoleIdKey.has(roleIdKey)) {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-role-permission-grants-duplicate-role'
        });
      }
      seenGrantEntriesByRoleIdKey.add(roleIdKey);

      const hasPermissionCodes = (
        Array.isArray(grantEntry?.permissionCodes)
        || Array.isArray(grantEntry?.permission_codes)
      );
      if (!hasPermissionCodes) {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-role-permission-grants-invalid'
        });
      }
      const permissionCodes = Array.isArray(grantEntry?.permissionCodes)
        ? grantEntry.permissionCodes
        : grantEntry.permission_codes;
      const dedupedCodes = new Map();
      for (const permissionCode of permissionCodes) {
        const normalizedPermissionCode = normalizeStrictRequiredStringField(permissionCode);
        const permissionCodeKey = toTenantPermissionCodeKey(normalizedPermissionCode);
        if (!normalizedPermissionCode || normalizedPermissionCode !== permissionCodeKey) {
          throw errors.tenantUserDependencyUnavailable({
            reason: 'tenant-role-permission-grants-invalid'
          });
        }
        if (CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)) {
          throw errors.tenantUserDependencyUnavailable({
            reason: 'tenant-role-permission-grants-invalid'
          });
        }
        if (
          !isTenantPermissionCode(normalizedPermissionCode)
          || !SUPPORTED_TENANT_PERMISSION_CODE_SET.has(permissionCodeKey)
        ) {
          throw errors.tenantUserDependencyUnavailable({
            reason: 'tenant-role-permission-grants-invalid'
          });
        }
        if (dedupedCodes.has(permissionCodeKey)) {
          throw errors.tenantUserDependencyUnavailable({
            reason: 'tenant-role-permission-grants-invalid'
          });
        }
        dedupedCodes.set(permissionCodeKey, permissionCodeKey);
      }
      grantsByRoleIdKey.set(roleIdKey, [...dedupedCodes.values()]);
    }

    return grantsByRoleIdKey;
  };

  return {
    loadValidatedTenantRoleCatalogEntries,
    loadTenantRolePermissionGrantsByRoleIds
  };
};

module.exports = {
  createTenantRoleCatalogDependencyCapabilities
};

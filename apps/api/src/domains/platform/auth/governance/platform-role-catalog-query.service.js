'use strict';

const createPlatformRoleCatalogQueryCapabilities = ({
  authStore,
  errors,
  assertStoreMethod,
  normalizeRequiredStringField,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogTenantIdForScope,
  VALID_PLATFORM_ROLE_CATALOG_SCOPE,
  PLATFORM_ROLE_CATALOG_SCOPE
} = {}) => {
  const listPlatformRoleCatalogEntries = async ({
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null
  } = {}) => {
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    assertStoreMethod(authStore, 'listPlatformRoleCatalogEntries', 'authStore');
    return authStore.listPlatformRoleCatalogEntries({
      scope: normalizedScope,
      tenantId: normalizedTenantId
    });
  };

  const findPlatformRoleCatalogEntryByRoleId = async ({
    roleId,
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null
  } = {}) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    assertStoreMethod(authStore, 'findPlatformRoleCatalogEntryByRoleId', 'authStore');
    return authStore.findPlatformRoleCatalogEntryByRoleId({
      roleId: normalizedRoleId,
      scope: normalizedScope,
      tenantId: normalizedTenantId
    });
  };

  return {
    listPlatformRoleCatalogEntries,
    findPlatformRoleCatalogEntryByRoleId
  };
};

module.exports = {
  createPlatformRoleCatalogQueryCapabilities
};

'use strict';

const createPlatformRoleCatalogDependencyCapabilities = ({
  authStore,
  errors,
  isMissingPlatformRoleCatalogTableError,
  resolveRawRoleIdCandidate,
  normalizeRequiredStringField,
  normalizePlatformRoleIdKey,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogScope,
  normalizeStrictRequiredStringField,
  resolveRawCamelSnakeField,
  toPlatformPermissionCodeKey,
  isPlatformPermissionCode,
  VALID_PLATFORM_ROLE_CATALOG_STATUS,
  PLATFORM_ROLE_CATALOG_SCOPE,
  SUPPORTED_PLATFORM_PERMISSION_CODE_SET,
  CONTROL_CHAR_PATTERN,
  ROLE_ID_ADDRESSABLE_PATTERN
} = {}) => {
  const mapPlatformRoleCatalogLookupErrorToProblem = (error) => {
    if (isMissingPlatformRoleCatalogTableError(error)) {
      return errors.platformSnapshotDegraded({
        reason: 'platform-role-catalog-unavailable'
      });
    }
    return errors.platformSnapshotDegraded({
      reason: 'platform-role-catalog-query-failed'
    });
  };

  const assertPlatformRoleCatalogLookupCapability = () => {
    if (typeof authStore.findPlatformRoleCatalogEntriesByRoleIds !== 'function') {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-catalog-lookup-unsupported'
      });
    }
  };

  const assertPlatformRoleCatalogDependencyAvailable = async () => {
    assertPlatformRoleCatalogLookupCapability();
    if (typeof authStore.countPlatformRoleCatalogEntries === 'function') {
      try {
        await authStore.countPlatformRoleCatalogEntries();
        return;
      } catch (error) {
        throw mapPlatformRoleCatalogLookupErrorToProblem(error);
      }
    }
    try {
      await authStore.findPlatformRoleCatalogEntriesByRoleIds({
        roleIds: ['__platform_roles_health_probe__']
      });
    } catch (error) {
      throw mapPlatformRoleCatalogLookupErrorToProblem(error);
    }
  };

  const loadValidatedPlatformRoleCatalogEntriesForRoleFacts = async ({
    roles = [],
    allowDisabledRoles = false
  }) => {
    if (!Array.isArray(roles) || roles.length === 0) {
      await assertPlatformRoleCatalogDependencyAvailable();
      return {
        requestedRoleIds: [],
        catalogEntriesByRoleIdKey: new Map()
      };
    }
    assertPlatformRoleCatalogLookupCapability();

    const requestedRoleIds = [];
    const requestedRoleIdKeys = new Set();
    for (const role of roles) {
      const roleId = normalizeRequiredStringField(
        resolveRawRoleIdCandidate(role),
        errors.invalidPayload
      );
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      if (requestedRoleIdKeys.has(roleIdKey)) {
        continue;
      }
      requestedRoleIds.push(roleId);
      requestedRoleIdKeys.add(roleIdKey);
    }

    let catalogEntries = [];
    try {
      catalogEntries = await authStore.findPlatformRoleCatalogEntriesByRoleIds({
        roleIds: requestedRoleIds
      });
    } catch (error) {
      throw mapPlatformRoleCatalogLookupErrorToProblem(error);
    }
    const catalogEntriesByRoleIdKey = new Map();
    for (const catalogEntry of Array.isArray(catalogEntries) ? catalogEntries : []) {
      const roleId = String(
        catalogEntry?.roleId
        || catalogEntry?.role_id
        || ''
      ).trim();
      if (!roleId) {
        continue;
      }
      catalogEntriesByRoleIdKey.set(
        normalizePlatformRoleIdKey(roleId),
        catalogEntry
      );
    }

    for (const roleId of requestedRoleIds) {
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      const catalogEntry = catalogEntriesByRoleIdKey.get(roleIdKey);
      if (!catalogEntry) {
        throw errors.invalidPayload();
      }

      const normalizedStatus = normalizePlatformRoleCatalogStatus(
        catalogEntry?.status
      );
      const normalizedScope = normalizePlatformRoleCatalogScope(
        catalogEntry?.scope
      );
      if (
        !VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)
        || (!allowDisabledRoles && normalizedStatus === 'disabled')
        || normalizedScope !== PLATFORM_ROLE_CATALOG_SCOPE
      ) {
        throw errors.invalidPayload();
      }
    }

    return {
      requestedRoleIds,
      catalogEntriesByRoleIdKey
    };
  };

  const loadPlatformRolePermissionGrantsByRoleIds = async ({
    roleIds = []
  }) => {
    const normalizedRoleIds = [...new Set(
      (Array.isArray(roleIds) ? roleIds : [])
        .map((roleId) => normalizeRequiredStringField(roleId, errors.invalidPayload))
    )];
    if (normalizedRoleIds.length === 0) {
      return new Map();
    }

    if (typeof authStore.listPlatformRolePermissionGrantsByRoleIds !== 'function') {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-grants-unsupported'
      });
    }

    let grantEntries = [];
    try {
      grantEntries = await authStore.listPlatformRolePermissionGrantsByRoleIds({
        roleIds: normalizedRoleIds
      });
    } catch (_error) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-grants-query-failed'
      });
    }

    const grantsByRoleIdKey = new Map();
    for (const roleId of normalizedRoleIds) {
      grantsByRoleIdKey.set(normalizePlatformRoleIdKey(roleId), []);
    }

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
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-invalid'
        });
      }
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      if (!grantsByRoleIdKey.has(roleIdKey)) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-invalid'
        });
      }
      const hasPermissionCodes = (
        Array.isArray(grantEntry?.permissionCodes)
        || Array.isArray(grantEntry?.permission_codes)
      );
      if (!hasPermissionCodes) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-invalid'
        });
      }
      const permissionCodes = Array.isArray(grantEntry?.permissionCodes)
        ? grantEntry.permissionCodes
        : grantEntry.permission_codes;
      const dedupedCodes = new Map();
      for (const permissionCode of permissionCodes) {
        const normalizedPermissionCode = normalizeStrictRequiredStringField(permissionCode);
        const permissionCodeKey = toPlatformPermissionCodeKey(normalizedPermissionCode);
        if (
          !normalizedPermissionCode
          || normalizedPermissionCode !== permissionCodeKey
        ) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-grants-invalid'
          });
        }
        if (CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-grants-invalid'
          });
        }
        if (
          !isPlatformPermissionCode(normalizedPermissionCode)
          || !SUPPORTED_PLATFORM_PERMISSION_CODE_SET.has(permissionCodeKey)
        ) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-grants-invalid'
          });
        }
        if (dedupedCodes.has(permissionCodeKey)) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-grants-invalid'
          });
        }
        dedupedCodes.set(permissionCodeKey, permissionCodeKey);
      }
      grantsByRoleIdKey.set(roleIdKey, [...dedupedCodes.values()]);
    }

    return grantsByRoleIdKey;
  };

  return {
    loadValidatedPlatformRoleCatalogEntriesForRoleFacts,
    loadPlatformRolePermissionGrantsByRoleIds
  };
};

module.exports = {
  createPlatformRoleCatalogDependencyCapabilities
};

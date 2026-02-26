'use strict';

const createPlatformMemoryAuthStoreRepositorySessionAccessGovernance = ({
  bumpSessionVersionAndConvergeSessions,
  findPlatformRoleCatalogRecordStateByRoleId,
  isActiveLikeStatus,
  listPlatformRolePermissionGrantsForRoleId,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogTenantId,
  platformDomainKnownByUserId,
  platformPermissionsByUserId,
  platformRolesByUserId,
  syncPlatformPermissionFromRoleFacts,
  toPlatformPermissionCodeKey,
  domainsByUserId,
  PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
} = {}) => ({
  ensureDefaultDomainAccessForUser: async (userId) => {
    const normalizedUserId = String(userId);
    const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
    if (userDomains.has('platform')) {
      domainsByUserId.set(normalizedUserId, userDomains);
      platformDomainKnownByUserId.add(normalizedUserId);
      return { inserted: false };
    }
    if (platformDomainKnownByUserId.has(normalizedUserId)) {
      domainsByUserId.set(normalizedUserId, userDomains);
      return { inserted: false };
    }
    userDomains.add('platform');
    domainsByUserId.set(normalizedUserId, userDomains);
    platformDomainKnownByUserId.add(normalizedUserId);
    return { inserted: true };
  },

  findPlatformPermissionByUserId: async ({ userId }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return null;
    }
    const permission = platformPermissionsByUserId.get(normalizedUserId);
    return permission ? { ...permission } : null;
  },

  hasPlatformPermissionByUserId: async ({
    userId,
    permissionCode
  } = {}) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedPermissionCode = toPlatformPermissionCodeKey(permissionCode);
    if (
      !normalizedUserId
      || !normalizedPermissionCode
      || (
        normalizedPermissionCode !== PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE
        && normalizedPermissionCode !== PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
      )
    ) {
      return {
        canViewRoleManagement: false,
        canOperateRoleManagement: false,
        granted: false
      };
    }

    const roles = platformRolesByUserId.get(normalizedUserId) || [];
    let canViewRoleManagement = false;
    let canOperateRoleManagement = false;

    for (const role of roles) {
      if (!role || !isActiveLikeStatus(role.status)) {
        continue;
      }
      const roleCatalogEntry = findPlatformRoleCatalogRecordStateByRoleId(
        role.roleId
      )?.record || null;
      if (roleCatalogEntry) {
        const roleCatalogScope = normalizePlatformRoleCatalogScope(
          roleCatalogEntry.scope
        );
        const roleCatalogTenantId = normalizePlatformRoleCatalogTenantId(
          roleCatalogEntry.tenantId
        );
        const roleCatalogStatus = normalizePlatformRoleCatalogStatus(
          roleCatalogEntry.status
        );
        if (
          roleCatalogScope !== 'platform'
          || roleCatalogTenantId !== ''
          || !isActiveLikeStatus(roleCatalogStatus)
        ) {
          continue;
        }
      }
      const permission = role.permission || {};
      if (Boolean(permission.canViewRoleManagement ?? permission.can_view_role_management)) {
        canViewRoleManagement = true;
      }
      if (Boolean(permission.canOperateRoleManagement ?? permission.can_operate_role_management)) {
        canOperateRoleManagement = true;
        canViewRoleManagement = true;
      }

      const grantCodes = listPlatformRolePermissionGrantsForRoleId(role.roleId);
      if (grantCodes.includes(PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE)) {
        canOperateRoleManagement = true;
        canViewRoleManagement = true;
      } else if (grantCodes.includes(PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE)) {
        canViewRoleManagement = true;
      }

      if (canViewRoleManagement && canOperateRoleManagement) {
        break;
      }
    }

    const granted = normalizedPermissionCode === PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
      ? canOperateRoleManagement
      : canViewRoleManagement;
    return {
      canViewRoleManagement,
      canOperateRoleManagement,
      granted
    };
  },

  syncPlatformPermissionSnapshotByUserId: async ({
    userId,
    forceWhenNoRoleFacts = false
  }) =>
    syncPlatformPermissionFromRoleFacts({
      userId,
      forceWhenNoRoleFacts
    }),
});

module.exports = {
  createPlatformMemoryAuthStoreRepositorySessionAccessGovernance
};

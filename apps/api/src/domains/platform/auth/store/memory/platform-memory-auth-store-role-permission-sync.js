'use strict';

const createPlatformMemoryAuthStoreRolePermissionSync = ({
  buildEmptyPlatformPermission,
  bumpSessionVersionAndConvergeSessions,
  dedupePlatformRolesByRoleId,
  isSamePlatformPermission,
  listPlatformRolePermissionGrantsForRoleId,
  mergePlatformPermissionFromRoles,
  normalizePlatformRole,
  normalizePlatformRoleCatalogRoleId,
  platformPermissionsByUserId,
  platformRolesByUserId,
  replacePlatformRolePermissionGrantsForRoleId,
  repositoryMethods,
  syncPlatformPermissionFromRoleFacts,
  usersById
} = {}) => ({
listPlatformRolePermissionGrants: async ({ roleId }) =>
      listPlatformRolePermissionGrantsForRoleId(roleId),

listPlatformRolePermissionGrantsByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIds = [...new Set(
        (Array.isArray(roleIds) ? roleIds : [])
          .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
          .filter((roleId) => roleId.length > 0)
      )];
      return normalizedRoleIds.map((roleId) => ({
        roleId,
        permissionCodes: listPlatformRolePermissionGrantsForRoleId(roleId)
      }));
    },

replacePlatformRolePermissionGrants: async ({
      roleId,
      permissionCodes = []
    }) =>
      replacePlatformRolePermissionGrantsForRoleId({
        roleId,
        permissionCodes
      }),

findPlatformPermissionByUserId: repositoryMethods.findPlatformPermissionByUserId,

hasPlatformPermissionByUserId: repositoryMethods.hasPlatformPermissionByUserId,

syncPlatformPermissionSnapshotByUserId: repositoryMethods.syncPlatformPermissionSnapshotByUserId,

replacePlatformRolesAndSyncSnapshot: async ({ userId, roles = [] }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId || !usersById.has(normalizedUserId)) {
        return {
          synced: false,
          reason: 'invalid-user-id',
          permission: null
        };
      }

      const previousRoles = platformRolesByUserId.get(normalizedUserId) || [];
      const previousPermission = platformPermissionsByUserId.get(normalizedUserId)
        || mergePlatformPermissionFromRoles(previousRoles)
        || buildEmptyPlatformPermission();

      const normalizedRoles = dedupePlatformRolesByRoleId(
        (Array.isArray(roles) ? roles : [])
          .map((role) => normalizePlatformRole(role))
          .filter(Boolean)
      );
      platformRolesByUserId.set(normalizedUserId, normalizedRoles);
      const syncResult = syncPlatformPermissionFromRoleFacts({
        userId: normalizedUserId,
        forceWhenNoRoleFacts: true
      });

      const nextPermission = syncResult?.permission || buildEmptyPlatformPermission();
      if (!isSamePlatformPermission(previousPermission, nextPermission)) {
        bumpSessionVersionAndConvergeSessions({
          userId: normalizedUserId,
          reason: 'platform-role-facts-changed',
          revokeRefreshTokens: true,
          revokeAuthSessions: true
        });
      }

      return syncResult;
    }
});

module.exports = {
  createPlatformMemoryAuthStoreRolePermissionSync
};

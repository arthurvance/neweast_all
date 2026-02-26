'use strict';

const createPlatformMysqlAuthStoreRepositorySessionAccessGovernance = ({
  dbClient,
  normalizeOrgStatus,
  normalizeUserStatus,
  resolveActivePlatformPermissionSnapshotByUserIdTx,
  syncPlatformPermissionSnapshotByUserIdImpl,
  toBoolean,
  toPlatformPermissionCodeKey,
  VALID_PLATFORM_USER_STATUS,
  PLATFORM_ROLE_MANAGEMENT_PERMISSION_CODE_SET,
  PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
} = {}) => {
  const deniedRoleManagementPermission = {
    canViewRoleManagement: false,
    canOperateRoleManagement: false,
    granted: false
  };

  return {
    ensureDefaultDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { inserted: false };
      }
      const result = await dbClient.query(
        `
          INSERT IGNORE INTO platform_users (user_id, name, department, status)
          VALUES (?, NULL, NULL, 'active')
        `,
        [normalizedUserId]
      );

      return { inserted: Number(result?.affectedRows || 0) > 0 };
    },

    findPlatformPermissionByUserId: async ({ userId }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return null;
      }

      return resolveActivePlatformPermissionSnapshotByUserIdTx({
        txClient: dbClient,
        userId: normalizedUserId
      });
    },

    hasPlatformPermissionByUserId: async ({
      userId,
      permissionCode
    } = {}) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedPermissionCode = toPlatformPermissionCodeKey(permissionCode);
      if (
        !normalizedUserId
        || !PLATFORM_ROLE_MANAGEMENT_PERMISSION_CODE_SET.has(normalizedPermissionCode)
      ) {
        return deniedRoleManagementPermission;
      }

      const platformAccessRows = await dbClient.query(
        `
          SELECT pu.status AS platform_status,
                 u.status AS user_status
          FROM platform_users pu
          INNER JOIN iam_users u
            ON u.id = pu.user_id
          WHERE pu.user_id = ?
          LIMIT 1
        `,
        [normalizedUserId]
      );
      const platformAccess = platformAccessRows?.[0] || null;
      const platformStatus = normalizeOrgStatus(platformAccess?.platform_status || '');
      const userStatus = normalizeUserStatus(platformAccess?.user_status || '');
      if (
        !platformAccess
        || !VALID_PLATFORM_USER_STATUS.has(platformStatus)
        || platformStatus !== 'active'
        || userStatus !== 'active'
      ) {
        return deniedRoleManagementPermission;
      }

      const rows = await dbClient.query(
        `
          SELECT MAX(
                   CASE
                     WHEN prg.permission_code = ? THEN 1
                     ELSE 0
                   END
                 ) AS can_view_role_management,
                 MAX(
                   CASE
                     WHEN prg.permission_code = ? THEN 1
                     ELSE 0
                   END
                 ) AS can_operate_role_management
          FROM platform_user_roles upr
          INNER JOIN platform_roles prc
            ON prc.role_id = upr.role_id
           AND prc.scope = 'platform'
           AND prc.tenant_id = ''
           AND prc.status IN ('active', 'enabled')
          LEFT JOIN platform_role_permission_grants prg
            ON prg.role_id = upr.role_id
           AND prg.permission_code IN (?, ?)
          WHERE upr.user_id = ?
            AND upr.status IN ('active', 'enabled')
        `,
        [
          PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
          PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
          PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
          PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
          normalizedUserId
        ]
      );
      const row = rows?.[0] || null;
      const canOperateRoleManagement = toBoolean(row?.can_operate_role_management);
      const canViewRoleManagement =
        canOperateRoleManagement || toBoolean(row?.can_view_role_management);
      const granted =
        normalizedPermissionCode === PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
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
      syncPlatformPermissionSnapshotByUserIdImpl({
        userId,
        forceWhenNoRoleFacts
      }),
  };
};

module.exports = {
  createPlatformMysqlAuthStoreRepositorySessionAccessGovernance
};

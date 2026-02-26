'use strict';

const createPlatformMysqlAuthStoreRoleSnapshotRuntimeSupport = ({
  VALID_PLATFORM_USER_STATUS,
  aggregatePlatformPermissionFromRoleRows,
  bumpSessionVersionAndConvergeSessionsTx,
  dbClient,
  dedupePlatformRoleFacts,
  executeWithDeadlockRetry,
  isSamePlatformPermissionSnapshot,
  normalizeOrgStatus,
  normalizeUserStatus,
  toPlatformPermissionSnapshot,
  toPlatformPermissionSnapshotFromCodes
} = {}) => {
  const resolveActivePlatformPermissionSnapshotByUserIdTx = async ({
    txClient = dbClient,
    userId
  } = {}) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return null;
    }

    const platformUserRows = await txClient.query(
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
    const platformUser = platformUserRows?.[0] || null;
    if (!platformUser) {
      return null;
    }

    const normalizedPlatformStatus = normalizeOrgStatus(platformUser.platform_status);
    const normalizedUserStatus = normalizeUserStatus(platformUser.user_status);
    if (
      !VALID_PLATFORM_USER_STATUS.has(normalizedPlatformStatus)
      || normalizedPlatformStatus !== 'active'
      || normalizedUserStatus !== 'active'
    ) {
      return null;
    }

    const grantRows = await txClient.query(
      `
        SELECT prg.permission_code
        FROM platform_user_roles upr
        INNER JOIN platform_roles prc
          ON prc.role_id = upr.role_id
         AND prc.scope = 'platform'
         AND prc.tenant_id = ''
         AND prc.status IN ('active', 'enabled')
        LEFT JOIN platform_role_permission_grants prg
          ON prg.role_id = upr.role_id
        WHERE upr.user_id = ?
          AND upr.status IN ('active', 'enabled')
      `,
      [normalizedUserId]
    );
    const permissionCodes = (Array.isArray(grantRows) ? grantRows : [])
      .map((row) => String(row?.permission_code || '').trim())
      .filter((permissionCode) => permissionCode.length > 0);
    const permissionSnapshot = toPlatformPermissionSnapshotFromCodes(permissionCodes);
    return toPlatformPermissionSnapshot(permissionSnapshot);
  };

  const syncPlatformPermissionSnapshotByUserIdOnce = async ({
    userId,
    forceWhenNoRoleFacts = false,
    txClient = dbClient
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return {
        synced: false,
        reason: 'invalid-user-id',
        permission: null
      };
    }
    const permission = await resolveActivePlatformPermissionSnapshotByUserIdTx({
      txClient,
      userId: normalizedUserId
    });
    if (!permission) {
      if (forceWhenNoRoleFacts) {
        return {
          synced: false,
          reason: 'already-empty',
          permission: toPlatformPermissionSnapshot()
        };
      }
      return {
        synced: false,
        reason: 'no-role-facts',
        permission: null
      };
    }
    return {
      synced: false,
      reason: 'up-to-date',
      permission
    };
  };

  const syncPlatformPermissionSnapshotByUserId = async ({
    userId,
    forceWhenNoRoleFacts = false,
    txClient = dbClient
  }) =>
    executeWithDeadlockRetry({
      operation: 'syncPlatformPermissionSnapshotByUserId',
      execute: () =>
        syncPlatformPermissionSnapshotByUserIdOnce({
          userId,
          forceWhenNoRoleFacts,
          txClient
        })
    });

  const replacePlatformRolesAndSyncSnapshotInTx = async ({
    txClient,
    userId,
    roles = []
  }) => {
    const transactionalClient = txClient || dbClient;
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return {
        synced: false,
        reason: 'invalid-user-id',
        permission: null
      };
    }

    const normalizedRoles = dedupePlatformRoleFacts(roles);

    const userRows = await transactionalClient.query(
      `
        SELECT id
        FROM iam_users
        WHERE id = ?
        LIMIT 1
        FOR UPDATE
      `,
      [normalizedUserId]
    );
    if (!userRows?.[0]) {
      return {
        synced: false,
        reason: 'invalid-user-id',
        permission: null
      };
    }

    await transactionalClient.query(
      `
        INSERT INTO platform_users (
          user_id,
          name,
          department,
          status
        )
        VALUES (?, NULL, NULL, 'active')
        ON DUPLICATE KEY UPDATE
          updated_at = updated_at
      `,
      [normalizedUserId]
    );

    const previousRoleRows = await transactionalClient.query(
      `
        SELECT status,
               can_view_user_management,
               can_operate_user_management,
               can_view_tenant_management,
               can_operate_tenant_management
        FROM platform_user_roles
        WHERE user_id = ?
      `,
      [normalizedUserId]
    );
    const previousPermission = aggregatePlatformPermissionFromRoleRows(previousRoleRows).permission;

    await transactionalClient.query(
      `
        DELETE FROM platform_user_roles
        WHERE user_id = ?
      `,
      [normalizedUserId]
    );

    for (const role of normalizedRoles) {
      await transactionalClient.query(
        `
          INSERT INTO platform_user_roles (
            user_id,
            role_id,
            status,
            can_view_user_management,
            can_operate_user_management,
            can_view_tenant_management,
            can_operate_tenant_management
          )
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `,
        [
          normalizedUserId,
          role.roleId,
          role.status,
          Number(role.canViewUserManagement),
          Number(role.canOperateUserManagement),
          Number(role.canViewTenantManagement),
          Number(role.canOperateTenantManagement)
        ]
      );
    }

    const permission = aggregatePlatformPermissionFromRoleRows(normalizedRoles).permission;

    if (!isSamePlatformPermissionSnapshot(previousPermission, permission)) {
      await bumpSessionVersionAndConvergeSessionsTx({
        txClient: transactionalClient,
        userId: normalizedUserId,
        reason: 'platform-role-facts-changed',
        revokeRefreshTokens: true,
        revokeAuthSessions: true
      });
    }

    return {
      synced: true,
      reason: 'ok',
      permission
    };
  };

  const replacePlatformRolesAndSyncSnapshotOnce = async ({ userId, roles = [] }) =>
    dbClient.inTransaction(async (tx) =>
      replacePlatformRolesAndSyncSnapshotInTx({
        txClient: tx,
        userId,
        roles
      }));

  const replacePlatformRolesAndSyncSnapshot = async ({ userId, roles = [] }) =>
    executeWithDeadlockRetry({
      operation: 'replacePlatformRolesAndSyncSnapshot',
      execute: () =>
        replacePlatformRolesAndSyncSnapshotOnce({
          userId,
          roles
        })
    });

  return {
    replacePlatformRolesAndSyncSnapshot,
    replacePlatformRolesAndSyncSnapshotInTx,
    replacePlatformRolesAndSyncSnapshotOnce,
    resolveActivePlatformPermissionSnapshotByUserIdTx,
    syncPlatformPermissionSnapshotByUserId,
    syncPlatformPermissionSnapshotByUserIdOnce
  };
};

module.exports = {
  createPlatformMysqlAuthStoreRoleSnapshotRuntimeSupport
};

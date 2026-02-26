'use strict';

const createPlatformMysqlAuthStoreRolePermissionSync = ({
  DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS,
  buildSqlInPlaceholders,
  createPlatformRolePermissionGrantDataError,
  dbClient,
  deadlockMetricsByOperation,
  executeWithDeadlockRetry,
  normalizePlatformPermissionCodes,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleStatus,
  normalizeStrictPlatformPermissionCodeFromGrantRow,
  normalizeStrictRoleIdFromPlatformGrantRow,
  recordAuditEventWithQueryClient,
  replacePlatformRolesAndSyncSnapshot,
  replacePlatformRolesAndSyncSnapshotInTx,
  repositoryMethods,
  syncPlatformPermissionSnapshotByUserId,
  toDeadlockRates,
  toPlatformPermissionSnapshotFromGrantCodes
} = {}) => ({
listPlatformRolePermissionGrants: async ({ roleId }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT permission_code
          FROM platform_role_permission_grants
          WHERE role_id = ?
          ORDER BY permission_code ASC
        `,
        [normalizedRoleId]
      );
      const normalizedPermissionCodeKeys = [];
      const seenPermissionCodeKeys = new Set();
      for (const row of Array.isArray(rows) ? rows : []) {
        const permissionCodeKey = normalizeStrictPlatformPermissionCodeFromGrantRow(
          row?.permission_code,
          'platform-role-permission-grants-invalid-permission-code'
        );
        if (seenPermissionCodeKeys.has(permissionCodeKey)) {
          throw createPlatformRolePermissionGrantDataError(
            'platform-role-permission-grants-duplicate-permission-code'
          );
        }
        seenPermissionCodeKeys.add(permissionCodeKey);
        normalizedPermissionCodeKeys.push(permissionCodeKey);
      }
      return normalizedPermissionCodeKeys;
    },

listPlatformRolePermissionGrantsByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIds = [...new Set(
        (Array.isArray(roleIds) ? roleIds : [])
          .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
          .filter((roleId) => roleId.length > 0)
      )];
      if (normalizedRoleIds.length === 0) {
        return [];
      }
      const placeholders = buildSqlInPlaceholders(normalizedRoleIds.length);
      const rows = await dbClient.query(
        `
          SELECT role_id, permission_code
          FROM platform_role_permission_grants
          WHERE role_id IN (${placeholders})
          ORDER BY role_id ASC, permission_code ASC
        `,
        normalizedRoleIds
      );
      const grantsByRoleId = new Map();
      for (const roleId of normalizedRoleIds) {
        grantsByRoleId.set(roleId, []);
      }
      const seenGrantPermissionCodeKeysByRoleId = new Map(
        normalizedRoleIds.map((roleId) => [roleId, new Set()])
      );
      for (const row of Array.isArray(rows) ? rows : []) {
        const roleId = normalizeStrictRoleIdFromPlatformGrantRow(
          row?.role_id,
          'platform-role-permission-grants-invalid-role-id'
        );
        if (!grantsByRoleId.has(roleId)) {
          throw createPlatformRolePermissionGrantDataError(
            'platform-role-permission-grants-unexpected-role-id'
          );
        }
        const permissionCodeKey = normalizeStrictPlatformPermissionCodeFromGrantRow(
          row?.permission_code,
          'platform-role-permission-grants-invalid-permission-code'
        );
        const seenPermissionCodeKeys = seenGrantPermissionCodeKeysByRoleId.get(roleId);
        if (seenPermissionCodeKeys.has(permissionCodeKey)) {
          throw createPlatformRolePermissionGrantDataError(
            'platform-role-permission-grants-duplicate-permission-code'
          );
        }
        seenPermissionCodeKeys.add(permissionCodeKey);
        grantsByRoleId.get(roleId).push(permissionCodeKey);
      }
      return [...grantsByRoleId.entries()].map(([roleId, permissionCodes]) => ({
        roleId,
        permissionCodes: [...permissionCodes]
      }));
    },

replacePlatformRolePermissionGrants: async ({
      roleId,
      permissionCodes = [],
      operatorUserId = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        throw new Error('replacePlatformRolePermissionGrants requires roleId');
      }
      const normalizedPermissionCodes = normalizePlatformPermissionCodes(permissionCodes);
      return executeWithDeadlockRetry({
        operation: 'replacePlatformRolePermissionGrants',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const roleRows = await tx.query(
              `
                SELECT role_id
                FROM platform_roles
                WHERE role_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedRoleId]
            );
            if (!roleRows?.[0]) {
              return null;
            }

            await tx.query(
              `
                DELETE FROM platform_role_permission_grants
                WHERE role_id = ?
              `,
              [normalizedRoleId]
            );

            for (const permissionCode of normalizedPermissionCodes) {
              await tx.query(
                `
                  INSERT INTO platform_role_permission_grants (
                    role_id,
                    permission_code,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedRoleId,
                  permissionCode,
                  operatorUserId ? String(operatorUserId) : null,
                  operatorUserId ? String(operatorUserId) : null
                ]
              );
            }

            const grantRows = await tx.query(
              `
                SELECT permission_code
                FROM platform_role_permission_grants
                WHERE role_id = ?
                ORDER BY permission_code ASC
              `,
              [normalizedRoleId]
            );
            const savedPermissionCodeKeys = [];
            const seenSavedPermissionCodeKeys = new Set();
            for (const row of Array.isArray(grantRows) ? grantRows : []) {
              const permissionCodeKey = normalizeStrictPlatformPermissionCodeFromGrantRow(
                row?.permission_code,
                'platform-role-permission-grants-invalid-permission-code'
              );
              if (seenSavedPermissionCodeKeys.has(permissionCodeKey)) {
                throw createPlatformRolePermissionGrantDataError(
                  'platform-role-permission-grants-duplicate-permission-code'
                );
              }
              seenSavedPermissionCodeKeys.add(permissionCodeKey);
              savedPermissionCodeKeys.push(permissionCodeKey);
            }
            return savedPermissionCodeKeys;
          })
      });
    },

replacePlatformRolePermissionGrantsAndSyncSnapshots: async ({
      roleId,
      permissionCodes = [],
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null,
      maxAffectedUsers = DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        throw new Error('replacePlatformRolePermissionGrantsAndSyncSnapshots requires roleId');
      }
      const normalizedPermissionCodes = normalizePlatformPermissionCodes(permissionCodes);
      const normalizedMaxAffectedUsers = Math.max(
        1,
        Math.floor(Number(maxAffectedUsers || DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS))
      );
      return executeWithDeadlockRetry({
        operation: 'replacePlatformRolePermissionGrantsAndSyncSnapshots',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const roleRows = await tx.query(
              `
                SELECT role_id
                FROM platform_roles
                WHERE role_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedRoleId]
            );
            if (!roleRows?.[0]) {
              return null;
            }

            const affectedUserRows = await tx.query(
              `
                SELECT user_id
                FROM platform_user_roles
                WHERE role_id = ?
                ORDER BY user_id ASC
                FOR UPDATE
              `,
              [normalizedRoleId]
            );
            const affectedUserIds = [
              ...new Set(
                (Array.isArray(affectedUserRows) ? affectedUserRows : [])
                  .map((row) => String(row?.user_id || '').trim())
                  .filter((userId) => userId.length > 0)
              )
            ];
            if (affectedUserIds.length > normalizedMaxAffectedUsers) {
              const limitError = new Error('platform role permission affected users exceed limit');
              limitError.code = 'ERR_PLATFORM_ROLE_PERMISSION_AFFECTED_USERS_OVER_LIMIT';
              limitError.maxAffectedUsers = normalizedMaxAffectedUsers;
              limitError.affectedUsers = affectedUserIds.length;
              throw limitError;
            }
            const previousGrantRows = await tx.query(
              `
                SELECT permission_code
                FROM platform_role_permission_grants
                WHERE role_id = ?
                ORDER BY permission_code ASC
                FOR UPDATE
              `,
              [normalizedRoleId]
            );
            const previousPermissionCodes = [];
            const seenPreviousPermissionCodeKeys = new Set();
            for (const row of Array.isArray(previousGrantRows) ? previousGrantRows : []) {
              const permissionCodeKey = normalizeStrictPlatformPermissionCodeFromGrantRow(
                row?.permission_code,
                'platform-role-permission-grants-invalid-permission-code'
              );
              if (seenPreviousPermissionCodeKeys.has(permissionCodeKey)) {
                throw createPlatformRolePermissionGrantDataError(
                  'platform-role-permission-grants-duplicate-permission-code'
                );
              }
              seenPreviousPermissionCodeKeys.add(permissionCodeKey);
              previousPermissionCodes.push(permissionCodeKey);
            }

            await tx.query(
              `
                DELETE FROM platform_role_permission_grants
                WHERE role_id = ?
              `,
              [normalizedRoleId]
            );

            for (const permissionCode of normalizedPermissionCodes) {
              await tx.query(
                `
                  INSERT INTO platform_role_permission_grants (
                    role_id,
                    permission_code,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedRoleId,
                  permissionCode,
                  operatorUserId ? String(operatorUserId) : null,
                  operatorUserId ? String(operatorUserId) : null
                ]
              );
            }

            const grantCodesByRoleId = new Map();
            grantCodesByRoleId.set(normalizedRoleId, [...normalizedPermissionCodes]);

            for (const affectedUserId of affectedUserIds) {
              const roleRowsForUser = await tx.query(
                `
                  SELECT role_id, status
                  FROM platform_user_roles
                  WHERE user_id = ?
                  ORDER BY role_id ASC
                  FOR UPDATE
                `,
                [affectedUserId]
              );

              const normalizedRoleIdsForUser = [
                ...new Set(
                  (Array.isArray(roleRowsForUser) ? roleRowsForUser : [])
                    .map((row) => normalizePlatformRoleCatalogRoleId(row?.role_id))
                    .filter((candidateRoleId) => candidateRoleId.length > 0)
                )
              ];
              const missingGrantRoleIds = normalizedRoleIdsForUser.filter(
                (candidateRoleId) => !grantCodesByRoleId.has(candidateRoleId)
              );
              if (missingGrantRoleIds.length > 0) {
                const placeholders = buildSqlInPlaceholders(missingGrantRoleIds.length);
                const grantRows = await tx.query(
                  `
                    SELECT role_id, permission_code
                    FROM platform_role_permission_grants
                    WHERE role_id IN (${placeholders})
                    ORDER BY role_id ASC, permission_code ASC
                  `,
                  missingGrantRoleIds
                );
                for (const roleIdKey of missingGrantRoleIds) {
                  grantCodesByRoleId.set(roleIdKey, []);
                }
                const seenGrantPermissionCodeKeysByRoleId = new Map(
                  missingGrantRoleIds.map((roleIdKey) => [roleIdKey, new Set()])
                );
                for (const row of Array.isArray(grantRows) ? grantRows : []) {
                  const roleIdKey = normalizeStrictRoleIdFromPlatformGrantRow(
                    row?.role_id,
                    'platform-role-permission-grants-invalid-role-id'
                  );
                  if (!grantCodesByRoleId.has(roleIdKey)) {
                    throw createPlatformRolePermissionGrantDataError(
                      'platform-role-permission-grants-unexpected-role-id'
                    );
                  }
                  const permissionCodeKey = normalizeStrictPlatformPermissionCodeFromGrantRow(
                    row?.permission_code,
                    'platform-role-permission-grants-invalid-permission-code'
                  );
                  const seenPermissionCodeKeys = seenGrantPermissionCodeKeysByRoleId.get(
                    roleIdKey
                  );
                  if (seenPermissionCodeKeys.has(permissionCodeKey)) {
                    throw createPlatformRolePermissionGrantDataError(
                      'platform-role-permission-grants-duplicate-permission-code'
                    );
                  }
                  seenPermissionCodeKeys.add(permissionCodeKey);
                  grantCodesByRoleId.get(roleIdKey).push(permissionCodeKey);
                }
                for (const roleIdKey of missingGrantRoleIds) {
                  grantCodesByRoleId.set(roleIdKey, [...(grantCodesByRoleId.get(roleIdKey) || [])]);
                }
              }

              const nextRoles = (Array.isArray(roleRowsForUser) ? roleRowsForUser : [])
                .map((row) => {
                  const normalizedRoleIdForUser = normalizePlatformRoleCatalogRoleId(row?.role_id);
                  if (!normalizedRoleIdForUser) {
                    return null;
                  }
                  const permissionSnapshot = toPlatformPermissionSnapshotFromGrantCodes(
                    grantCodesByRoleId.get(normalizedRoleIdForUser) || []
                  );
                  return {
                    roleId: normalizedRoleIdForUser,
                    status: normalizePlatformRoleStatus(row?.status),
                    canViewUserManagement: permissionSnapshot.canViewUserManagement,
                    canOperateUserManagement: permissionSnapshot.canOperateUserManagement,
                    canViewTenantManagement: permissionSnapshot.canViewTenantManagement,
                    canOperateTenantManagement: permissionSnapshot.canOperateTenantManagement
                  };
                })
                .filter(Boolean);

              const syncResult = await replacePlatformRolesAndSyncSnapshotInTx({
                txClient: tx,
                userId: affectedUserId,
                roles: nextRoles
              });
              const syncReason = String(syncResult?.reason || 'unknown')
                .trim()
                .toLowerCase();
              if (syncReason !== 'ok') {
                const syncError = new Error(
                  `platform role permission sync failed: ${syncReason || 'unknown'}`
                );
                syncError.code = 'ERR_PLATFORM_ROLE_PERMISSION_SYNC_FAILED';
                syncError.syncReason = syncReason || 'unknown';
                throw syncError;
              }
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  tenantId: null,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.platform_role_permission_grants.updated',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'role_permission_grants',
                  targetId: normalizedRoleId,
                  result: 'success',
                  beforeState: {
                    permission_codes: [...previousPermissionCodes]
                  },
                  afterState: {
                    permission_codes: [...normalizedPermissionCodes]
                  },
                  metadata: {
                    affected_user_count: affectedUserIds.length
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform role permission grants audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }

            return {
              roleId: normalizedRoleId,
              permissionCodes: [...normalizedPermissionCodes],
              affectedUserIds: [...affectedUserIds],
              affectedUserCount: affectedUserIds.length,
              auditRecorded
            };
          })
      });
    },

findPlatformPermissionByUserId: repositoryMethods.findPlatformPermissionByUserId,

hasPlatformPermissionByUserId: repositoryMethods.hasPlatformPermissionByUserId,

syncPlatformPermissionSnapshotByUserId: repositoryMethods.syncPlatformPermissionSnapshotByUserId,

replacePlatformRolesAndSyncSnapshot: async ({ userId, roles = [] }) =>
      replacePlatformRolesAndSyncSnapshot({
        userId,
        roles
      }),

getPlatformDeadlockMetrics: () =>
      Object.fromEntries(
        [...deadlockMetricsByOperation.entries()].map(([operation, metrics]) => {
          const rates = toDeadlockRates(metrics);
          return [
            operation,
            {
              deadlockCount: Number(metrics.deadlockCount),
              retrySuccessCount: Number(metrics.retrySuccessCount),
              finalFailureCount: Number(metrics.finalFailureCount),
              retrySuccessRate: Number(rates.retrySuccessRate),
              finalFailureRate: Number(rates.finalFailureRate)
            }
          ];
        })
      )
});

module.exports = {
  createPlatformMysqlAuthStoreRolePermissionSync
};

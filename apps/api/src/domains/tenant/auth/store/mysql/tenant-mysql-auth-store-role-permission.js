'use strict';

const createTenantMysqlAuthStoreRolePermission = ({
  DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS,
  buildSqlInPlaceholders,
  createTenantRolePermissionGrantDataError,
  dbClient,
  executeWithDeadlockRetry,
  normalizePlatformRoleCatalogRoleId,
  normalizeStrictRoleIdFromTenantGrantRow,
  normalizeStrictTenantPermissionCodeFromGrantRow,
  normalizeStrictTenantRolePermissionGrantIdentity,
  normalizeTenantPermissionCodes,
  normalizeTenantUsershipRoleIds,
  recordAuditEventWithQueryClient,
  syncTenantUsershipPermissionSnapshotInTx
} = {}) => ({
listTenantRolePermissionGrants: async ({ roleId }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT permission_code
          FROM tenant_role_permission_grants
          WHERE role_id = ?
          ORDER BY permission_code ASC
        `,
        [normalizedRoleId]
      );
      const normalizedPermissionCodeKeys = [];
      const seenPermissionCodeKeys = new Set();
      for (const row of Array.isArray(rows) ? rows : []) {
        const permissionCodeKey = normalizeStrictTenantPermissionCodeFromGrantRow(
          row?.permission_code,
          'tenant-role-permission-grants-invalid-permission-code'
        );
        if (seenPermissionCodeKeys.has(permissionCodeKey)) {
          throw createTenantRolePermissionGrantDataError(
            'tenant-role-permission-grants-duplicate-permission-code'
          );
        }
        seenPermissionCodeKeys.add(permissionCodeKey);
        normalizedPermissionCodeKeys.push(permissionCodeKey);
      }
      return normalizedPermissionCodeKeys;
    },

listTenantRolePermissionGrantsByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIds = normalizeTenantUsershipRoleIds(roleIds);
      if (normalizedRoleIds.length === 0) {
        return [];
      }
      const placeholders = buildSqlInPlaceholders(normalizedRoleIds.length);
      const rows = await dbClient.query(
        `
          SELECT role_id, permission_code
          FROM tenant_role_permission_grants
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
        const roleId = normalizeStrictRoleIdFromTenantGrantRow(
          row?.role_id,
          'tenant-role-permission-grants-invalid-role-id'
        );
        if (!roleId || !grantsByRoleId.has(roleId)) {
          throw createTenantRolePermissionGrantDataError(
            'tenant-role-permission-grants-invalid-role-id'
          );
        }
        const permissionCodeKey = normalizeStrictTenantPermissionCodeFromGrantRow(
          row?.permission_code,
          'tenant-role-permission-grants-invalid-permission-code'
        );
        const seenPermissionCodeKeys = seenGrantPermissionCodeKeysByRoleId.get(roleId);
        if (seenPermissionCodeKeys.has(permissionCodeKey)) {
          throw createTenantRolePermissionGrantDataError(
            'tenant-role-permission-grants-duplicate-permission-code'
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

replaceTenantRolePermissionGrantsAndSyncSnapshots: async ({
      tenantId,
      roleId,
      permissionCodes = [],
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null,
      maxAffectedMemberships = DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS
    }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedTenantId || !normalizedRoleId) {
        throw new Error('replaceTenantRolePermissionGrantsAndSyncSnapshots requires tenantId and roleId');
      }
      const normalizedPermissionCodes = normalizeTenantPermissionCodes(permissionCodes)
        .sort((left, right) => left.localeCompare(right));
      const normalizedMaxAffectedMemberships = Math.max(
        1,
        Math.floor(
          Number(
            maxAffectedMemberships || DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS
          )
        )
      );
      return executeWithDeadlockRetry({
        operation: 'replaceTenantRolePermissionGrantsAndSyncSnapshots',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const roleRows = await tx.query(
              `
                SELECT role_id
                FROM platform_roles
                WHERE role_id = ?
                  AND scope = 'tenant'
                  AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedRoleId, normalizedTenantId]
            );
            if (!roleRows?.[0]) {
              return null;
            }

            const membershipRows = await tx.query(
              `
                SELECT ut.membership_id, ut.user_id
                FROM tenant_membership_roles mr
                JOIN tenant_memberships ut ON ut.membership_id = mr.membership_id
                WHERE mr.role_id = ?
                  AND ut.tenant_id = ?
                  AND ut.status IN ('active', 'enabled')
                ORDER BY ut.membership_id ASC
                FOR UPDATE
              `,
              [normalizedRoleId, normalizedTenantId]
            );
            const affectedMembershipIds = [];
            const affectedUserIds = new Set();
            for (const row of Array.isArray(membershipRows) ? membershipRows : []) {
              const membershipId =
                normalizeStrictTenantRolePermissionGrantIdentity(
                  row?.membership_id,
                  'tenant-role-permission-grants-invalid-membership-id'
                );
              if (affectedMembershipIds.includes(membershipId)) {
                continue;
              }
              affectedMembershipIds.push(membershipId);
              const userId = normalizeStrictTenantRolePermissionGrantIdentity(
                row?.user_id,
                'tenant-role-permission-grants-invalid-affected-user-id'
              );
              affectedUserIds.add(userId);
            }
            if (affectedMembershipIds.length > normalizedMaxAffectedMemberships) {
              const limitError = new Error(
                'tenant role permission affected memberships exceed limit'
              );
              limitError.code = 'ERR_TENANT_ROLE_PERMISSION_AFFECTED_MEMBERSHIPS_OVER_LIMIT';
              limitError.maxAffectedMemberships = normalizedMaxAffectedMemberships;
              limitError.affectedMemberships = affectedMembershipIds.length;
              throw limitError;
            }
            const previousGrantRows = await tx.query(
              `
                SELECT permission_code
                FROM tenant_role_permission_grants
                WHERE role_id = ?
                ORDER BY permission_code ASC
                FOR UPDATE
              `,
              [normalizedRoleId]
            );
            const previousPermissionCodes = [];
            const seenPreviousPermissionCodes = new Set();
            for (const row of Array.isArray(previousGrantRows) ? previousGrantRows : []) {
              const permissionCode = normalizeStrictTenantPermissionCodeFromGrantRow(
                row?.permission_code,
                'tenant-role-permission-grants-invalid-permission-code'
              );
              if (seenPreviousPermissionCodes.has(permissionCode)) {
                throw createTenantRolePermissionGrantDataError(
                  'tenant-role-permission-grants-duplicate-permission-code'
                );
              }
              seenPreviousPermissionCodes.add(permissionCode);
              previousPermissionCodes.push(permissionCode);
            }

            await tx.query(
              `
                DELETE FROM tenant_role_permission_grants
                WHERE role_id = ?
              `,
              [normalizedRoleId]
            );

            for (const permissionCode of normalizedPermissionCodes) {
              await tx.query(
                `
                  INSERT INTO tenant_role_permission_grants (
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

            for (const membershipId of affectedMembershipIds) {
              const syncResult = await syncTenantUsershipPermissionSnapshotInTx({
                txClient: tx,
                membershipId,
                tenantId: normalizedTenantId,
                revokeReason: 'tenant-role-permission-grants-changed'
              });
              const syncReason = String(syncResult?.reason || 'unknown')
                .trim()
                .toLowerCase();
              if (syncReason !== 'ok') {
                const syncError = new Error(
                  `tenant role permission sync failed: ${syncReason || 'unknown'}`
                );
                syncError.code = 'ERR_TENANT_ROLE_PERMISSION_SYNC_FAILED';
                syncError.syncReason = syncReason || 'unknown';
                throw syncError;
              }
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'tenant',
                  tenantId: normalizedTenantId,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.tenant_role_permission_grants.updated',
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
                    affected_user_count: affectedUserIds.size
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'tenant role permission grants audit write failed'
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
              affectedUserCount: affectedUserIds.size,
              auditRecorded
            };
          })
      });
    }
});

module.exports = {
  createTenantMysqlAuthStoreRolePermission
};

'use strict';

const createTenantMysqlAuthStoreUsershipGovernanceReplaceTenantUsershipRoleBindingsAndSyncSnapshot = ({
  buildSqlInPlaceholders,
  dbClient,
  executeWithDeadlockRetry,
  isActiveLikeStatus,
  listTenantUsershipRoleBindingsTx,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogTenantId,
  normalizeStrictTenantUsershipRoleBindingIdentity,
  normalizeTenantUsershipRoleIds,
  normalizeTenantUsershipStatusForRead,
  recordAuditEventWithQueryClient,
  syncTenantUsershipPermissionSnapshotInTx
} = {}) => ({
replaceTenantUsershipRoleBindingsAndSyncSnapshot: async ({
      tenantId,
      membershipId,
      roleIds = [],
      operatorUserId = null,
      auditContext = null
    } = {}) => {
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedMembershipId = String(membershipId || '').trim();
      if (!normalizedTenantId || !normalizedMembershipId) {
        throw new Error(
          'replaceTenantUsershipRoleBindingsAndSyncSnapshot requires tenantId and membershipId'
        );
      }
      const normalizedRoleIds = normalizeTenantUsershipRoleIds(roleIds);
      return executeWithDeadlockRetry({
        operation: 'replaceTenantUsershipRoleBindingsAndSyncSnapshot',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const membershipRows = await tx.query(
              `
                SELECT membership_id,
                       user_id,
                       tenant_id,
                       status
                FROM tenant_memberships
                WHERE membership_id = ? AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedMembershipId, normalizedTenantId]
            );
            const membershipRow = membershipRows?.[0] || null;
            if (!membershipRow) {
              return null;
            }
            const normalizedMembershipStatus = normalizeTenantUsershipStatusForRead(
              membershipRow.status
            );
            if (!isActiveLikeStatus(normalizedMembershipStatus)) {
              const membershipStatusError = new Error(
                'tenant usership role bindings membership not active'
              );
              membershipStatusError.code =
                'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_MEMBERSHIP_NOT_ACTIVE';
              throw membershipStatusError;
            }
            const normalizedAffectedUserId =
              normalizeStrictTenantUsershipRoleBindingIdentity(
                membershipRow?.user_id,
                'tenant-membership-role-bindings-invalid-affected-user-id'
              );
            if (normalizedRoleIds.length > 0) {
              const rolePlaceholders = buildSqlInPlaceholders(
                normalizedRoleIds.length
              );
              const roleRows = await tx.query(
                `
                  SELECT role_id, status, scope, tenant_id
                  FROM platform_roles
                  WHERE role_id IN (${rolePlaceholders})
                  FOR UPDATE
                `,
                normalizedRoleIds
              );
              const roleRowsByRoleId = new Map();
              for (const row of Array.isArray(roleRows) ? roleRows : []) {
                const resolvedRoleId = normalizePlatformRoleCatalogRoleId(
                  row?.role_id
                );
                if (!resolvedRoleId || roleRowsByRoleId.has(resolvedRoleId)) {
                  continue;
                }
                roleRowsByRoleId.set(resolvedRoleId, row);
              }
              for (const roleId of normalizedRoleIds) {
                const roleRow = roleRowsByRoleId.get(roleId) || null;
                const roleScope = normalizePlatformRoleCatalogScope(roleRow?.scope);
                const roleTenantId = normalizePlatformRoleCatalogTenantId(
                  roleRow?.tenant_id
                );
                let roleStatus = 'disabled';
                try {
                  roleStatus = normalizePlatformRoleCatalogStatus(
                    roleRow?.status || 'disabled'
                  );
                } catch (_error) {}
                if (
                  !roleRow
                  || roleScope !== 'tenant'
                  || roleTenantId !== normalizedTenantId
                  || !isActiveLikeStatus(roleStatus)
                ) {
                  const roleValidationError = new Error(
                    'tenant usership role bindings role invalid'
                  );
                  roleValidationError.code =
                    'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_ROLE_INVALID';
                  roleValidationError.roleId = roleId;
                  throw roleValidationError;
                }
              }
            }
            const previousRoleIds = await listTenantUsershipRoleBindingsTx({
              txClient: tx,
              membershipId: normalizedMembershipId
            });

            await tx.query(
              `
                DELETE FROM tenant_membership_roles
                WHERE membership_id = ?
              `,
              [normalizedMembershipId]
            );

            for (const roleId of normalizedRoleIds) {
              await tx.query(
                `
                  INSERT INTO tenant_membership_roles (
                    membership_id,
                    role_id,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedMembershipId,
                  roleId,
                  operatorUserId ? String(operatorUserId) : null,
                  operatorUserId ? String(operatorUserId) : null
                ]
              );
            }

            const syncResult = await syncTenantUsershipPermissionSnapshotInTx({
              txClient: tx,
              membershipId: normalizedMembershipId,
              tenantId: normalizedTenantId,
              roleIds: normalizedRoleIds,
              revokeReason: 'tenant-membership-role-bindings-changed'
            });
            const syncReason = String(syncResult?.reason || 'unknown')
              .trim()
              .toLowerCase();
            if (syncReason !== 'ok') {
              const syncError = new Error(
                `tenant usership role bindings sync failed: ${syncReason || 'unknown'}`
              );
              syncError.code = 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_SYNC_FAILED';
              syncError.syncReason = syncReason || 'unknown';
              throw syncError;
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
                  eventType: 'auth.tenant_membership_roles.updated',
                  actorUserId: auditContext.actorUserId,
                  actorSessionId: auditContext.actorSessionId,
                  targetType: 'membership_role_bindings',
                  targetId: normalizedMembershipId,
                  result: 'success',
                  beforeState: {
                    role_ids: previousRoleIds
                  },
                  afterState: {
                    role_ids: [...normalizedRoleIds]
                  },
                  metadata: {
                    affected_user_count: 1
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'tenant usership role bindings audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }

            return {
              membershipId: normalizedMembershipId,
              roleIds: [...normalizedRoleIds],
              affectedUserIds: [normalizedAffectedUserId],
              affectedUserCount: 1,
              auditRecorded
            };
          })
      });
    }
});

module.exports = {
  createTenantMysqlAuthStoreUsershipGovernanceReplaceTenantUsershipRoleBindingsAndSyncSnapshot
};

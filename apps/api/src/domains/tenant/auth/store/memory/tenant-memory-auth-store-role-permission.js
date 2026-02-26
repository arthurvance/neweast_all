'use strict';

const createTenantMemoryAuthStoreRolePermission = ({
  findPlatformRoleCatalogRecordStateByRoleId,
  invokeFaultInjector,
  isTenantUsershipActiveForAuth,
  listTenantRolePermissionGrantsForRoleId,
  listTenantUsershipRoleBindingsForMembershipId,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogTenantId,
  normalizeStrictTenantRolePermissionGrantIdentity,
  persistAuditEvent,
  replaceTenantRolePermissionGrantsForRoleId,
  revokeTenantSessionsForUser,
  syncTenantUsershipPermissionSnapshot,
  tenantsByUserId
} = {}) => ({
listTenantRolePermissionGrants: async ({ roleId }) =>
      listTenantRolePermissionGrantsForRoleId(roleId),

listTenantRolePermissionGrantsByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIds = [...new Set(
        (Array.isArray(roleIds) ? roleIds : [])
          .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
          .filter((roleId) => roleId.length > 0)
      )];
      return normalizedRoleIds.map((roleId) => ({
        roleId,
        permissionCodes: listTenantRolePermissionGrantsForRoleId(roleId)
      }));
    },

replaceTenantRolePermissionGrantsAndSyncSnapshots: async ({
      tenantId,
      roleId,
      permissionCodes = [],
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null,
      maxAffectedMemberships = 100
    }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedTenantId || !normalizedRoleId) {
        throw new Error('replaceTenantRolePermissionGrantsAndSyncSnapshots requires tenantId and roleId');
      }
      const roleCatalogEntry = findPlatformRoleCatalogRecordStateByRoleId(
        normalizedRoleId
      )?.record;
      if (!roleCatalogEntry) {
        return null;
      }
      if (
        normalizePlatformRoleCatalogScope(roleCatalogEntry.scope) !== 'tenant'
        || normalizePlatformRoleCatalogTenantId(roleCatalogEntry.tenantId) !== normalizedTenantId
      ) {
        return null;
      }
      const normalizedMaxAffectedMemberships = Math.max(
        1,
        Math.floor(Number(maxAffectedMemberships || 100))
      );
      const affectedMembershipStatesByMembershipId = new Map();
      for (const [userId, memberships] of tenantsByUserId.entries()) {
        for (const membership of Array.isArray(memberships) ? memberships : []) {
          if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
            continue;
          }
          if (!isTenantUsershipActiveForAuth(membership)) {
            continue;
          }
          const membershipId = normalizeStrictTenantRolePermissionGrantIdentity(
            membership?.membershipId || membership?.membership_id,
            'tenant-role-permission-grants-invalid-membership-id'
          );
          const boundRoleIds = listTenantUsershipRoleBindingsForMembershipId({
            membershipId,
            tenantId: normalizedTenantId
          });
          if (!boundRoleIds.includes(normalizedRoleId)) {
            continue;
          }
          affectedMembershipStatesByMembershipId.set(membershipId, {
            userId: normalizeStrictTenantRolePermissionGrantIdentity(
              userId,
              'tenant-role-permission-grants-invalid-affected-user-id'
            ),
            memberships,
            membership
          });
        }
      }
      if (
        affectedMembershipStatesByMembershipId.size
        > normalizedMaxAffectedMemberships
      ) {
        const limitError = new Error('tenant role permission affected memberships exceed limit');
        limitError.code = 'ERR_TENANT_ROLE_PERMISSION_AFFECTED_MEMBERSHIPS_OVER_LIMIT';
        limitError.maxAffectedMemberships = normalizedMaxAffectedMemberships;
        limitError.affectedMemberships = affectedMembershipStatesByMembershipId.size;
        throw limitError;
      }
      const previousPermissionCodes = listTenantRolePermissionGrantsForRoleId(
        normalizedRoleId
      );
      const previousMembershipPermissionsByMembershipId = new Map();
      for (const [membershipId, membershipState] of affectedMembershipStatesByMembershipId.entries()) {
        const previousPermission =
          membershipState?.membership?.permission
          && typeof membershipState.membership.permission === 'object'
            ? { ...membershipState.membership.permission }
            : null;
        previousMembershipPermissionsByMembershipId.set(
          membershipId,
          previousPermission
        );
      }
      const savedPermissionCodes = replaceTenantRolePermissionGrantsForRoleId({
        roleId: normalizedRoleId,
        permissionCodes
      });
      const affectedUserIds = new Set();
      const tenantSessionRevocations = new Map();
      try {
        for (const [
          membershipId,
          membershipState
        ] of affectedMembershipStatesByMembershipId.entries()) {
          const resolvedUserId = normalizeStrictTenantRolePermissionGrantIdentity(
            membershipState?.userId,
            'tenant-role-permission-grants-invalid-affected-user-id'
          );
          affectedUserIds.add(resolvedUserId);
          invokeFaultInjector('beforeTenantRolePermissionSnapshotSync', {
            tenantId: normalizedTenantId,
            roleId: normalizedRoleId,
            membershipId,
            userId: resolvedUserId
          });
          const syncResult = syncTenantUsershipPermissionSnapshot({
            membershipState,
            reason: 'tenant-role-permission-grants-changed',
            revokeSessions: false
          });
          if (!syncResult?.synced || syncResult.reason !== 'ok') {
            const syncError = new Error(
              `tenant role permission sync failed: ${String(syncResult?.reason || 'unknown')}`
            );
            syncError.code = 'ERR_TENANT_ROLE_PERMISSION_SYNC_FAILED';
            syncError.syncReason = String(syncResult?.reason || 'unknown');
            throw syncError;
          }
          const syncUserId = String(syncResult?.userId || '').trim();
          const syncTenantId = String(syncResult?.tenantId || '').trim();
          if (syncResult.changed && syncUserId && syncTenantId) {
            tenantSessionRevocations.set(`${syncUserId}::${syncTenantId}`, {
              userId: syncUserId,
              tenantId: syncTenantId
            });
          }
        }
      } catch (error) {
        replaceTenantRolePermissionGrantsForRoleId({
          roleId: normalizedRoleId,
          permissionCodes: previousPermissionCodes
        });
        for (const [
          membershipId,
          membershipState
        ] of affectedMembershipStatesByMembershipId.entries()) {
          if (!membershipState?.membership || typeof membershipState.membership !== 'object') {
            continue;
          }
          const previousPermission =
            previousMembershipPermissionsByMembershipId.get(membershipId);
          membershipState.membership.permission = previousPermission
            ? { ...previousPermission }
            : null;
        }
        throw error;
      }
      for (const { userId, tenantId: activeTenantId } of tenantSessionRevocations.values()) {
        revokeTenantSessionsForUser({
          userId,
          reason: 'tenant-role-permission-grants-changed',
          activeTenantId
        });
      }
      let auditRecorded = false;
      if (auditContext && typeof auditContext === 'object') {
        try {
          persistAuditEvent({
            domain: 'tenant',
            tenantId: normalizedTenantId,
            requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
            traceparent: auditContext.traceparent,
            eventType: 'auth.tenant_role_permission_grants.updated',
            actorUserId: auditContext.actorUserId || operatorUserId || null,
            actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
            targetType: 'role_permission_grants',
            targetId: normalizedRoleId,
            result: 'success',
            beforeState: {
              permission_codes: [...previousPermissionCodes]
            },
            afterState: {
              permission_codes: [...savedPermissionCodes]
            },
            metadata: {
              affected_user_count: affectedUserIds.size
            }
          });
        } catch (error) {
          const auditWriteError = new Error(
            'tenant role permission grants audit write failed'
          );
          auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
          auditWriteError.cause = error;
          throw auditWriteError;
        }
        auditRecorded = true;
      }

      return {
        roleId: normalizedRoleId,
        permissionCodes: savedPermissionCodes,
        affectedUserIds: [...affectedUserIds],
        affectedUserCount: affectedUserIds.size,
        auditRecorded
      };
    }
});

module.exports = {
  createTenantMemoryAuthStoreRolePermission
};

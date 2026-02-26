'use strict';

const createTenantMemoryAuthStoreUsershipGovernanceReplaceTenantUsershipRoleBindingsAndSyncSnapshot = ({
  auditEvents,
  findPlatformRoleCatalogRecordStateByRoleId,
  findTenantUsershipStateByMembershipId,
  isActiveLikeStatus,
  listTenantUsershipRoleBindingsForMembershipId,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogTenantId,
  normalizeStrictTenantUsershipRoleBindingIdentity,
  normalizeTenantUsershipStatusForRead,
  persistAuditEvent,
  refreshTokensByHash,
  replaceTenantUsershipRoleBindingsForMembershipId,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  sessionsById,
  syncTenantUsershipPermissionSnapshot,
  tenantUsershipRolesByMembershipId,
  tenantsByUserId
} = {}) => ({
replaceTenantUsershipRoleBindingsAndSyncSnapshot: async ({
      tenantId,
      membershipId,
      roleIds = [],
      auditContext = null
    } = {}) => {
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedMembershipId = String(membershipId || '').trim();
      if (!normalizedTenantId || !normalizedMembershipId) {
        throw new Error('replaceTenantUsershipRoleBindingsAndSyncSnapshot requires tenantId and membershipId');
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          tenantUsershipRolesByMembershipId: structuredClone(
            tenantUsershipRolesByMembershipId
          ),
          tenantsByUserId: structuredClone(tenantsByUserId),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const membershipState = findTenantUsershipStateByMembershipId(
          normalizedMembershipId
        );
        if (!membershipState) {
          return null;
        }
        if (
          String(membershipState.membership?.tenantId || '').trim()
          !== normalizedTenantId
        ) {
          return null;
        }
        if (
          !isActiveLikeStatus(
            normalizeTenantUsershipStatusForRead(
              membershipState.membership?.status
            )
          )
        ) {
          const membershipStatusError = new Error(
            'tenant usership role bindings membership not active'
          );
          membershipStatusError.code =
            'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_MEMBERSHIP_NOT_ACTIVE';
          throw membershipStatusError;
        }
        const normalizedAffectedUserId =
          normalizeStrictTenantUsershipRoleBindingIdentity(
            membershipState?.userId,
            'tenant-membership-role-bindings-invalid-affected-user-id'
          );
        const normalizedRoleIds = [...new Set(
          (Array.isArray(roleIds) ? roleIds : [])
            .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
            .filter((roleId) => roleId.length > 0)
        )].sort((left, right) => left.localeCompare(right));
        for (const roleId of normalizedRoleIds) {
          const catalogEntry = findPlatformRoleCatalogRecordStateByRoleId(
            roleId
          )?.record;
          const normalizedScope = normalizePlatformRoleCatalogScope(
            catalogEntry?.scope
          );
          const normalizedCatalogTenantId = normalizePlatformRoleCatalogTenantId(
            catalogEntry?.tenantId
          );
          let normalizedCatalogStatus = 'disabled';
          try {
            normalizedCatalogStatus = normalizePlatformRoleCatalogStatus(
              catalogEntry?.status || 'disabled'
            );
          } catch (_error) {}
          if (
            !catalogEntry
            || normalizedScope !== 'tenant'
            || normalizedCatalogTenantId !== normalizedTenantId
            || !isActiveLikeStatus(normalizedCatalogStatus)
          ) {
            const roleBindingError = new Error(
              'tenant usership role bindings role invalid'
            );
            roleBindingError.code =
              'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_ROLE_INVALID';
            roleBindingError.roleId = roleId;
            throw roleBindingError;
          }
        }
        const previousRoleIds = listTenantUsershipRoleBindingsForMembershipId({
          membershipId: normalizedMembershipId,
          tenantId: normalizedTenantId
        });
        const resolvedRoleIds = replaceTenantUsershipRoleBindingsForMembershipId({
          membershipId: normalizedMembershipId,
          roleIds: normalizedRoleIds
        });
        const rollbackRoleBindings = () =>
          replaceTenantUsershipRoleBindingsForMembershipId({
            membershipId: normalizedMembershipId,
            roleIds: previousRoleIds
          });
        let syncResult;
        try {
          syncResult = syncTenantUsershipPermissionSnapshot({
            membershipState,
            reason: 'tenant-membership-role-bindings-changed'
          });
        } catch (error) {
          rollbackRoleBindings();
          throw error;
        }
        const syncReason = String(syncResult?.reason || 'unknown')
          .trim()
          .toLowerCase();
        if (syncReason !== 'ok') {
          rollbackRoleBindings();
          const syncError = new Error(
            `tenant usership role bindings sync failed: ${syncReason || 'unknown'}`
          );
          syncError.code = 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_SYNC_FAILED';
          syncError.syncReason = syncReason || 'unknown';
          throw syncError;
        }
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedTenantId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.tenant_membership_roles.updated',
              actorUserId: auditContext.actorUserId || null,
              actorSessionId: auditContext.actorSessionId || null,
              targetType: 'membership_role_bindings',
              targetId: normalizedMembershipId,
              result: 'success',
              beforeState: {
                role_ids: previousRoleIds
              },
              afterState: {
                role_ids: resolvedRoleIds
              },
              metadata: {
                affected_user_count: 1
              }
            });
          } catch (error) {
            const auditWriteError = new Error(
              'tenant usership role bindings audit write failed'
            );
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }
        return {
          membershipId: normalizedMembershipId,
          roleIds: resolvedRoleIds,
          affectedUserIds: [normalizedAffectedUserId],
          affectedUserCount: 1,
          auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            tenantUsershipRolesByMembershipId,
            snapshot.tenantUsershipRolesByMembershipId
          );
          restoreMapFromSnapshot(tenantsByUserId, snapshot.tenantsByUserId);
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    }
});

module.exports = {
  createTenantMemoryAuthStoreUsershipGovernanceReplaceTenantUsershipRoleBindingsAndSyncSnapshot
};

'use strict';

const createTenantMemoryAuthStoreUsershipGovernanceUpdateTenantUsershipStatus = ({
  VALID_TENANT_MEMBERSHIP_STATUS,
  appendTenantUsershipHistory,
  auditEvents,
  domainsByUserId,
  isTenantUsershipActiveForAuth,
  normalizeTenantUsershipStatusForRead,
  persistAuditEvent,
  randomUUID,
  refreshTokensByHash,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  revokeTenantSessionsForUser,
  sessionsById,
  syncTenantUsershipPermissionSnapshot,
  tenantUsershipHistoryByPair,
  tenantUsershipRolesByMembershipId,
  tenantsByUserId
} = {}) => ({
updateTenantUsershipStatus: async ({
      membershipId,
      tenantId,
      nextStatus,
      operatorUserId = null,
      reason = null,
      auditContext = null
    }) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedNextStatus = normalizeTenantUsershipStatusForRead(nextStatus);
      if (
        !normalizedMembershipId
        || !normalizedTenantId
        || !VALID_TENANT_MEMBERSHIP_STATUS.has(normalizedNextStatus)
      ) {
        throw new Error(
          'updateTenantUsershipStatus requires membershipId, tenantId and supported nextStatus'
        );
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          tenantsByUserId: structuredClone(tenantsByUserId),
          tenantUsershipRolesByMembershipId: structuredClone(
            tenantUsershipRolesByMembershipId
          ),
          tenantUsershipHistoryByPair: structuredClone(tenantUsershipHistoryByPair),
          domainsByUserId: structuredClone(domainsByUserId),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        let targetUserId = '';
        const tenantUsershipsByUser = [...tenantsByUserId.entries()];
        let targetMembership = null;
        let targetMemberships = null;

        for (const [userId, memberships] of tenantUsershipsByUser) {
          if (!Array.isArray(memberships)) {
            continue;
          }
          const match = memberships.find((membership) => {
            const membershipTenantId = String(membership?.tenantId || '').trim();
            const resolvedMembershipId = String(membership?.membershipId || '').trim();
            return (
              membershipTenantId === normalizedTenantId
              && resolvedMembershipId === normalizedMembershipId
            );
          });
          if (!match) {
            continue;
          }
          targetUserId = String(userId || '').trim();
          targetMembership = match;
          targetMemberships = memberships;
          break;
        }

        if (!targetMembership || !targetUserId || !targetMemberships) {
          return null;
        }

        const previousStatus = normalizeTenantUsershipStatusForRead(targetMembership.status);
        if (!VALID_TENANT_MEMBERSHIP_STATUS.has(previousStatus)) {
          throw new Error('updateTenantUsershipStatus encountered unsupported existing status');
        }
        if (previousStatus !== normalizedNextStatus) {
          let previousMembershipId = '';
          if (previousStatus === 'left' && normalizedNextStatus === 'active') {
            appendTenantUsershipHistory({
              membership: {
                ...targetMembership,
                userId: targetUserId,
                tenantId: normalizedTenantId
              },
              reason: reason || 'reactivate',
              operatorUserId
            });
            previousMembershipId = String(targetMembership.membershipId || '').trim();
            targetMembership.membershipId = randomUUID();
            targetMembership.joinedAt = new Date().toISOString();
            targetMembership.leftAt = null;
            if (targetMembership.permission) {
              targetMembership.permission = {
                ...targetMembership.permission,
                canViewUserManagement: false,
                canOperateUserManagement: false,
                canViewRoleManagement: false,
                canOperateRoleManagement: false
              };
            }
            if (previousMembershipId) {
              tenantUsershipRolesByMembershipId.delete(previousMembershipId);
            }
            tenantUsershipRolesByMembershipId.set(
              String(targetMembership.membershipId || '').trim(),
              []
            );
          } else if (normalizedNextStatus === 'left') {
            appendTenantUsershipHistory({
              membership: {
                ...targetMembership,
                userId: targetUserId,
                tenantId: normalizedTenantId
              },
              reason: reason || 'left',
              operatorUserId
            });
            targetMembership.leftAt = new Date().toISOString();
            if (targetMembership.permission) {
              targetMembership.permission = {
                ...targetMembership.permission,
                canViewUserManagement: false,
                canOperateUserManagement: false,
                canViewRoleManagement: false,
                canOperateRoleManagement: false
              };
            }
            const resolvedMembershipId = String(targetMembership.membershipId || '').trim();
            if (resolvedMembershipId) {
              tenantUsershipRolesByMembershipId.delete(resolvedMembershipId);
            }
          } else if (normalizedNextStatus === 'active') {
            targetMembership.leftAt = null;
          }

          targetMembership.status = normalizedNextStatus;
          tenantsByUserId.set(targetUserId, targetMemberships);

          if (normalizedNextStatus === 'active') {
            const userDomains = domainsByUserId.get(targetUserId) || new Set();
            userDomains.add('tenant');
            domainsByUserId.set(targetUserId, userDomains);
          } else {
            revokeTenantSessionsForUser({
              userId: targetUserId,
              reason: 'tenant-membership-status-changed',
              activeTenantId: normalizedTenantId
            });
            const userDomains = domainsByUserId.get(targetUserId) || new Set();
            const hasAnyActiveMembership = (tenantsByUserId.get(targetUserId) || []).some(
              (membership) => isTenantUsershipActiveForAuth(membership)
            );
            if (!hasAnyActiveMembership) {
              userDomains.delete('tenant');
            }
            domainsByUserId.set(targetUserId, userDomains);
          }

          if (normalizedNextStatus === 'active') {
            syncTenantUsershipPermissionSnapshot({
              membershipState: {
                userId: targetUserId,
                memberships: targetMemberships,
                membership: targetMembership
              },
              reason: 'tenant-membership-status-changed'
            });
          }
        }

        const resolvedMembershipId = String(targetMembership.membershipId || '').trim();
        const currentStatus = normalizeTenantUsershipStatusForRead(targetMembership.status);
        let auditRecorded = false;
        if (shouldRecordAudit) {
          const normalizedAuditReason =
            auditContext.reason === null || auditContext.reason === undefined
              ? null
              : String(auditContext.reason).trim() || null;
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedTenantId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.tenant.user.status.updated',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || null,
              targetType: 'membership',
              targetId: resolvedMembershipId,
              result: 'success',
              beforeState: {
                status: previousStatus
              },
              afterState: {
                status: currentStatus
              },
              metadata: {
                tenant_id: normalizedTenantId,
                membership_id: resolvedMembershipId,
                target_user_id: targetUserId,
                previous_status: previousStatus,
                current_status: currentStatus,
                reason: normalizedAuditReason
              }
            });
          } catch (error) {
            const auditWriteError = new Error('tenant usership status audit write failed');
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }

        return {
          membership_id: resolvedMembershipId,
          user_id: targetUserId,
          tenant_id: normalizedTenantId,
          previous_status: previousStatus,
          current_status: currentStatus,
          audit_recorded: auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(tenantsByUserId, snapshot.tenantsByUserId);
          restoreMapFromSnapshot(
            tenantUsershipRolesByMembershipId,
            snapshot.tenantUsershipRolesByMembershipId
          );
          restoreMapFromSnapshot(
            tenantUsershipHistoryByPair,
            snapshot.tenantUsershipHistoryByPair
          );
          restoreMapFromSnapshot(domainsByUserId, snapshot.domainsByUserId);
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    }
});

module.exports = {
  createTenantMemoryAuthStoreUsershipGovernanceUpdateTenantUsershipStatus
};

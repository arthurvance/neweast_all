'use strict';

const createPlatformMemoryAuthStoreOrganizationGovernanceUpdateOrganizationStatus = ({
  VALID_ORG_STATUS,
  auditEvents,
  buildEmptyTenantPermission,
  domainsByUserId,
  isActiveLikeStatus,
  isTenantUsershipActiveForAuth,
  membershipsByOrgId,
  normalizeOrgStatus,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogTenantId,
  normalizeTenantUsershipStatusForRead,
  orgsById,
  persistAuditEvent,
  platformRoleCatalogById,
  refreshTokensByHash,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  revokeTenantSessionsForUser,
  sessionsById,
  tenantUsershipRolesByMembershipId,
  tenantsByUserId,
  toTenantUsershipScopeLabel
} = {}) => ({
updateOrganizationStatus: async ({
      orgId,
      nextStatus,
      operatorUserId,
      auditContext = null
    }) => {
      const normalizedOrgId = String(orgId || '').trim();
      const normalizedOperatorUserId = String(operatorUserId || '').trim();
      const normalizedNextStatus = normalizeOrgStatus(nextStatus);
      if (
        !normalizedOrgId
        || !normalizedOperatorUserId
        || !VALID_ORG_STATUS.has(normalizedNextStatus)
      ) {
        throw new Error(
          'updateOrganizationStatus requires orgId, nextStatus, and operatorUserId'
        );
      }
      const existingOrg = orgsById.get(normalizedOrgId);
      if (!existingOrg) {
        return null;
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          orgsById: structuredClone(orgsById),
          membershipsByOrgId: structuredClone(membershipsByOrgId),
          tenantsByUserId: structuredClone(tenantsByUserId),
          tenantUsershipRolesByMembershipId: structuredClone(
            tenantUsershipRolesByMembershipId
          ),
          platformRoleCatalogById: structuredClone(platformRoleCatalogById),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          domainsByUserId: structuredClone(domainsByUserId),
          auditEvents: structuredClone(auditEvents)
        }
        : null;

      try {
        const previousStatus = normalizeOrgStatus(existingOrg.status);
        let affectedMembershipCount = 0;
        let affectedRoleCount = 0;
        let affectedRoleBindingCount = 0;
        let revokedSessionCount = 0;
        let revokedRefreshTokenCount = 0;
        if (previousStatus !== normalizedNextStatus) {
          existingOrg.status = normalizedNextStatus;
          existingOrg.updatedAt = Date.now();
          orgsById.set(normalizedOrgId, existingOrg);

          if (normalizedNextStatus === 'disabled') {
            const affectedMembershipUserIds = new Set();
            const affectedUserIds = new Set();
            const orgMemberships = membershipsByOrgId.get(normalizedOrgId) || [];
            for (const membership of orgMemberships) {
              const membershipUserId = String(membership?.userId || '').trim();
              if (
                !membershipUserId
                || !isActiveLikeStatus(normalizeOrgStatus(membership?.status))
              ) {
                continue;
              }
              membership.status = 'disabled';
              affectedMembershipUserIds.add(membershipUserId);
              affectedUserIds.add(membershipUserId);
            }

            const tenantUsershipIdsByOrg = new Set();
            for (const [userId, tenantUserships] of tenantsByUserId.entries()) {
              const normalizedUserId = String(userId || '').trim();
              let hasMutation = false;
              for (const membership of Array.isArray(tenantUserships) ? tenantUserships : []) {
                const membershipTenantId = String(membership?.tenantId || '').trim();
                if (membershipTenantId !== normalizedOrgId) {
                  continue;
                }
                const membershipId = String(membership?.membershipId || '').trim();
                if (membershipId) {
                  tenantUsershipIdsByOrg.add(membershipId);
                }
                if (
                  !isActiveLikeStatus(
                    normalizeTenantUsershipStatusForRead(membership?.status)
                  )
                ) {
                  continue;
                }
                membership.status = 'disabled';
                membership.permission = buildEmptyTenantPermission(
                  toTenantUsershipScopeLabel(membership)
                );
                affectedMembershipUserIds.add(normalizedUserId);
                affectedUserIds.add(normalizedUserId);
                hasMutation = true;
              }
              if (hasMutation) {
                tenantsByUserId.set(normalizedUserId, tenantUserships);
              }
            }

            for (const membershipId of tenantUsershipIdsByOrg) {
              const existingRoleIds = tenantUsershipRolesByMembershipId.get(membershipId) || [];
              affectedRoleBindingCount += existingRoleIds.length;
              tenantUsershipRolesByMembershipId.delete(membershipId);
            }

            for (const [roleId, roleCatalogEntry] of platformRoleCatalogById.entries()) {
              if (
                normalizePlatformRoleCatalogScope(roleCatalogEntry?.scope) !== 'tenant'
                || normalizePlatformRoleCatalogTenantId(roleCatalogEntry?.tenantId)
                  !== normalizedOrgId
              ) {
                continue;
              }
              if (
                !isActiveLikeStatus(
                  normalizePlatformRoleCatalogStatus(roleCatalogEntry?.status)
                )
              ) {
                continue;
              }
              roleCatalogEntry.status = 'disabled';
              roleCatalogEntry.updatedByUserId = normalizedOperatorUserId;
              roleCatalogEntry.updatedAt = new Date().toISOString();
              platformRoleCatalogById.set(roleId, roleCatalogEntry);
              affectedRoleCount += 1;
            }

            const ownerUserId = String(existingOrg.ownerUserId || '').trim();
            if (ownerUserId) {
              affectedUserIds.add(ownerUserId);
            }

            affectedMembershipCount = affectedMembershipUserIds.size;
            for (const userId of affectedUserIds) {
              const revoked = revokeTenantSessionsForUser({
                userId,
                reason: 'org-status-changed',
                activeTenantId: normalizedOrgId
              });
              revokedSessionCount += Number(revoked?.revokedSessionCount || 0);
              revokedRefreshTokenCount += Number(
                revoked?.revokedRefreshTokenCount || 0
              );

              const userDomains = domainsByUserId.get(userId) || new Set();
              const hasAnyActiveMembership = (tenantsByUserId.get(userId) || []).some(
                (membership) => isTenantUsershipActiveForAuth(membership)
              );
              if (!hasAnyActiveMembership) {
                userDomains.delete('tenant');
              }
              domainsByUserId.set(userId, userDomains);
            }
          }
        }
        let auditRecorded = false;
        if (shouldRecordAudit) {
          const normalizedAuditReason =
            auditContext.reason === null || auditContext.reason === undefined
              ? null
              : String(auditContext.reason).trim() || null;
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedOrgId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.org.status.updated',
              actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
              actorSessionId: auditContext.actorSessionId || null,
              targetType: 'org',
              targetId: normalizedOrgId,
              result: 'success',
              beforeState: {
                status: previousStatus
              },
              afterState: {
                status: normalizedNextStatus
              },
              metadata: {
                reason: normalizedAuditReason,
                affected_membership_count: affectedMembershipCount,
                affected_role_count: affectedRoleCount,
                affected_role_binding_count: affectedRoleBindingCount,
                revoked_session_count: revokedSessionCount,
                revoked_refresh_token_count: revokedRefreshTokenCount
              }
            });
          } catch (error) {
            const auditWriteError = new Error('organization status audit write failed');
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }
        return {
          org_id: normalizedOrgId,
          previous_status: previousStatus,
          current_status: normalizedNextStatus,
          affected_membership_count: affectedMembershipCount,
          affected_role_count: affectedRoleCount,
          affected_role_binding_count: affectedRoleBindingCount,
          revoked_session_count: revokedSessionCount,
          revoked_refresh_token_count: revokedRefreshTokenCount,
          audit_recorded: auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(orgsById, snapshot.orgsById);
          restoreMapFromSnapshot(membershipsByOrgId, snapshot.membershipsByOrgId);
          restoreMapFromSnapshot(tenantsByUserId, snapshot.tenantsByUserId);
          restoreMapFromSnapshot(
            tenantUsershipRolesByMembershipId,
            snapshot.tenantUsershipRolesByMembershipId
          );
          restoreMapFromSnapshot(platformRoleCatalogById, snapshot.platformRoleCatalogById);
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreMapFromSnapshot(domainsByUserId, snapshot.domainsByUserId);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    }
});

module.exports = {
  createPlatformMemoryAuthStoreOrganizationGovernanceUpdateOrganizationStatus
};

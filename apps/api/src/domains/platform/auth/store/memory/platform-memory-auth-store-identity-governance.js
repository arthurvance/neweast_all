'use strict';

const createPlatformMemoryAuthStoreIdentityGovernance = ({
  VALID_PLATFORM_USER_STATUS,
  auditEvents,
  buildEmptyPlatformPermission,
  clone,
  createForeignKeyConstraintError,
  domainsByUserId,
  hasOrgReferenceForUser,
  isActiveLikeStatus,
  membershipsByOrgId,
  normalizeOrgStatus,
  normalizeTenantUsershipStatusForRead,
  persistAuditEvent,
  platformDomainKnownByUserId,
  platformPermissionsByUserId,
  platformRolesByUserId,
  randomUUID,
  refreshTokensByHash,
  repositoryMethods,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  restoreSetFromSnapshot,
  revokePlatformSessionsForUser,
  sessionsById,
  tenantUsershipRolesByMembershipId,
  tenantsByUserId,
  usersById,
  usersByPhone
} = {}) => ({
listPlatformUsers: repositoryMethods.listPlatformUsers,

listPlatformOrgs: repositoryMethods.listPlatformOrgs,

getPlatformUserById: repositoryMethods.getPlatformUserById,

upsertPlatformUserProfile: repositoryMethods.upsertPlatformUserProfile,

createUserByPhone: async ({ phone, passwordHash, status = 'active' }) => {
      const normalizedPhone = String(phone || '').trim();
      const normalizedPasswordHash = String(passwordHash || '').trim();
      if (!normalizedPhone || !normalizedPasswordHash) {
        throw new Error('createUserByPhone requires phone and passwordHash');
      }
      if (usersByPhone.has(normalizedPhone)) {
        return null;
      }
      const normalizedStatus = String(status || 'active').trim().toLowerCase() || 'active';
      const user = {
        id: randomUUID(),
        phone: normalizedPhone,
        passwordHash: normalizedPasswordHash,
        status: normalizedStatus,
        sessionVersion: 1,
        createdAt: new Date().toISOString()
      };
      usersByPhone.set(normalizedPhone, user);
      usersById.set(user.id, user);
      if (!domainsByUserId.has(user.id)) {
        domainsByUserId.set(user.id, new Set());
      }
      if (!tenantsByUserId.has(user.id)) {
        tenantsByUserId.set(user.id, []);
      }
      return clone(user);
    },

updatePlatformUserStatus: async ({
      userId,
      nextStatus,
      operatorUserId,
      auditContext = null
    }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedOperatorUserId = String(operatorUserId || '').trim();
      const normalizedNextStatus = normalizeOrgStatus(nextStatus);
      if (
        !normalizedUserId
        || !normalizedOperatorUserId
        || !VALID_PLATFORM_USER_STATUS.has(normalizedNextStatus)
      ) {
        throw new Error(
          'updatePlatformUserStatus requires userId, nextStatus, and operatorUserId'
        );
      }
      const existingUser = usersById.get(normalizedUserId);
      if (
        !existingUser
        || !platformDomainKnownByUserId.has(normalizedUserId)
      ) {
        return null;
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          domainsByUserId: structuredClone(domainsByUserId),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
        const previousStatus = userDomains.has('platform') ? 'active' : 'disabled';
        if (previousStatus !== normalizedNextStatus) {
          if (normalizedNextStatus === 'active') {
            userDomains.add('platform');
          } else {
            userDomains.delete('platform');
            revokePlatformSessionsForUser({
              userId: normalizedUserId,
              reason: 'platform-user-status-changed'
            });
          }
          domainsByUserId.set(normalizedUserId, userDomains);
        }
        let auditRecorded = false;
        if (shouldRecordAudit) {
          const normalizedAuditReason =
            auditContext.reason === null || auditContext.reason === undefined
              ? null
              : String(auditContext.reason).trim() || null;
          try {
            persistAuditEvent({
              domain: 'platform',
              tenantId: null,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.platform.user.status.updated',
              actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
              actorSessionId: auditContext.actorSessionId || null,
              targetType: 'user',
              targetId: normalizedUserId,
              result: 'success',
              beforeState: {
                status: previousStatus
              },
              afterState: {
                status: normalizedNextStatus
              },
              metadata: {
                reason: normalizedAuditReason
              }
            });
          } catch (error) {
            const auditWriteError = new Error('platform user status audit write failed');
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }

        return {
          user_id: normalizedUserId,
          previous_status: previousStatus,
          current_status: normalizedNextStatus,
          audit_recorded: auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(domainsByUserId, snapshot.domainsByUserId);
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

softDeleteUser: async ({
      userId,
      operatorUserId,
      auditContext = null
    }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedOperatorUserId = String(operatorUserId || '').trim();
      if (!normalizedUserId || !normalizedOperatorUserId) {
        throw new Error('softDeleteUser requires userId and operatorUserId');
      }
      const existingUser = usersById.get(normalizedUserId);
      if (!existingUser) {
        return null;
      }
      const previousStatus = normalizeOrgStatus(existingUser.status);
      if (!VALID_PLATFORM_USER_STATUS.has(previousStatus)) {
        throw new Error('platform-user-soft-delete-status-read-invalid');
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          usersById: structuredClone(usersById),
          usersByPhone: structuredClone(usersByPhone),
          domainsByUserId: structuredClone(domainsByUserId),
          platformDomainKnownByUserId: structuredClone(platformDomainKnownByUserId),
          tenantsByUserId: structuredClone(tenantsByUserId),
          membershipsByOrgId: structuredClone(membershipsByOrgId),
          tenantUsershipRolesByMembershipId: structuredClone(
            tenantUsershipRolesByMembershipId
          ),
          platformRolesByUserId: structuredClone(platformRolesByUserId),
          platformPermissionsByUserId: structuredClone(platformPermissionsByUserId),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        let revokedSessionCount = 0;
        let revokedRefreshTokenCount = 0;
        if (previousStatus !== 'disabled') {
          const disabledUser = {
            ...existingUser,
            status: 'disabled'
          };
          usersById.set(normalizedUserId, disabledUser);
          usersByPhone.set(disabledUser.phone, disabledUser);
        }

        domainsByUserId.set(normalizedUserId, new Set());
        platformDomainKnownByUserId.delete(normalizedUserId);

        const memberships = tenantsByUserId.get(normalizedUserId) || [];
        const updatedMemberships = [];
        for (const membership of memberships) {
          const normalizedMembershipStatus = normalizeTenantUsershipStatusForRead(
            membership?.status
          );
          const normalizedMembership = {
            ...membership,
            status: isActiveLikeStatus(normalizedMembershipStatus)
              ? 'disabled'
              : normalizedMembershipStatus || 'disabled'
          };
          const membershipId = String(
            membership?.membershipId || membership?.membership_id || ''
          ).trim();
          if (membershipId) {
            tenantUsershipRolesByMembershipId.delete(membershipId);
          }
          updatedMemberships.push(normalizedMembership);
        }
        tenantsByUserId.set(normalizedUserId, updatedMemberships);

        for (const [orgId, orgMemberships] of membershipsByOrgId.entries()) {
          const nextOrgMemberships = [];
          for (const orgMembership of Array.isArray(orgMemberships)
            ? orgMemberships
            : []) {
            if (String(orgMembership?.userId || '').trim() !== normalizedUserId) {
              nextOrgMemberships.push(orgMembership);
              continue;
            }
            const normalizedOrgMembershipStatus = normalizeTenantUsershipStatusForRead(
              orgMembership?.status
            );
            nextOrgMemberships.push({
              ...orgMembership,
              status: isActiveLikeStatus(normalizedOrgMembershipStatus)
                ? 'disabled'
                : normalizedOrgMembershipStatus || 'disabled'
            });
          }
          membershipsByOrgId.set(orgId, nextOrgMemberships);
        }

        const platformRoles = platformRolesByUserId.get(normalizedUserId) || [];
        platformRolesByUserId.set(
          normalizedUserId,
          platformRoles.map((role) => ({
            ...role,
            status: isActiveLikeStatus(role?.status) ? 'disabled' : normalizeOrgStatus(role?.status)
          }))
        );
        platformPermissionsByUserId.set(
          normalizedUserId,
          buildEmptyPlatformPermission()
        );

        for (const session of sessionsById.values()) {
          if (
            session.userId === normalizedUserId
            && session.status === 'active'
          ) {
            session.status = 'revoked';
            session.revokedReason = 'user-soft-deleted';
            session.updatedAt = Date.now();
            revokedSessionCount += 1;
          }
        }
        for (const refreshRecord of refreshTokensByHash.values()) {
          if (
            refreshRecord.userId === normalizedUserId
            && refreshRecord.status === 'active'
          ) {
            refreshRecord.status = 'revoked';
            refreshRecord.updatedAt = Date.now();
            revokedRefreshTokenCount += 1;
          }
        }

        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'platform',
              tenantId: null,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.platform.user.soft_deleted',
              actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
              actorSessionId: auditContext.actorSessionId || null,
              targetType: 'user',
              targetId: normalizedUserId,
              result: 'success',
              beforeState: {
                status: previousStatus
              },
              afterState: {
                status: 'disabled'
              },
              metadata: {
                revoked_session_count: revokedSessionCount,
                revoked_refresh_token_count: revokedRefreshTokenCount
              }
            });
          } catch (error) {
            const auditWriteError = new Error('platform user soft-delete audit write failed');
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }

        return {
          user_id: normalizedUserId,
          previous_status: previousStatus,
          current_status: 'disabled',
          revoked_session_count: revokedSessionCount,
          revoked_refresh_token_count: revokedRefreshTokenCount,
          audit_recorded: auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(usersById, snapshot.usersById);
          restoreMapFromSnapshot(usersByPhone, snapshot.usersByPhone);
          restoreMapFromSnapshot(domainsByUserId, snapshot.domainsByUserId);
          restoreSetFromSnapshot(
            platformDomainKnownByUserId,
            snapshot.platformDomainKnownByUserId
          );
          restoreMapFromSnapshot(tenantsByUserId, snapshot.tenantsByUserId);
          restoreMapFromSnapshot(membershipsByOrgId, snapshot.membershipsByOrgId);
          restoreMapFromSnapshot(
            tenantUsershipRolesByMembershipId,
            snapshot.tenantUsershipRolesByMembershipId
          );
          restoreMapFromSnapshot(platformRolesByUserId, snapshot.platformRolesByUserId);
          restoreMapFromSnapshot(
            platformPermissionsByUserId,
            snapshot.platformPermissionsByUserId
          );
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

deleteUserById: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { deleted: false };
      }
      const existingUser = usersById.get(normalizedUserId);
      if (!existingUser) {
        return { deleted: false };
      }
      if (hasOrgReferenceForUser(normalizedUserId)) {
        throw createForeignKeyConstraintError();
      }

      usersById.delete(normalizedUserId);
      usersByPhone.delete(String(existingUser.phone || ''));
      domainsByUserId.delete(normalizedUserId);
      platformDomainKnownByUserId.delete(normalizedUserId);
      for (const membership of tenantsByUserId.get(normalizedUserId) || []) {
        const membershipId = String(membership?.membershipId || '').trim();
        if (!membershipId) {
          continue;
        }
        tenantUsershipRolesByMembershipId.delete(membershipId);
      }
      tenantsByUserId.delete(normalizedUserId);
      platformRolesByUserId.delete(normalizedUserId);
      platformPermissionsByUserId.delete(normalizedUserId);

      for (const [sessionId, session] of sessionsById.entries()) {
        if (session.userId === normalizedUserId) {
          sessionsById.delete(sessionId);
        }
      }
      for (const [tokenHash, refreshToken] of refreshTokensByHash.entries()) {
        if (refreshToken.userId === normalizedUserId) {
          refreshTokensByHash.delete(tokenHash);
        }
      }

      return { deleted: true };
    }
});

module.exports = {
  createPlatformMemoryAuthStoreIdentityGovernance
};

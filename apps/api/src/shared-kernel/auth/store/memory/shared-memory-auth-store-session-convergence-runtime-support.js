'use strict';

const createSharedMemoryAuthStoreSessionConvergenceRuntimeSupport = ({
  usersByPhone,
  usersById,
  sessionsById,
  refreshTokensByHash,
  orgsById,
  membershipsByOrgId,
  clone
} = {}) => {
  const bumpSessionVersionAndConvergeSessions = ({
    userId,
    passwordHash = null,
    reason = 'critical-state-changed',
    revokeRefreshTokens = true,
    revokeAuthSessions = true
  }) => {
    const user = usersById.get(String(userId));
    if (!user) {
      return null;
    }

    if (passwordHash !== null && passwordHash !== undefined) {
      user.passwordHash = passwordHash;
    }
    user.sessionVersion += 1;
    usersByPhone.set(user.phone, user);
    usersById.set(user.id, user);

    if (revokeAuthSessions) {
      for (const session of sessionsById.values()) {
        if (session.userId === String(userId) && session.status === 'active') {
          session.status = 'revoked';
          session.revokedReason = reason;
          session.updatedAt = Date.now();
        }
      }
    }

    if (revokeRefreshTokens) {
      for (const refreshRecord of refreshTokensByHash.values()) {
        if (refreshRecord.userId === String(userId) && refreshRecord.status === 'active') {
          refreshRecord.status = 'revoked';
          refreshRecord.updatedAt = Date.now();
        }
      }
    }

    return clone(user);
  };

  const revokeSessionsForUserByEntryDomain = ({
    userId,
    entryDomain,
    reason,
    activeTenantId = null
  }) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedEntryDomain = String(entryDomain || '').trim().toLowerCase();
    const normalizedActiveTenantId = activeTenantId === null || activeTenantId === undefined
      ? null
      : String(activeTenantId).trim() || null;
    if (!normalizedUserId) {
      return {
        revokedSessionCount: 0,
        revokedRefreshTokenCount: 0
      };
    }
    if (!normalizedEntryDomain) {
      return {
        revokedSessionCount: 0,
        revokedRefreshTokenCount: 0
      };
    }

    const revokedSessionIds = new Set();
    for (const session of sessionsById.values()) {
      if (
        session.userId === normalizedUserId
        && session.status === 'active'
        && String(session.entryDomain || '').trim().toLowerCase() === normalizedEntryDomain
        && (
          normalizedActiveTenantId === null
          || String(session.activeTenantId || '').trim() === normalizedActiveTenantId
        )
      ) {
        session.status = 'revoked';
        session.revokedReason = reason;
        session.updatedAt = Date.now();
        revokedSessionIds.add(String(session.sessionId || '').trim());
      }
    }

    if (revokedSessionIds.size === 0) {
      return {
        revokedSessionCount: 0,
        revokedRefreshTokenCount: 0
      };
    }

    let revokedRefreshTokenCount = 0;
    for (const refreshRecord of refreshTokensByHash.values()) {
      if (
        refreshRecord.status === 'active'
        && revokedSessionIds.has(String(refreshRecord.sessionId || '').trim())
      ) {
        refreshRecord.status = 'revoked';
        refreshRecord.updatedAt = Date.now();
        revokedRefreshTokenCount += 1;
      }
    }
    return {
      revokedSessionCount: revokedSessionIds.size,
      revokedRefreshTokenCount
    };
  };

  const revokePlatformSessionsForUser = ({
    userId,
    reason = 'platform-user-status-changed'
  }) =>
    revokeSessionsForUserByEntryDomain({
      userId,
      entryDomain: 'platform',
      reason
    });

  const revokeTenantSessionsForUser = ({
    userId,
    reason = 'org-status-changed',
    activeTenantId = null
  }) =>
    revokeSessionsForUserByEntryDomain({
      userId,
      entryDomain: 'tenant',
      reason,
      activeTenantId
    });

  const createForeignKeyConstraintError = () => {
    const error = new Error('Cannot delete or update a parent row: a foreign key constraint fails');
    error.code = 'ER_ROW_IS_REFERENCED_2';
    error.errno = 1451;
    return error;
  };

  const createDataTooLongError = () => {
    const error = new Error('Data too long for column');
    error.code = 'ER_DATA_TOO_LONG';
    error.errno = 1406;
    return error;
  };

  const hasOrgReferenceForUser = (userId) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return false;
    }

    for (const org of orgsById.values()) {
      if (
        String(org?.ownerUserId || '').trim() === normalizedUserId
        || String(org?.createdByUserId || '').trim() === normalizedUserId
      ) {
        return true;
      }
    }
    for (const memberships of membershipsByOrgId.values()) {
      if (!Array.isArray(memberships)) {
        continue;
      }
      if (
        memberships.some(
          (membership) => String(membership?.userId || '').trim() === normalizedUserId
        )
      ) {
        return true;
      }
    }
    return false;
  };

  return {
    bumpSessionVersionAndConvergeSessions,
    revokeSessionsForUserByEntryDomain,
    revokePlatformSessionsForUser,
    revokeTenantSessionsForUser,
    createForeignKeyConstraintError,
    createDataTooLongError,
    hasOrgReferenceForUser
  };
};

module.exports = {
  createSharedMemoryAuthStoreSessionConvergenceRuntimeSupport
};

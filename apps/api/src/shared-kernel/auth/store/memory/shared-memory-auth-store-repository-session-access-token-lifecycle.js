const createSharedMemoryAuthStoreRepositorySessionAccessTokenLifecycle = ({
  clone,
  usersByPhone,
  usersById,
  orgsById,
  systemSensitiveConfigsByKey,
  sessionsById,
  refreshTokensByHash,
  domainsByUserId,
  platformDomainKnownByUserId,
  platformProfilesByUserId,
  platformRoleCatalogById,
  platformRolesByUserId,
  platformPermissionsByUserId,
  cloneSystemSensitiveConfigRecord,
  clonePlatformRoleCatalogRecord,
  isActiveLikeStatus,
  resolvePlatformUserReadModel,
  normalizeSystemSensitiveConfigKey,
  normalizeSystemSensitiveConfigStatus,
  normalizeOrgStatus,
  normalizeDateTimeFilterToEpoch,
  normalizeRequiredPlatformUserProfileField,
  normalizeOptionalPlatformUserProfileField,
  findPlatformRoleCatalogRecordStateByRoleId,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogTenantId,
  normalizePlatformRoleCatalogTenantIdForScope,
  normalizePlatformRoleCatalogStatus,
  listPlatformRolePermissionGrantsForRoleId,
  toPlatformPermissionCodeKey,
  syncPlatformPermissionFromRoleFacts,
  bumpSessionVersionAndConvergeSessions,
  MAINLAND_PHONE_PATTERN,
  CONTROL_CHAR_PATTERN,
  ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
  VALID_ORG_STATUS,
  VALID_PLATFORM_USER_STATUS,
  PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
} = {}) => {
  return {
    createSession: async ({
      sessionId,
      userId,
      sessionVersion,
      entryDomain = 'platform',
      activeTenantId = null
    }) => {
      sessionsById.set(sessionId, {
        sessionId,
        userId: String(userId),
        sessionVersion: Number(sessionVersion),
        entryDomain: String(entryDomain || 'platform').toLowerCase(),
        activeTenantId: activeTenantId ? String(activeTenantId) : null,
        status: 'active',
        revokedReason: null,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
    },

    findSessionById: async (sessionId) => clone(sessionsById.get(sessionId) || null),

    updateSessionContext: async ({ sessionId, entryDomain, activeTenantId }) => {
      const session = sessionsById.get(sessionId);
      if (!session) {
        return false;
      }

      if (entryDomain !== undefined) {
        session.entryDomain = String(entryDomain || 'platform').toLowerCase();
      }
      if (activeTenantId !== undefined) {
        session.activeTenantId = activeTenantId ? String(activeTenantId) : null;
      }
      session.updatedAt = Date.now();
      sessionsById.set(sessionId, session);
      return true;
    },

    findDomainAccessByUserId: async (userId) => {
      const userDomains = domainsByUserId.get(String(userId)) || new Set();
      return {
        platform: userDomains.has('platform'),
        tenant: userDomains.has('tenant')
      };
    },

    createRefreshToken: async ({ tokenHash, sessionId, userId, expiresAt }) => {
      refreshTokensByHash.set(tokenHash, {
        tokenHash,
        sessionId,
        userId: String(userId),
        status: 'active',
        rotatedFrom: null,
        rotatedTo: null,
        expiresAt,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
    },

    findRefreshTokenByHash: async (tokenHash) => clone(refreshTokensByHash.get(tokenHash) || null),

    markRefreshTokenStatus: async ({ tokenHash, status }) => {
      const token = refreshTokensByHash.get(tokenHash);
      if (!token) {
        return;
      }

      token.status = status;
      token.updatedAt = Date.now();
    },

    linkRefreshRotation: async ({ previousTokenHash, nextTokenHash }) => {
      const previous = refreshTokensByHash.get(previousTokenHash);
      if (previous) {
        previous.rotatedTo = nextTokenHash;
        previous.updatedAt = Date.now();
      }

      const next = refreshTokensByHash.get(nextTokenHash);
      if (next) {
        next.rotatedFrom = previousTokenHash;
        next.updatedAt = Date.now();
      }
    },

    rotateRefreshToken: async ({ previousTokenHash, nextTokenHash, sessionId, userId, expiresAt }) => {
      const normalizedSessionId = String(sessionId);
      const normalizedUserId = String(userId);
      const previous = refreshTokensByHash.get(previousTokenHash);
      if (
        !previous
        || previous.status !== 'active'
        || String(previous.sessionId || '') !== normalizedSessionId
        || String(previous.userId || '') !== normalizedUserId
      ) {
        return { ok: false };
      }

      previous.status = 'rotated';
      previous.rotatedTo = nextTokenHash;
      previous.updatedAt = Date.now();

      refreshTokensByHash.set(nextTokenHash, {
        tokenHash: nextTokenHash,
        sessionId: normalizedSessionId,
        userId: normalizedUserId,
        status: 'active',
        rotatedFrom: previousTokenHash,
        rotatedTo: null,
        expiresAt,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });

      return { ok: true };
    },

    revokeSession: async ({ sessionId, reason }) => {
      const session = sessionsById.get(sessionId);
      if (session && session.status === 'active') {
        session.status = 'revoked';
        session.revokedReason = reason;
        session.updatedAt = Date.now();
      }

      for (const refreshRecord of refreshTokensByHash.values()) {
        if (refreshRecord.sessionId === sessionId && refreshRecord.status === 'active') {
          refreshRecord.status = 'revoked';
          refreshRecord.updatedAt = Date.now();
        }
      }
    },

    revokeAllUserSessions: async ({ userId, reason }) => {
      for (const session of sessionsById.values()) {
        if (session.userId === String(userId) && session.status === 'active') {
          session.status = 'revoked';
          session.revokedReason = reason;
          session.updatedAt = Date.now();
        }
      }

      for (const refreshRecord of refreshTokensByHash.values()) {
        if (refreshRecord.userId === String(userId) && refreshRecord.status === 'active') {
          refreshRecord.status = 'revoked';
          refreshRecord.updatedAt = Date.now();
        }
      }
    },

    updateUserPasswordAndBumpSessionVersion: async ({ userId, passwordHash }) => {
      const user = bumpSessionVersionAndConvergeSessions({
        userId,
        passwordHash,
        reason: 'password-changed',
        revokeRefreshTokens: false,
        revokeAuthSessions: false
      });
      return clone(user);
    },

    updateUserPasswordAndRevokeSessions: async ({ userId, passwordHash, reason }) => {
      const user = bumpSessionVersionAndConvergeSessions({
        userId,
        passwordHash,
        reason: reason || 'password-changed',
        revokeRefreshTokens: true,
        revokeAuthSessions: true
      });
      return clone(user);
    }
  };
};

module.exports = {
  createSharedMemoryAuthStoreRepositorySessionAccessTokenLifecycle
};

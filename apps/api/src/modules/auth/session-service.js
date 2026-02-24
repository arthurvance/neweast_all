const createAuthSessionService = ({
  userRepository,
  sessionRepository,
  jwtKeyPair,
  signJwt,
  verifyJwt,
  tokenHash,
  randomUUID,
  now,
  normalizeEntryDomain,
  normalizeTenantId,
  normalizeOrgStatus,
  accessSessionCache,
  accessSessionCacheTtlMs,
  addAccessInvalidAuditEvent,
  errors,
  accessTtlSeconds,
  refreshTtlSeconds
} = {}) => {
  const invalidateSessionCacheBySessionId = (sessionId) => {
    for (const key of accessSessionCache.keys()) {
      if (key.startsWith(`${String(sessionId)}:`)) {
        accessSessionCache.delete(key);
      }
    }
  };

  const invalidateSessionCacheByUserId = (userId) => {
    for (const key of accessSessionCache.keys()) {
      const parts = key.split(':');
      if (parts[1] === String(userId)) {
        accessSessionCache.delete(key);
      }
    }
  };

  const invalidateAllAccessSessionCache = () => {
    accessSessionCache.clear();
  };

  const buildSessionContext = (session = {}) => ({
    entry_domain: normalizeEntryDomain(session.entryDomain || session.entry_domain || 'platform') || 'platform',
    active_tenant_id: normalizeTenantId(session.activeTenantId || session.active_tenant_id)
  });

  const issueAccessToken = ({ userId, sessionId, sessionVersion }) =>
    signJwt({
      privateKeyPem: jwtKeyPair.privateKey,
      ttlSeconds: accessTtlSeconds,
      payload: {
        sub: userId,
        sid: sessionId,
        sv: sessionVersion,
        jti: randomUUID(),
        typ: 'access'
      }
    });

  const issueRefreshToken = ({ userId, sessionId, sessionVersion, refreshTokenId }) =>
    signJwt({
      privateKeyPem: jwtKeyPair.privateKey,
      ttlSeconds: refreshTtlSeconds,
      payload: {
        sub: userId,
        sid: sessionId,
        sv: sessionVersion,
        jti: refreshTokenId,
        typ: 'refresh'
      }
    });

  const issueLoginTokenPair = async ({
    userId,
    sessionId,
    sessionVersion
  }) => {
    const refreshTokenId = randomUUID();
    const refreshHash = tokenHash(refreshTokenId);
    const expiresAt = now() + Number(refreshTtlSeconds) * 1000;

    await sessionRepository.createRefreshToken({
      tokenHash: refreshHash,
      sessionId,
      userId,
      expiresAt
    });

    const accessToken = signJwt({
      privateKeyPem: jwtKeyPair.privateKey,
      ttlSeconds: accessTtlSeconds,
      payload: {
        sub: userId,
        sid: sessionId,
        sv: sessionVersion,
        jti: randomUUID(),
        typ: 'access'
      }
    });

    const refreshToken = issueRefreshToken({
      userId,
      sessionId,
      sessionVersion,
      refreshTokenId
    });

    return {
      accessToken,
      refreshToken,
      refreshHash
    };
  };

  const createSessionAndIssueLoginTokens = async ({
    userId,
    sessionVersion,
    entryDomain,
    activeTenantId
  }) => {
    const sessionId = randomUUID();
    await sessionRepository.createSession({
      sessionId,
      userId,
      sessionVersion: Number(sessionVersion),
      entryDomain,
      activeTenantId
    });

    const { accessToken, refreshToken } = await issueLoginTokenPair({
      userId,
      sessionId,
      sessionVersion: Number(sessionVersion)
    });

    return {
      sessionId,
      accessToken,
      refreshToken,
      sessionContext: {
        entry_domain: entryDomain,
        active_tenant_id: normalizeTenantId(activeTenantId)
      }
    };
  };

  const assertValidAccessSession = async ({
    accessToken,
    requestId = 'request_id_unset'
  }) => {
    let payload;
    try {
      payload = verifyJwt({
        token: accessToken,
        publicKeyPem: jwtKeyPair.publicKey,
        expectedTyp: 'access'
      });
    } catch (_error) {
      if (typeof addAccessInvalidAuditEvent === 'function') {
        addAccessInvalidAuditEvent({
          requestId,
          dispositionReason: 'access-token-malformed'
        });
      }
      throw errors.invalidAccess();
    }

    const cacheKey = `${String(payload.sid)}:${String(payload.sub)}:${String(payload.sv)}`;
    if (Number(accessSessionCacheTtlMs) > 0) {
      const cached = accessSessionCache.get(cacheKey);
      if (cached && cached.expiresAt > now()) {
        return { payload, session: cached.session, user: cached.user };
      }
    }

    const [session, user] = await Promise.all([
      sessionRepository.findSessionById(payload.sid),
      userRepository.findUserById(payload.sub)
    ]);

    const normalizedSessionStatus = String(session?.status || '').toLowerCase();
    const normalizedUserStatus = user ? normalizeOrgStatus(user.status) : '';
    const hasInvalidUserStatus = Boolean(user) && normalizedUserStatus !== 'active';
    const normalizedRevokedReason = String(
      session?.revokedReason || session?.revoked_reason || ''
    ).trim().toLowerCase();
    const revokedByCriticalStateChange = normalizedSessionStatus === 'revoked'
      && (
        normalizedRevokedReason === 'password-changed'
        || normalizedRevokedReason === 'platform-role-facts-changed'
        || normalizedRevokedReason === 'critical-state-changed'
      );
    if (!session || !user || normalizedSessionStatus !== 'active' || hasInvalidUserStatus) {
      const dispositionReason = !session
        ? 'access-session-missing'
        : !user
          ? 'access-user-missing'
          : hasInvalidUserStatus
            ? `user-status-${normalizedUserStatus || 'invalid'}`
          : revokedByCriticalStateChange
            ? 'session-version-mismatch'
          : `access-session-${normalizedSessionStatus || 'invalid'}`;
      if (typeof addAccessInvalidAuditEvent === 'function') {
        addAccessInvalidAuditEvent({
          requestId,
          payload,
          userId: payload?.sub || 'unknown',
          sessionId: payload?.sid || 'unknown',
          dispositionReason
        });
      }
      throw errors.invalidAccess();
    }

    const boundUserMismatch = String(session.userId) !== String(payload.sub);
    const sessionVersionMismatch =
      Number(session.sessionVersion) !== Number(payload.sv)
      || Number(user.sessionVersion) !== Number(payload.sv);
    if (boundUserMismatch || sessionVersionMismatch) {
      const dispositionReason = boundUserMismatch
        ? 'access-token-binding-mismatch'
        : sessionVersionMismatch
          ? 'session-version-mismatch'
          : 'access-token-state-mismatch';
      if (typeof addAccessInvalidAuditEvent === 'function') {
        addAccessInvalidAuditEvent({
          requestId,
          payload,
          userId: user.id || payload?.sub || 'unknown',
          sessionId: session.sessionId || session.session_id || payload?.sid || 'unknown',
          dispositionReason
        });
      }
      throw errors.invalidAccess();
    }

    if (Number(accessSessionCacheTtlMs) > 0) {
      accessSessionCache.set(cacheKey, {
        session,
        user,
        expiresAt: now() + Number(accessSessionCacheTtlMs)
      });
    }
    return { payload, session, user };
  };

  const resolveAuthorizedSession = async ({
    requestId,
    accessToken,
    authorizationContext = null
  }) => {
    const authorizedSession = await assertValidAccessSession({
      accessToken,
      requestId
    });
    if (!authorizationContext || typeof authorizationContext !== 'object') {
      return authorizedSession;
    }

    const contextSession = authorizationContext.session;
    const contextUser = authorizationContext.user;
    if (!contextSession || !contextUser) {
      return authorizedSession;
    }

    const resolvedSessionId = String(
      authorizedSession.session?.sessionId || authorizedSession.session?.session_id || ''
    ).trim();
    const resolvedUserId = String(
      authorizedSession.user?.id || authorizedSession.user?.user_id || ''
    ).trim();
    const contextSessionId = String(
      contextSession?.sessionId || contextSession?.session_id || ''
    ).trim();
    const contextUserId = String(contextUser?.id || contextUser?.user_id || '').trim();

    if (
      resolvedSessionId.length === 0
      || resolvedUserId.length === 0
      || contextSessionId.length === 0
      || contextUserId.length === 0
      || resolvedSessionId !== contextSessionId
      || resolvedUserId !== contextUserId
    ) {
      const auditUserId = contextUserId || resolvedUserId || 'unknown';
      const auditSessionId = contextSessionId || resolvedSessionId || 'unknown';
      if (typeof addAccessInvalidAuditEvent === 'function') {
        addAccessInvalidAuditEvent({
          requestId,
          userId: auditUserId,
          sessionId: auditSessionId,
          dispositionReason: 'access-authorization-context-mismatch'
        });
      }
      throw errors.invalidAccess();
    }

    return authorizedSession;
  };

  return {
    invalidateSessionCacheBySessionId,
    invalidateSessionCacheByUserId,
    invalidateAllAccessSessionCache,
    buildSessionContext,
    issueAccessToken,
    issueRefreshToken,
    issueLoginTokenPair,
    createSessionAndIssueLoginTokens,
    assertValidAccessSession,
    resolveAuthorizedSession
  };
};

module.exports = {
  createAuthSessionService
};

'use strict';

const createSharedAuthRefreshSessionCapabilities = ({
  authStore,
  now,
  errors,
  bindRequestTraceparent,
  addAuditEvent,
  verifyJwt,
  jwtKeyPair,
  tokenHash,
  normalizeOrgStatus,
  invalidateSessionCacheBySessionId,
  randomUUID,
  issueAccessToken,
  issueRefreshToken,
  buildSessionContext,
  getTenantOptionsForUser,
  reconcileTenantSessionContext,
  getTenantPermissionContext,
  getPlatformPermissionContext,
  resolveLoginUserName,
  resolveAuthorizedSession,
  ACCESS_TTL_SECONDS,
  REFRESH_TTL_SECONDS
} = {}) => {
  const refresh = async ({ requestId, refreshToken, traceparent = null }) => {
    bindRequestTraceparent({
      requestId,
      traceparent
    });
    if (typeof refreshToken !== 'string' || refreshToken.trim() === '') {
      addAuditEvent({
        type: 'auth.refresh.replay_or_invalid',
        requestId,
        detail: 'refresh payload missing',
        metadata: {
          session_id_hint: 'unknown',
          disposition_reason: 'refresh-payload-missing',
          disposition_action: 'reject-only'
        }
      });
      throw errors.invalidPayload();
    }

    let payload;
    try {
      payload = verifyJwt({
        token: refreshToken,
        publicKeyPem: jwtKeyPair.publicKey,
        expectedTyp: 'refresh'
      });
    } catch (error) {
      const isExpiredRefreshToken = String(error?.code || '').trim().toUpperCase() === 'JWT_EXPIRED';
      const expiredPayload = isExpiredRefreshToken && error?.payload && typeof error.payload === 'object'
        ? error.payload
        : null;
      const expiredUserId = expiredPayload?.sub ? String(expiredPayload.sub) : 'unknown';
      const expiredSessionId = expiredPayload?.sid ? String(expiredPayload.sid) : 'unknown';
      addAuditEvent({
        type: 'auth.refresh.replay_or_invalid',
        requestId,
        userId: isExpiredRefreshToken ? expiredUserId : 'unknown',
        sessionId: isExpiredRefreshToken ? expiredSessionId : 'unknown',
        detail: isExpiredRefreshToken ? 'refresh token expired' : 'refresh token malformed',
        metadata: {
          session_id_hint: isExpiredRefreshToken ? expiredSessionId : 'unknown',
          disposition_reason: isExpiredRefreshToken
            ? 'refresh-token-expired'
            : 'refresh-token-malformed',
          disposition_action: 'reject-only'
        }
      });
      throw errors.invalidRefresh();
    }

    const refreshHash = tokenHash(String(payload.jti || ''));
    const [refreshRecord, session, user] = await Promise.all([
      authStore.findRefreshTokenByHash(refreshHash),
      authStore.findSessionById(payload.sid),
      authStore.findUserById(payload.sub)
    ]);

    const refreshStatus = refreshRecord ? String(refreshRecord.status).toLowerCase() : 'missing';
    const refreshExpired = Boolean(refreshRecord) && refreshRecord.expiresAt <= now();
    const refreshBelongsToClaim = Boolean(
      refreshRecord
      && String(refreshRecord.sessionId || '') === String(payload.sid || '')
      && String(refreshRecord.userId || '') === String(payload.sub || '')
    );
    const normalizedUserStatus = user ? normalizeOrgStatus(user.status) : '';
    const hasInvalidUserStatus = Boolean(user) && normalizedUserStatus !== 'active';

    const sessionVersionMismatch = Boolean(session && user)
      && (
        Number(session.sessionVersion) !== Number(payload.sv)
        || Number(user.sessionVersion) !== Number(payload.sv)
      );
    const invalidState = (
      !refreshRecord
      || !refreshBelongsToClaim
      || refreshStatus !== 'active'
      || refreshExpired
      || !session
      || String(session.status).toLowerCase() !== 'active'
      || !user
      || hasInvalidUserStatus
      || String(session.userId) !== String(user.id)
      || sessionVersionMismatch
    );

    if (invalidState) {
      const replayDetected = refreshBelongsToClaim
        && (refreshStatus === 'rotated' || refreshStatus === 'revoked');
      const dispositionReason = !refreshRecord
          ? 'refresh-token-missing'
          : !refreshBelongsToClaim
            ? 'refresh-token-binding-mismatch'
          : refreshExpired
            ? 'refresh-token-expired'
            : hasInvalidUserStatus
              ? `user-status-${normalizedUserStatus || 'invalid'}`
            : sessionVersionMismatch
              ? 'session-version-mismatch'
            : replayDetected
              ? 'refresh-replay-detected'
            : refreshStatus === 'active'
              ? 'refresh-token-state-mismatch'
              : `refresh-token-${refreshStatus}`;

      if (refreshRecord && refreshStatus === 'active' && refreshBelongsToClaim) {
        await authStore.markRefreshTokenStatus({
          tokenHash: refreshHash,
          status: 'revoked'
        });
      }

      if (replayDetected) {
        await authStore.revokeSession({
          sessionId: refreshRecord.sessionId || payload.sid,
          reason: 'refresh-replay-detected'
        });
        invalidateSessionCacheBySessionId(refreshRecord.sessionId || payload.sid);
      }

      addAuditEvent({
        type: 'auth.refresh.replay_or_invalid',
        requestId,
        userId: payload.sub,
        sessionId: payload.sid,
        detail: 'refresh token rejected',
        metadata: {
          session_id_hint: String(payload.sid || 'unknown'),
          refresh_status: refreshStatus,
          disposition_reason: dispositionReason,
          disposition_action: replayDetected
            ? 'revoke-session-chain'
            : refreshStatus === 'active' && refreshBelongsToClaim
              ? 'revoke-current-token'
              : 'reject-only'
        }
      });
      throw errors.invalidRefresh();
    }

    const sessionId = session.sessionId || session.session_id || payload.sid;
    const nextRefreshTokenId = randomUUID();
    const nextRefreshHash = tokenHash(nextRefreshTokenId);
    const nextRefreshExpiresAt = now() + REFRESH_TTL_SECONDS * 1000;

    if (typeof authStore.rotateRefreshToken === 'function') {
      const rotated = await authStore.rotateRefreshToken({
        previousTokenHash: refreshHash,
        nextTokenHash: nextRefreshHash,
        sessionId,
        userId: user.id,
        expiresAt: nextRefreshExpiresAt
      });

      if (!rotated || rotated.ok !== true) {
        await authStore.revokeSession({
          sessionId,
          reason: 'refresh-rotation-conflict'
        });
        invalidateSessionCacheBySessionId(sessionId);
        addAuditEvent({
          type: 'auth.refresh.replay_or_invalid',
          requestId,
          userId: user.id,
          sessionId,
          detail: 'refresh token rejected by rotation conflict',
          metadata: {
            session_id_hint: String(sessionId || 'unknown'),
            disposition_reason: 'refresh-rotation-conflict',
            disposition_action: 'revoke-session-chain'
          }
        });
        throw errors.invalidRefresh();
      }
    } else {
      await authStore.markRefreshTokenStatus({
        tokenHash: refreshHash,
        status: 'rotated'
      });

      await authStore.createRefreshToken({
        tokenHash: nextRefreshHash,
        sessionId,
        userId: user.id,
        expiresAt: nextRefreshExpiresAt
      });

      await authStore.linkRefreshRotation({
        previousTokenHash: refreshHash,
        nextTokenHash: nextRefreshHash
      });
    }

    const accessToken = issueAccessToken({
      userId: user.id,
      sessionId,
      sessionVersion: Number(user.sessionVersion)
    });
    const nextRefreshToken = issueRefreshToken({
      userId: user.id,
      sessionId,
      sessionVersion: Number(user.sessionVersion),
      refreshTokenId: nextRefreshTokenId
    });
    let sessionContext = buildSessionContext(session);
    const refreshedTenantOptions = sessionContext.entry_domain === 'tenant'
      ? await getTenantOptionsForUser(user.id)
      : [];
    sessionContext = await reconcileTenantSessionContext({
      requestId,
      userId: user.id,
      sessionId,
      sessionContext,
      options: refreshedTenantOptions
    });
    const tenantSwitchRequired = sessionContext.entry_domain === 'tenant'
      && refreshedTenantOptions.length > 1
      && !sessionContext.active_tenant_id;
    const tenantPermissionContext = await getTenantPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: sessionContext.active_tenant_id
    });
    const platformPermissionContext = await getPlatformPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: sessionContext.entry_domain
    });
    const userName = await resolveLoginUserName({
      userId: user.id,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: sessionContext.active_tenant_id
    });

    addAuditEvent({
      type: 'auth.refresh.succeeded',
      requestId,
      userId: user.id,
      sessionId
    });

    return {
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: nextRefreshToken,
      expires_in: ACCESS_TTL_SECONDS,
      refresh_expires_in: REFRESH_TTL_SECONDS,
      session_id: sessionId,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: sessionContext.active_tenant_id,
      tenant_selection_required: tenantSwitchRequired,
      tenant_options: refreshedTenantOptions,
      user_name: userName,
      platform_permission_context: platformPermissionContext,
      tenant_permission_context: tenantPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  const logout = async ({
    requestId,
    accessToken,
    authorizationContext = null,
    traceparent = null
  }) => {
    bindRequestTraceparent({
      requestId,
      traceparent
    });
    const { session, user } = await resolveAuthorizedSession({
      requestId,
      accessToken,
      authorizationContext
    });
    const sessionId = session.sessionId || session.session_id;
    await authStore.revokeSession({
      sessionId,
      reason: 'logout-current-session'
    });
    invalidateSessionCacheBySessionId(sessionId);

    addAuditEvent({
      type: 'auth.logout.current_session',
      requestId,
      userId: user.id,
      sessionId
    });

    return {
      ok: true,
      session_id: sessionId,
      request_id: requestId || 'request_id_unset'
    };
  };

  return {
    refresh,
    logout
  };
};

module.exports = {
  createSharedAuthRefreshSessionCapabilities
};

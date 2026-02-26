'use strict';

const createSharedAuthCredentialGovernanceCapabilities = ({
  now,
  errors,
  otpStore,
  rateLimitStore,
  bindRequestTraceparent,
  addAuditEvent,
  maskPhone,
  normalizePhone,
  randomInt,
  resolveAuthorizedSession,
  verifyPassword,
  normalizeAuditStringOrNull,
  normalizeAuditDomain,
  recordPersistentAuditEvent,
  authStore,
  hashPassword,
  invalidateSessionCacheByUserId,
  OTP_CODE_LENGTH,
  OTP_RESEND_COOLDOWN_SECONDS,
  PASSWORD_MIN_LENGTH,
  OTP_TTL_SECONDS,
  RATE_LIMIT_WINDOW_SECONDS,
  RATE_LIMIT_MAX_ATTEMPTS
} = {}) => {
  const validatePasswordPolicy = (candidatePassword) => {
    if (typeof candidatePassword !== 'string' || candidatePassword.length < PASSWORD_MIN_LENGTH) {
      throw errors.weakPassword();
    }
  };

  const assertRateLimit = async ({ requestId, phone, action }) => {
    const result = await rateLimitStore.consume({
      phone,
      action,
      limit: RATE_LIMIT_MAX_ATTEMPTS,
      windowSeconds: RATE_LIMIT_WINDOW_SECONDS,
      nowMs: now()
    });

    if (result.allowed) {
      return result;
    }

    addAuditEvent({
      type: 'auth.rate_limited',
      requestId,
      detail: `rate limit exceeded for ${action}`,
      metadata: {
        phone_masked: maskPhone(phone),
        rate_limit_action: action,
        retry_after_seconds: result.remainingSeconds
      }
    });

    throw errors.rateLimited({
      action,
      remainingSeconds: result.remainingSeconds,
      limit: RATE_LIMIT_MAX_ATTEMPTS,
      windowSeconds: RATE_LIMIT_WINDOW_SECONDS
    });
  };

  const sendOtp = async ({ requestId, phone, traceparent = null }) => {
    bindRequestTraceparent({
      requestId,
      traceparent
    });
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) {
      throw errors.invalidPayload();
    }

    const currentTime = now();
    let lastSentAt = null;
    try {
      lastSentAt = await otpStore.getSentAt({ phone: normalizedPhone });
    } catch (error) {
      addAuditEvent({
        type: 'auth.otp.send.cooldown_check_failed',
        requestId,
        detail: `getSentAt failed: ${error.message}`,
        metadata: { phone_masked: maskPhone(normalizedPhone) }
      });
      throw errors.rateLimited({
        action: 'otp_send',
        remainingSeconds: OTP_RESEND_COOLDOWN_SECONDS,
        limit: 1,
        windowSeconds: OTP_RESEND_COOLDOWN_SECONDS
      });
    }

    if (lastSentAt !== null && lastSentAt !== undefined) {
      const lastSentAtMs = Number(lastSentAt);
      if (!Number.isFinite(lastSentAtMs) || lastSentAtMs <= 0) {
        addAuditEvent({
          type: 'auth.otp.send.cooldown_check_failed',
          requestId,
          detail: `getSentAt returned invalid value: ${String(lastSentAt)}`,
          metadata: { phone_masked: maskPhone(normalizedPhone) }
        });
        throw errors.rateLimited({
          action: 'otp_send',
          remainingSeconds: OTP_RESEND_COOLDOWN_SECONDS,
          limit: 1,
          windowSeconds: OTP_RESEND_COOLDOWN_SECONDS
        });
      }

      const cooldownEndsAt = lastSentAtMs + OTP_RESEND_COOLDOWN_SECONDS * 1000;
      if (cooldownEndsAt > currentTime) {
        const remainingSeconds = Math.ceil((cooldownEndsAt - currentTime) / 1000);
        addAuditEvent({
          type: 'auth.otp.send.cooldown',
          requestId,
          detail: 'otp resend within cooldown period',
          metadata: {
            phone_masked: maskPhone(normalizedPhone),
            resend_after_seconds: remainingSeconds
          }
        });
        throw errors.rateLimited({
          action: 'otp_send',
          remainingSeconds,
          limit: 1,
          windowSeconds: OTP_RESEND_COOLDOWN_SECONDS
        });
      }
    }

    await assertRateLimit({
      requestId,
      phone: normalizedPhone,
      action: 'otp_send'
    });

    const otpCode = String(randomInt(0, 10 ** OTP_CODE_LENGTH)).padStart(OTP_CODE_LENGTH, '0');
    const expiresAt = currentTime + OTP_TTL_SECONDS * 1000;

    try {
      await otpStore.upsertOtp({
        phone: normalizedPhone,
        code: otpCode,
        expiresAt
      });
    } catch (error) {
      addAuditEvent({
        type: 'auth.otp.send.failed',
        requestId,
        detail: `otp store failure: ${error.message}`,
        metadata: { phone_masked: maskPhone(normalizedPhone) }
      });
      throw error;
    }

    addAuditEvent({
      type: 'auth.otp.send.succeeded',
      requestId,
      detail: 'otp code issued',
      metadata: {
        phone_masked: maskPhone(normalizedPhone),
        resend_after_seconds: OTP_RESEND_COOLDOWN_SECONDS
      }
    });

    return {
      sent: true,
      resend_after_seconds: OTP_RESEND_COOLDOWN_SECONDS,
      request_id: requestId || 'request_id_unset'
    };
  };

  const changePassword = async ({
    requestId,
    accessToken,
    currentPassword,
    newPassword,
    authorizationContext = null,
    traceparent = null
  }) => {
    bindRequestTraceparent({
      requestId,
      traceparent
    });
    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
      addAuditEvent({
        type: 'auth.password_change.rejected',
        requestId,
        detail: 'password payload invalid',
        metadata: {
          session_id_hint: 'unknown'
        }
      });
      throw errors.invalidPayload();
    }

    try {
      validatePasswordPolicy(newPassword);
    } catch (error) {
      addAuditEvent({
        type: 'auth.password_change.rejected',
        requestId,
        detail: 'new password policy violation',
        metadata: {
          session_id_hint: 'unknown'
        }
      });
      throw error;
    }

    const { session, user } = await resolveAuthorizedSession({
      requestId,
      accessToken,
      authorizationContext
    });
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);
    const normalizedSessionEntryDomain = normalizeAuditDomain(
      session.entryDomain || session.entry_domain || 'platform'
    );
    const normalizedSessionActiveTenantId = normalizeAuditStringOrNull(
      session.activeTenantId || session.active_tenant_id,
      64
    );
    const resolvedPasswordAuditDomain =
      normalizedSessionEntryDomain === 'tenant' && normalizedSessionActiveTenantId
        ? 'tenant'
        : 'platform';
    const resolvedPasswordAuditTenantId =
      resolvedPasswordAuditDomain === 'tenant'
        ? normalizedSessionActiveTenantId
        : null;
    const currentPasswordValid = verifyPassword(currentPassword, user.passwordHash);

    if (!currentPasswordValid) {
      addAuditEvent({
        type: 'auth.password_change.rejected',
        requestId,
        userId: user.id,
        sessionId: session.sessionId || session.session_id,
        detail: 'current password mismatch',
        metadata: {
          phone_masked: maskPhone(user.phone)
        }
      });
      await recordPersistentAuditEvent({
        domain: resolvedPasswordAuditDomain,
        tenantId: resolvedPasswordAuditTenantId,
        requestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.password_change.rejected',
        actorUserId: user.id,
        actorSessionId: session.sessionId || session.session_id || null,
        targetType: 'user',
        targetId: user.id,
        result: 'rejected',
        beforeState: {
          session_version: Number(user.sessionVersion || 0)
        },
        afterState: {
          session_version: Number(user.sessionVersion || 0)
        },
        metadata: {
          reason: 'current-password-mismatch',
          phone_masked: maskPhone(user.phone)
        }
      });
      throw errors.loginFailed();
    }

    const previousSessionVersion = Number(user.sessionVersion || 0);
    const updatedUser = typeof authStore.updateUserPasswordAndRevokeSessions === 'function'
      ? await authStore.updateUserPasswordAndRevokeSessions({
        userId: user.id,
        passwordHash: hashPassword(newPassword),
        reason: 'password-changed'
      })
      : await authStore.updateUserPasswordAndBumpSessionVersion({
        userId: user.id,
        passwordHash: hashPassword(newPassword)
      });
    if (!updatedUser) {
      throw errors.invalidAccess();
    }
    if (typeof authStore.updateUserPasswordAndRevokeSessions !== 'function') {
      await authStore.revokeAllUserSessions({
        userId: user.id,
        reason: 'password-changed'
      });
    }
    invalidateSessionCacheByUserId(user.id);

    addAuditEvent({
      type: 'auth.password_change.succeeded',
      requestId,
      userId: user.id,
      sessionId: session.sessionId || session.session_id
    });
    await recordPersistentAuditEvent({
      domain: resolvedPasswordAuditDomain,
      tenantId: resolvedPasswordAuditTenantId,
      requestId,
      traceparent: normalizedTraceparent,
      eventType: 'auth.password_change.succeeded',
      actorUserId: user.id,
      actorSessionId: session.sessionId || session.session_id || null,
      targetType: 'user',
      targetId: user.id,
      result: 'success',
      beforeState: {
        session_version: previousSessionVersion
      },
      afterState: {
        session_version: Number(updatedUser.sessionVersion || previousSessionVersion)
      },
      metadata: {
        relogin_required: true
      }
    });

    return {
      password_changed: true,
      relogin_required: true,
      request_id: requestId || 'request_id_unset'
    };
  };

  return {
    validatePasswordPolicy,
    assertRateLimit,
    sendOtp,
    changePassword
  };
};

module.exports = {
  createSharedAuthCredentialGovernanceCapabilities
};

const createLoginService = ({
  userRepository,
  otpStore,
  errors,
  addAuditEvent,
  bindRequestTraceparent,
  now,
  normalizePhone,
  normalizeEntryDomain,
  maskPhone,
  isUserActive,
  verifyPassword,
  assertRateLimit,
  shouldProvisionDefaultPlatformDomainAccess,
  ensureDefaultDomainAccessForUser,
  ensureTenantDomainAccessForUser,
  assertDomainAccess,
  getTenantOptionsForUser,
  createSessionAndIssueLoginTokens,
  getTenantPermissionContext,
  getPlatformPermissionContext,
  resolveLoginUserName,
  accessTtlSeconds,
  refreshTtlSeconds
} = {}) => {
  const buildLoginResult = async ({
    requestId,
    user,
    normalizedPhone,
    normalizedEntryDomain,
    sessionId,
    sessionContext,
    tenantOptions,
    tenantSwitchRequired,
    successAuditType,
    resendAfterSeconds
  }) => {
    addAuditEvent({
      type: 'auth.domain.bound',
      requestId,
      userId: user.id,
      sessionId,
      detail: `domain bound to session: ${normalizedEntryDomain}`,
      metadata: {
        entry_domain: normalizedEntryDomain,
        tenant_id: sessionContext.active_tenant_id
      }
    });

    const successMetadata = {
      phone_masked: maskPhone(normalizedPhone),
      entry_domain: normalizedEntryDomain,
      tenant_id: sessionContext.active_tenant_id
    };
    if (resendAfterSeconds !== undefined) {
      successMetadata.resend_after_seconds = resendAfterSeconds;
    }
    addAuditEvent({
      type: successAuditType,
      requestId,
      userId: user.id,
      sessionId,
      metadata: successMetadata
    });

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

    return {
      token_type: 'Bearer',
      access_token: sessionContext.access_token,
      refresh_token: sessionContext.refresh_token,
      expires_in: accessTtlSeconds,
      refresh_expires_in: refreshTtlSeconds,
      session_id: sessionId,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: sessionContext.active_tenant_id,
      tenant_selection_required: tenantSwitchRequired,
      tenant_options: tenantOptions,
      user_name: userName,
      platform_permission_context: platformPermissionContext,
      tenant_permission_context: tenantPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  const resolveTenantContextForLogin = async ({
    requestId,
    userId,
    normalizedEntryDomain
  }) => {
    await assertDomainAccess({
      requestId,
      userId,
      entryDomain: normalizedEntryDomain
    });
    const tenantOptions = normalizedEntryDomain === 'tenant'
      ? await getTenantOptionsForUser(userId)
      : [];

    if (normalizedEntryDomain === 'tenant' && tenantOptions.length === 0) {
      addAuditEvent({
        type: 'auth.domain.rejected',
        requestId,
        userId,
        detail: 'tenant entry without active tenant relationship',
        metadata: {
          permission_code: null,
          entry_domain: normalizedEntryDomain,
          tenant_id: null
        }
      });
      throw errors.noDomainAccess();
    }

    const tenantSwitchRequired = normalizedEntryDomain === 'tenant' && tenantOptions.length > 1;
    const activeTenantId = normalizedEntryDomain === 'tenant' && tenantOptions.length === 1
      ? tenantOptions[0].tenant_id
      : null;

    return {
      tenantOptions,
      tenantSwitchRequired,
      activeTenantId
    };
  };

  const login = async ({
    requestId,
    phone,
    password,
    entryDomain,
    traceparent = null
  }) => {
    bindRequestTraceparent({
      requestId,
      traceparent
    });
    const normalizedPhone = normalizePhone(phone);
    const normalizedEntryDomain = normalizeEntryDomain(entryDomain);
    if (
      !normalizedPhone ||
      typeof password !== 'string' ||
      password.trim() === '' ||
      !normalizedEntryDomain
    ) {
      throw errors.invalidPayload();
    }

    const rateLimit = await assertRateLimit({
      requestId,
      phone: normalizedPhone,
      action: 'password_login'
    });

    const user = await userRepository.findUserByPhone(normalizedPhone);
    const validCredentials = Boolean(
      user && isUserActive(user) && verifyPassword(password, user.passwordHash)
    );

    if (!validCredentials) {
      addAuditEvent({
        type: 'auth.login.failed',
        requestId,
        userId: user?.id,
        detail: 'invalid credentials or unavailable user',
        metadata: {
          phone_masked: maskPhone(normalizedPhone),
          session_id_hint: 'unknown'
        }
      });
      throw errors.loginFailed();
    }

    if (normalizedEntryDomain === 'platform') {
      const shouldProvisionDefaultPlatformDomain =
        await shouldProvisionDefaultPlatformDomainAccess({ userId: user.id });
      if (shouldProvisionDefaultPlatformDomain) {
        await ensureDefaultDomainAccessForUser({
          requestId,
          userId: user.id
        });
      }
    }
    if (normalizedEntryDomain === 'tenant') {
      await ensureTenantDomainAccessForUser({
        requestId,
        userId: user.id,
        entryDomain: normalizedEntryDomain
      });
    }

    const {
      tenantOptions,
      tenantSwitchRequired,
      activeTenantId
    } = await resolveTenantContextForLogin({
      requestId,
      userId: user.id,
      normalizedEntryDomain
    });

    const { sessionId, accessToken, refreshToken, sessionContext } =
      await createSessionAndIssueLoginTokens({
        userId: user.id,
        sessionVersion: Number(user.sessionVersion),
        entryDomain: normalizedEntryDomain,
        activeTenantId
      });

    return buildLoginResult({
      requestId,
      user,
      normalizedPhone,
      normalizedEntryDomain,
      sessionId,
      sessionContext: {
        ...sessionContext,
        access_token: accessToken,
        refresh_token: refreshToken
      },
      tenantOptions,
      tenantSwitchRequired,
      successAuditType: 'auth.login.succeeded',
      resendAfterSeconds: rateLimit.remainingSeconds
    });
  };

  const loginWithOtp = async ({
    requestId,
    phone,
    otpCode,
    entryDomain,
    traceparent = null
  }) => {
    bindRequestTraceparent({
      requestId,
      traceparent
    });
    const normalizedPhone = normalizePhone(phone);
    const normalizedEntryDomain = normalizeEntryDomain(entryDomain);
    if (
      !normalizedPhone ||
      typeof otpCode !== 'string' ||
      !/^\d{6}$/.test(otpCode.trim()) ||
      !normalizedEntryDomain
    ) {
      throw errors.invalidPayload();
    }

    await assertRateLimit({
      requestId,
      phone: normalizedPhone,
      action: 'otp_login'
    });

    let verifyResult;
    try {
      verifyResult = await otpStore.verifyAndConsumeOtp({
        phone: normalizedPhone,
        code: otpCode.trim(),
        nowMs: now()
      });
    } catch (error) {
      addAuditEvent({
        type: 'auth.otp.login.failed',
        requestId,
        detail: `otp store failure: ${error.message}`,
        metadata: { phone_masked: maskPhone(normalizedPhone) }
      });
      throw error;
    }

    if (!verifyResult || verifyResult.ok !== true) {
      addAuditEvent({
        type: 'auth.otp.login.failed',
        requestId,
        detail: `otp rejected: ${verifyResult?.reason || 'unknown'}`,
        metadata: {
          phone_masked: maskPhone(normalizedPhone),
          session_id_hint: 'unknown'
        }
      });
      throw errors.otpFailed();
    }

    const user = await userRepository.findUserByPhone(normalizedPhone);
    if (!user || !isUserActive(user)) {
      addAuditEvent({
        type: 'auth.otp.login.failed',
        requestId,
        userId: user?.id,
        detail: 'otp accepted but user unavailable',
        metadata: {
          phone_masked: maskPhone(normalizedPhone),
          session_id_hint: 'unknown'
        }
      });
      throw errors.otpFailed();
    }

    if (normalizedEntryDomain === 'platform') {
      const shouldProvisionDefaultPlatformDomain =
        await shouldProvisionDefaultPlatformDomainAccess({ userId: user.id });
      if (shouldProvisionDefaultPlatformDomain) {
        await ensureDefaultDomainAccessForUser({
          requestId,
          userId: user.id
        });
      }
    }
    if (normalizedEntryDomain === 'tenant') {
      await ensureTenantDomainAccessForUser({
        requestId,
        userId: user.id,
        entryDomain: normalizedEntryDomain
      });
    }

    const {
      tenantOptions,
      tenantSwitchRequired,
      activeTenantId
    } = await resolveTenantContextForLogin({
      requestId,
      userId: user.id,
      normalizedEntryDomain
    });

    const { sessionId, accessToken, refreshToken, sessionContext } =
      await createSessionAndIssueLoginTokens({
        userId: user.id,
        sessionVersion: Number(user.sessionVersion),
        entryDomain: normalizedEntryDomain,
        activeTenantId
      });

    return buildLoginResult({
      requestId,
      user,
      normalizedPhone,
      normalizedEntryDomain,
      sessionId,
      sessionContext: {
        ...sessionContext,
        access_token: accessToken,
        refresh_token: refreshToken
      },
      tenantOptions,
      tenantSwitchRequired,
      successAuditType: 'auth.otp.login.succeeded'
    });
  };

  return {
    login,
    loginWithOtp
  };
};

module.exports = {
  createLoginService
};

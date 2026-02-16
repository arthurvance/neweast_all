const { AuthProblemError, createAuthService } = require('./auth.service');

const authPing = (requestId) => ({
  module: 'auth',
  status: 'ready',
  request_id: requestId
});

const extractBearerToken = (authorization) => {
  if (typeof authorization !== 'string') {
    throw new AuthProblemError({
      status: 401,
      title: 'Unauthorized',
      detail: '当前会话无效，请重新登录',
      errorCode: 'AUTH-401-INVALID-ACCESS'
    });
  }

  const normalizedAuthorization = authorization.trim();
  const match = normalizedAuthorization.match(/^(\S+)\s+(\S+)$/);
  if (!match || match[1].toLowerCase() !== 'bearer') {
    throw new AuthProblemError({
      status: 401,
      title: 'Unauthorized',
      detail: '当前会话无效，请重新登录',
      errorCode: 'AUTH-401-INVALID-ACCESS'
    });
  }

  return match[2];
};

const toPlatformPermissionContextResponse = (permissionContext = null) => ({
  scope_label:
    permissionContext?.scopeLabel
    || permissionContext?.scope_label
    || '平台权限（角色并集）',
  can_view_member_admin: Boolean(
    permissionContext?.canViewMemberAdmin ?? permissionContext?.can_view_member_admin
  ),
  can_operate_member_admin: Boolean(
    permissionContext?.canOperateMemberAdmin ?? permissionContext?.can_operate_member_admin
  ),
  can_view_billing: Boolean(
    permissionContext?.canViewBilling ?? permissionContext?.can_view_billing
  ),
  can_operate_billing: Boolean(
    permissionContext?.canOperateBilling ?? permissionContext?.can_operate_billing
  )
});

const createAuthHandlers = (authService = createAuthService()) => {
  const handlers = {
    login: async ({ requestId, body }) =>
      authService.login({
        requestId,
        phone: body.phone,
        password: body.password,
        entryDomain: body.entry_domain
      }),

    otpSend: async ({ requestId, body }) =>
      authService.sendOtp({
        requestId,
        phone: body.phone
      }),

    otpLogin: async ({ requestId, body }) =>
      authService.loginWithOtp({
        requestId,
        phone: body.phone,
        otpCode: body.otp_code,
        entryDomain: body.entry_domain
      }),

    tenantOptions: async ({ requestId, authorization, authorizationContext = null }) =>
      authService.tenantOptions({
        requestId,
        accessToken: extractBearerToken(authorization),
        authorizationContext
      }),

    tenantSelect: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null
    }) =>
      authService.selectTenant({
        requestId,
        accessToken: extractBearerToken(authorization),
        tenantId: body.tenant_id,
        authorizationContext
      }),

    tenantSwitch: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null
    }) =>
      authService.switchTenant({
        requestId,
        accessToken: extractBearerToken(authorization),
        tenantId: body.tenant_id,
        authorizationContext
      }),

    platformProvisionUser: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null
    }) =>
      authService.provisionPlatformUserByPhone({
        requestId,
        accessToken: extractBearerToken(authorization),
        payload: body,
        authorizationContext
      }),

    tenantProvisionUser: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null
    }) =>
      authService.provisionTenantUserByPhone({
        requestId,
        accessToken: extractBearerToken(authorization),
        payload: body,
        authorizationContext
      }),

    refresh: async ({ requestId, body }) =>
      authService.refresh({
        requestId,
        refreshToken: body.refresh_token
      }),

    logout: async ({ requestId, authorization, authorizationContext = null }) =>
      authService.logout({
        requestId,
        accessToken: extractBearerToken(authorization),
        authorizationContext
      }),

    changePassword: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null
    }) =>
      authService.changePassword({
        requestId,
        accessToken: extractBearerToken(authorization),
        currentPassword: body.current_password,
        newPassword: body.new_password,
        authorizationContext
      }),

    replacePlatformRoleFacts: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null
    }) => {
      const result = await authService.replacePlatformRolesAndSyncSnapshot({
        requestId,
        accessToken: extractBearerToken(authorization),
        userId: body.user_id,
        roles: body.roles,
        authorizationContext
      });
      return {
        synced: Boolean(result?.synced),
        reason: String(result?.reason || 'unknown'),
        platform_permission_context: toPlatformPermissionContextResponse(result?.permission),
        request_id: requestId || 'request_id_unset'
      };
    }
  };

  if (typeof authService.authorizeRoute === 'function') {
    handlers.authorizeRoute = async ({ requestId, authorization, permissionCode, scope }) =>
      authService.authorizeRoute({
        requestId,
        accessToken: extractBearerToken(authorization),
        permissionCode,
        scope
      });
  }

  return handlers;
};

module.exports = {
  AuthProblemError,
  authPing,
  createAuthHandlers,
  extractBearerToken
};

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
  can_view_user_management: Boolean(
    permissionContext?.canViewUserManagement ?? permissionContext?.can_view_user_management
  ),
  can_operate_user_management: Boolean(
    permissionContext?.canOperateUserManagement ?? permissionContext?.can_operate_user_management
  ),
  can_view_tenant_management: Boolean(
    permissionContext?.canViewTenantManagement ?? permissionContext?.can_view_tenant_management
  ),
  can_operate_tenant_management: Boolean(
    permissionContext?.canOperateTenantManagement ?? permissionContext?.can_operate_tenant_management
  ),
  can_view_role_management: Boolean(
    permissionContext?.canViewRoleManagement ?? permissionContext?.can_view_role_management
  ),
  can_operate_role_management: Boolean(
    permissionContext?.canOperateRoleManagement ?? permissionContext?.can_operate_role_management
  )
});

const toProvisionDependencyUnavailable = () =>
  new AuthProblemError({
    status: 503,
    title: 'Service Unavailable',
    detail: '默认密码配置不可用，请稍后重试',
    errorCode: 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE',
    extensions: {
      retryable: true,
      degradation_reason: 'provision-dependency-unavailable'
    }
  });

const mapProvisionUnexpectedError = (error) => {
  if (error instanceof AuthProblemError) {
    throw error;
  }
  throw toProvisionDependencyUnavailable();
};

const createAuthHandlers = (authService = createAuthService()) => {
  const handlers = {
    login: async ({ requestId, body, traceparent = null }) =>
      authService.login({
        requestId,
        phone: body.phone,
        password: body.password,
        entryDomain: body.entry_domain,
        traceparent
      }),

    otpSend: async ({ requestId, body, traceparent = null }) =>
      authService.sendOtp({
        requestId,
        phone: body.phone,
        traceparent
      }),

    otpLogin: async ({ requestId, body, traceparent = null }) =>
      authService.loginWithOtp({
        requestId,
        phone: body.phone,
        otpCode: body.otp_code,
        entryDomain: body.entry_domain,
        traceparent
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
    }) => {
      try {
        return await authService.provisionPlatformUserByPhone({
          requestId,
          accessToken: extractBearerToken(authorization),
          payload: body,
          authorizationContext
        });
      } catch (error) {
        mapProvisionUnexpectedError(error);
      }
    },

    tenantProvisionUser: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null
    }) => {
      try {
        return await authService.provisionTenantUserByPhone({
          requestId,
          accessToken: extractBearerToken(authorization),
          payload: body,
          authorizationContext
        });
      } catch (error) {
        mapProvisionUnexpectedError(error);
      }
    },

    refresh: async ({ requestId, body, traceparent = null }) =>
      authService.refresh({
        requestId,
        refreshToken: body.refresh_token,
        traceparent
      }),

    logout: async ({
      requestId,
      authorization,
      authorizationContext = null,
      traceparent = null
    }) =>
      authService.logout({
        requestId,
        accessToken: extractBearerToken(authorization),
        authorizationContext,
        traceparent
      }),

    changePassword: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null,
      traceparent = null
    }) =>
      authService.changePassword({
        requestId,
        accessToken: extractBearerToken(authorization),
        currentPassword: body.current_password,
        newPassword: body.new_password,
        authorizationContext,
        traceparent
      }),

    replacePlatformRoleFacts: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null,
      traceparent = null
    }) => {
      const result = await authService.replacePlatformRolesAndSyncSnapshot({
        requestId,
        accessToken: extractBearerToken(authorization),
        userId: body.user_id,
        roles: body.roles,
        authorizationContext,
        traceparent,
        enforceRoleCatalogValidation: true
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

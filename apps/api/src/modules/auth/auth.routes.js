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

  const [type, rawToken] = authorization.split(' ');
  if (type !== 'Bearer' || !rawToken) {
    throw new AuthProblemError({
      status: 401,
      title: 'Unauthorized',
      detail: '当前会话无效，请重新登录',
      errorCode: 'AUTH-401-INVALID-ACCESS'
    });
  }

  return rawToken;
};

const createAuthHandlers = (authService = createAuthService()) => ({
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

  tenantOptions: async ({ requestId, authorization }) =>
    authService.tenantOptions({
      requestId,
      accessToken: extractBearerToken(authorization)
    }),

  tenantSelect: async ({ requestId, authorization, body }) =>
    authService.selectTenant({
      requestId,
      accessToken: extractBearerToken(authorization),
      tenantId: body.tenant_id
    }),

  tenantSwitch: async ({ requestId, authorization, body }) =>
    authService.switchTenant({
      requestId,
      accessToken: extractBearerToken(authorization),
      tenantId: body.tenant_id
    }),

  refresh: async ({ requestId, body }) =>
    authService.refresh({
      requestId,
      refreshToken: body.refresh_token
    }),

  logout: async ({ requestId, authorization }) =>
    authService.logout({
      requestId,
      accessToken: extractBearerToken(authorization)
    }),

  changePassword: async ({ requestId, authorization, body }) =>
    authService.changePassword({
      requestId,
      accessToken: extractBearerToken(authorization),
      currentPassword: body.current_password,
      newPassword: body.new_password
    })
});

module.exports = {
  AuthProblemError,
  authPing,
  createAuthHandlers,
  extractBearerToken
};

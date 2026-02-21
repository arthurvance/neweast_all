const { extractBearerToken } = require('../auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_SCOPE
} = require('./system-config.constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  expectedPermissionCode = PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE
} = {}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_SYSTEM_CONFIG_SCOPE,
      expectedEntryDomain: PLATFORM_SYSTEM_CONFIG_SCOPE
    })
  );

const resolveAccessToken = ({
  authorization,
  authorizationContext = null,
  expectedPermissionCode = PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE
}) => {
  if (
    hasTrustedPreauthorizedContext({
      authorizationContext,
      expectedPermissionCode
    })
  ) {
    return null;
  }
  const normalizedAuthorization = String(authorization || '').trim();
  if (normalizedAuthorization.length > 0) {
    return extractBearerToken(normalizedAuthorization);
  }
  return extractBearerToken(authorization);
};

const createPlatformSystemConfigHandlers = (platformSystemConfigService) => {
  if (
    !platformSystemConfigService
    || typeof platformSystemConfigService.getSystemConfig !== 'function'
    || typeof platformSystemConfigService.updateSystemConfig !== 'function'
  ) {
    throw new TypeError(
      'createPlatformSystemConfigHandlers requires a platformSystemConfigService with getSystemConfig and updateSystemConfig'
    );
  }

  return {
    getSystemConfig: async ({
      requestId,
      authorization,
      params = {},
      traceparent = null,
      authorizationContext = null
    }) =>
      platformSystemConfigService.getSystemConfig({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE
        }),
        configKey: params.config_key,
        traceparent,
        authorizationContext
      }),

    updateSystemConfig: async ({
      requestId,
      authorization,
      params = {},
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformSystemConfigService.updateSystemConfig({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE
        }),
        configKey: params.config_key,
        payload: body || {},
        traceparent,
        authorizationContext
      })
  };
};

module.exports = { createPlatformSystemConfigHandlers };

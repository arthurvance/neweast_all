const { extractBearerToken } = require('../auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_SCOPE
} = require('./integration.constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  expectedPermissionCode
}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_INTEGRATION_SCOPE,
      expectedEntryDomain: PLATFORM_INTEGRATION_SCOPE
    })
  );

const resolveAccessToken = ({
  authorization,
  authorizationContext = null,
  expectedPermissionCode = PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE
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

const createPlatformIntegrationHandlers = (platformIntegrationService) => {
  if (
    !platformIntegrationService
    || typeof platformIntegrationService.listIntegrations !== 'function'
    || typeof platformIntegrationService.getIntegration !== 'function'
    || typeof platformIntegrationService.createIntegration !== 'function'
    || typeof platformIntegrationService.updateIntegration !== 'function'
    || typeof platformIntegrationService.changeIntegrationLifecycle !== 'function'
  ) {
    throw new TypeError(
      'createPlatformIntegrationHandlers requires a platformIntegrationService with listIntegrations, getIntegration, createIntegration, updateIntegration, and changeIntegrationLifecycle'
    );
  }

  return {
    listIntegrations: async ({
      requestId,
      authorization,
      query = {},
      authorizationContext = null
    }) =>
      platformIntegrationService.listIntegrations({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE
        }),
        query: query || {},
        authorizationContext
      }),

    getIntegration: async ({
      requestId,
      authorization,
      params = {},
      authorizationContext = null
    }) =>
      platformIntegrationService.getIntegration({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE
        }),
        integrationId: params.integration_id,
        authorizationContext
      }),

    createIntegration: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformIntegrationService.createIntegration({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    updateIntegration: async ({
      requestId,
      authorization,
      params = {},
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformIntegrationService.updateIntegration({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE
        }),
        integrationId: params.integration_id,
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    changeIntegrationLifecycle: async ({
      requestId,
      authorization,
      params = {},
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformIntegrationService.changeIntegrationLifecycle({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE
        }),
        integrationId: params.integration_id,
        payload: body || {},
        traceparent,
        authorizationContext
      })
  };
};

module.exports = {
  createPlatformIntegrationHandlers
};

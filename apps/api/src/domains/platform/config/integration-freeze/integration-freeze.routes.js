const { extractBearerToken } = require('../../../../modules/auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../shared-kernel/auth/route-authz');
const {
  PLATFORM_INTEGRATION_FREEZE_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_FREEZE_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_FREEZE_SCOPE
} = require('./constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  expectedPermissionCode
}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_INTEGRATION_FREEZE_SCOPE,
      expectedEntryDomain: PLATFORM_INTEGRATION_FREEZE_SCOPE
    })
  );

const resolveAccessToken = ({
  authorization,
  authorizationContext = null,
  expectedPermissionCode = PLATFORM_INTEGRATION_FREEZE_VIEW_PERMISSION_CODE
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

const createPlatformIntegrationFreezeHandlers = (
  platformIntegrationFreezeService
) => {
  if (
    !platformIntegrationFreezeService
    || typeof platformIntegrationFreezeService.getFreezeStatus !== 'function'
    || typeof platformIntegrationFreezeService.activateFreeze !== 'function'
    || typeof platformIntegrationFreezeService.releaseFreeze !== 'function'
  ) {
    throw new TypeError(
      'createPlatformIntegrationFreezeHandlers requires a platformIntegrationFreezeService with getFreezeStatus, activateFreeze, and releaseFreeze'
    );
  }

  return {
    getFreezeStatus: async ({
      requestId,
      authorization,
      authorizationContext = null
    }) =>
      platformIntegrationFreezeService.getFreezeStatus({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_FREEZE_VIEW_PERMISSION_CODE
        }),
        authorizationContext
      }),

    activateFreeze: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformIntegrationFreezeService.activateFreeze({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_FREEZE_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    releaseFreeze: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformIntegrationFreezeService.releaseFreeze({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_FREEZE_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      })
  };
};

module.exports = {
  createPlatformIntegrationFreezeHandlers
};

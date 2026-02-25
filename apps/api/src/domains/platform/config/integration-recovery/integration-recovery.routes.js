const { extractBearerToken } = require('../../../../modules/auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../shared-kernel/auth/route-authz');
const {
  PLATFORM_INTEGRATION_RECOVERY_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_RECOVERY_SCOPE
} = require('./constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  expectedPermissionCode
}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_INTEGRATION_RECOVERY_SCOPE,
      expectedEntryDomain: PLATFORM_INTEGRATION_RECOVERY_SCOPE
    })
  );

const resolveAccessToken = ({
  authorization,
  authorizationContext = null,
  expectedPermissionCode = PLATFORM_INTEGRATION_RECOVERY_VIEW_PERMISSION_CODE
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

const createPlatformIntegrationRecoveryHandlers = (
  platformIntegrationRecoveryService
) => {
  if (
    !platformIntegrationRecoveryService
    || typeof platformIntegrationRecoveryService.listRecoveryQueue !== 'function'
    || typeof platformIntegrationRecoveryService.replayRecoveryQueueItem !== 'function'
  ) {
    throw new TypeError(
      'createPlatformIntegrationRecoveryHandlers requires a platformIntegrationRecoveryService with listRecoveryQueue and replayRecoveryQueueItem'
    );
  }

  return {
    listRecoveryQueue: async ({
      requestId,
      authorization,
      params = {},
      query = {},
      authorizationContext = null
    }) =>
      platformIntegrationRecoveryService.listRecoveryQueue({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_RECOVERY_VIEW_PERMISSION_CODE
        }),
        integrationId: params.integration_id,
        query: query || {},
        authorizationContext
      }),

    replayRecoveryQueueItem: async ({
      requestId,
      authorization,
      params = {},
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformIntegrationRecoveryService.replayRecoveryQueueItem({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE
        }),
        integrationId: params.integration_id,
        recoveryId: params.recovery_id,
        payload: body || {},
        traceparent,
        authorizationContext
      })
  };
};

module.exports = {
  createPlatformIntegrationRecoveryHandlers
};

const { extractBearerToken } = require('../auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_USER_PERMISSION_CODE,
  PLATFORM_USER_SCOPE
} = require('./user.constants');

const hasTrustedPreauthorizedContext = (authorizationContext = null) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode: PLATFORM_USER_PERMISSION_CODE,
      expectedScope: PLATFORM_USER_SCOPE,
      expectedEntryDomain: PLATFORM_USER_SCOPE
    })
  );

const resolveAccessToken = ({
  authorization,
  authorizationContext = null
}) => {
  if (hasTrustedPreauthorizedContext(authorizationContext)) {
    return null;
  }
  const normalizedAuthorization = String(authorization || '').trim();
  if (normalizedAuthorization.length > 0) {
    return extractBearerToken(normalizedAuthorization);
  }
  return extractBearerToken(authorization);
};

const createPlatformUserHandlers = (platformUserService) => {
  if (
    !platformUserService
    || typeof platformUserService.createUser !== 'function'
    || typeof platformUserService.updateUserStatus !== 'function'
  ) {
    throw new TypeError(
      'createPlatformUserHandlers requires a platformUserService with createUser and updateUserStatus'
    );
  }

  return {
    createUser: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null
    }) =>
      platformUserService.createUser({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext
        }),
        payload: body || {},
        authorizationContext
      }),
    updateUserStatus: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformUserService.updateUserStatus({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      })
  };
};

module.exports = { createPlatformUserHandlers };

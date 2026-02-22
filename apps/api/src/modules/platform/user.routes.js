const { extractBearerToken } = require('../auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_USER_VIEW_PERMISSION_CODE,
  PLATFORM_USER_OPERATE_PERMISSION_CODE,
  PLATFORM_USER_SCOPE
} = require('./user.constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  expectedPermissionCode = PLATFORM_USER_OPERATE_PERMISSION_CODE
}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_USER_SCOPE,
      expectedEntryDomain: PLATFORM_USER_SCOPE
    })
  );

const resolveAccessToken = ({
  authorization,
  authorizationContext = null,
  expectedPermissionCode = PLATFORM_USER_OPERATE_PERMISSION_CODE
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

const createPlatformUserHandlers = (platformUserService) => {
  if (
    !platformUserService
    || typeof platformUserService.listUsers !== 'function'
    || typeof platformUserService.getUser !== 'function'
    || typeof platformUserService.createUser !== 'function'
    || typeof platformUserService.updateUserStatus !== 'function'
    || typeof platformUserService.softDeleteUser !== 'function'
  ) {
    throw new TypeError(
      'createPlatformUserHandlers requires a platformUserService with listUsers, getUser, createUser, updateUserStatus, and softDeleteUser'
    );
  }

  return {
    listUsers: async ({
      requestId,
      authorization,
      query,
      authorizationContext = null
    }) =>
      platformUserService.listUsers({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_USER_VIEW_PERMISSION_CODE
        }),
        query: query || {},
        authorizationContext
      }),
    getUser: async ({
      requestId,
      authorization,
      params,
      authorizationContext = null
    }) =>
      platformUserService.getUser({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_USER_VIEW_PERMISSION_CODE
        }),
        params: params || {},
        authorizationContext
      }),
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
          authorizationContext,
          expectedPermissionCode: PLATFORM_USER_OPERATE_PERMISSION_CODE
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
          authorizationContext,
          expectedPermissionCode: PLATFORM_USER_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      }),
    softDeleteUser: async ({
      requestId,
      authorization,
      params,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformUserService.softDeleteUser({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_USER_OPERATE_PERMISSION_CODE
        }),
        params: params || {},
        traceparent,
        authorizationContext
      })
  };
};

module.exports = { createPlatformUserHandlers };

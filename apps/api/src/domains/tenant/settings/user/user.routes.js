const { extractBearerToken } = require('../../../../modules/auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../shared-kernel/auth/route-authz');
const {
  TENANT_USER_VIEW_PERMISSION_CODE,
  TENANT_USER_OPERATE_PERMISSION_CODE,
  TENANT_USER_SCOPE
} = require('./constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  permissionCode = ''
} = {}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode: permissionCode,
      expectedScope: TENANT_USER_SCOPE,
      expectedEntryDomain: TENANT_USER_SCOPE
    })
  );

const resolveAccessToken = ({
  authorization,
  authorizationContext = null,
  permissionCode = ''
}) => {
  if (
    hasTrustedPreauthorizedContext({
      authorizationContext,
      permissionCode
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

const createTenantUserHandlers = (tenantUserService) => {
  if (
    !tenantUserService
    || typeof tenantUserService.listUsers !== 'function'
    || typeof tenantUserService.createUser !== 'function'
    || typeof tenantUserService.updateUserStatus !== 'function'
    || typeof tenantUserService.getUserDetail !== 'function'
    || typeof tenantUserService.updateUserProfile !== 'function'
    || typeof tenantUserService.getUserRoles !== 'function'
    || typeof tenantUserService.replaceUserRoles !== 'function'
  ) {
    throw new TypeError(
      'createTenantUserHandlers requires a tenantUserService with listUsers, createUser, updateUserStatus, getUserDetail, updateUserProfile, getUserRoles and replaceUserRoles'
    );
  }

  return {
    listUsers: async ({
      requestId,
      authorization,
      query = {},
      authorizationContext = null
    }) =>
      tenantUserService.listUsers({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_USER_VIEW_PERMISSION_CODE
        }),
        query: query || {},
        authorizationContext
      }),
    createUser: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null
    }) =>
      tenantUserService.createUser({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_USER_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        authorizationContext
      }),
    updateUserStatus: async ({
      requestId,
      authorization,
      params,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantUserService.updateUserStatus({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_USER_OPERATE_PERMISSION_CODE
        }),
        params: params || {},
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    getUserDetail: async ({
      requestId,
      authorization,
      params,
      authorizationContext = null
    }) =>
      tenantUserService.getUserDetail({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_USER_VIEW_PERMISSION_CODE
        }),
        params: params || {},
        authorizationContext
      }),

    updateUserProfile: async ({
      requestId,
      authorization,
      params,
      body,
      authorizationContext = null
    }) =>
      tenantUserService.updateUserProfile({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_USER_OPERATE_PERMISSION_CODE
        }),
        params: params || {},
        payload: body || {},
        authorizationContext
      }),

    getUserRoles: async ({
      requestId,
      authorization,
      params,
      authorizationContext = null
    }) =>
      tenantUserService.getUserRoles({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_USER_VIEW_PERMISSION_CODE
        }),
        params: params || {},
        authorizationContext
      }),

    replaceUserRoles: async ({
      requestId,
      authorization,
      params,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantUserService.replaceUserRoles({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_USER_OPERATE_PERMISSION_CODE
        }),
        params: params || {},
        payload: body || {},
        traceparent,
        authorizationContext
      })
  };
};

module.exports = { createTenantUserHandlers };

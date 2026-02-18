const { extractBearerToken } = require('../auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_ROLE_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_OPERATE_PERMISSION_CODE,
  PLATFORM_ROLE_SCOPE
} = require('./role.constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  expectedPermissionCode
}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_ROLE_SCOPE,
      expectedEntryDomain: PLATFORM_ROLE_SCOPE
    })
  );

const resolveAccessToken = ({
  authorization,
  authorizationContext = null,
  expectedPermissionCode
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

const createPlatformRoleHandlers = (platformRoleService) => {
  if (
    !platformRoleService
    || typeof platformRoleService.createRole !== 'function'
    || typeof platformRoleService.updateRole !== 'function'
    || typeof platformRoleService.deleteRole !== 'function'
    || typeof platformRoleService.listRoles !== 'function'
  ) {
    throw new TypeError(
      'createPlatformRoleHandlers requires a platformRoleService with createRole, updateRole, deleteRole, and listRoles'
    );
  }

  return {
    listRoles: async ({
      requestId,
      authorization,
      authorizationContext = null
    }) =>
      platformRoleService.listRoles({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_ROLE_VIEW_PERMISSION_CODE
        }),
        authorizationContext
      }),

    createRole: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null
    }) =>
      platformRoleService.createRole({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_ROLE_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        authorizationContext
      }),

    updateRole: async ({
      requestId,
      authorization,
      params = {},
      body,
      authorizationContext = null
    }) =>
      platformRoleService.updateRole({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_ROLE_OPERATE_PERMISSION_CODE
        }),
        roleId: params.role_id,
        payload: body || {},
        authorizationContext
      }),

    deleteRole: async ({
      requestId,
      authorization,
      params = {},
      authorizationContext = null
    }) =>
      platformRoleService.deleteRole({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_ROLE_OPERATE_PERMISSION_CODE
        }),
        roleId: params.role_id,
        authorizationContext
      })
  };
};

module.exports = { createPlatformRoleHandlers };

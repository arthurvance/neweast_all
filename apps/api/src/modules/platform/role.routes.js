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
    || typeof platformRoleService.getRolePermissions !== 'function'
    || typeof platformRoleService.replaceRolePermissions !== 'function'
  ) {
    throw new TypeError(
      'createPlatformRoleHandlers requires a platformRoleService with createRole, updateRole, deleteRole, listRoles, getRolePermissions, and replaceRolePermissions'
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
      traceparent = null,
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
        traceparent,
        authorizationContext
      }),

    updateRole: async ({
      requestId,
      authorization,
      params = {},
      body,
      traceparent = null,
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
        traceparent,
        authorizationContext
      }),

    deleteRole: async ({
      requestId,
      authorization,
      params = {},
      traceparent = null,
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
        traceparent,
        authorizationContext
      }),

    getRolePermissions: async ({
      requestId,
      authorization,
      params = {},
      authorizationContext = null
    }) =>
      platformRoleService.getRolePermissions({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_ROLE_VIEW_PERMISSION_CODE
        }),
        roleId: params.role_id,
        authorizationContext
      }),

    replaceRolePermissions: async ({
      requestId,
      authorization,
      params = {},
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformRoleService.replaceRolePermissions({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_ROLE_OPERATE_PERMISSION_CODE
        }),
        roleId: params.role_id,
        payload: body || {},
        traceparent,
        authorizationContext
      })
  };
};

module.exports = { createPlatformRoleHandlers };

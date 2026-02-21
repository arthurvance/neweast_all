const { extractBearerToken } = require('../auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  TENANT_ROLE_VIEW_PERMISSION_CODE,
  TENANT_ROLE_OPERATE_PERMISSION_CODE,
  TENANT_ROLE_SCOPE
} = require('./role.constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  permissionCode = ''
} = {}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode: permissionCode,
      expectedScope: TENANT_ROLE_SCOPE,
      expectedEntryDomain: TENANT_ROLE_SCOPE
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

const createTenantRoleHandlers = (tenantRoleService) => {
  if (
    !tenantRoleService
    || typeof tenantRoleService.listRoles !== 'function'
    || typeof tenantRoleService.createRole !== 'function'
    || typeof tenantRoleService.updateRole !== 'function'
    || typeof tenantRoleService.deleteRole !== 'function'
    || typeof tenantRoleService.getRolePermissions !== 'function'
    || typeof tenantRoleService.replaceRolePermissions !== 'function'
  ) {
    throw new TypeError(
      'createTenantRoleHandlers requires a tenantRoleService with listRoles, createRole, updateRole, deleteRole, getRolePermissions and replaceRolePermissions'
    );
  }

  return {
    listRoles: async ({
      requestId,
      authorization,
      authorizationContext = null
    }) =>
      tenantRoleService.listRoles({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_ROLE_VIEW_PERMISSION_CODE
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
      tenantRoleService.createRole({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_ROLE_OPERATE_PERMISSION_CODE
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
      tenantRoleService.updateRole({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_ROLE_OPERATE_PERMISSION_CODE
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
      tenantRoleService.deleteRole({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_ROLE_OPERATE_PERMISSION_CODE
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
      tenantRoleService.getRolePermissions({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_ROLE_VIEW_PERMISSION_CODE
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
      tenantRoleService.replaceRolePermissions({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_ROLE_OPERATE_PERMISSION_CODE
        }),
        roleId: params.role_id,
        payload: body || {},
        traceparent,
        authorizationContext
      })
  };
};

module.exports = { createTenantRoleHandlers };

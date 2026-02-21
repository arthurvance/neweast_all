const { extractBearerToken } = require('../auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  TENANT_MEMBER_VIEW_PERMISSION_CODE,
  TENANT_MEMBER_OPERATE_PERMISSION_CODE,
  TENANT_MEMBER_SCOPE
} = require('./member.constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  permissionCode = ''
} = {}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode: permissionCode,
      expectedScope: TENANT_MEMBER_SCOPE,
      expectedEntryDomain: TENANT_MEMBER_SCOPE
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

const createTenantMemberHandlers = (tenantMemberService) => {
  if (
    !tenantMemberService
    || typeof tenantMemberService.listMembers !== 'function'
    || typeof tenantMemberService.createMember !== 'function'
    || typeof tenantMemberService.updateMemberStatus !== 'function'
    || typeof tenantMemberService.getMemberDetail !== 'function'
    || typeof tenantMemberService.updateMemberProfile !== 'function'
    || typeof tenantMemberService.getMemberRoles !== 'function'
    || typeof tenantMemberService.replaceMemberRoles !== 'function'
  ) {
    throw new TypeError(
      'createTenantMemberHandlers requires a tenantMemberService with listMembers, createMember, updateMemberStatus, getMemberDetail, updateMemberProfile, getMemberRoles and replaceMemberRoles'
    );
  }

  return {
    listMembers: async ({
      requestId,
      authorization,
      query = {},
      authorizationContext = null
    }) =>
      tenantMemberService.listMembers({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_MEMBER_VIEW_PERMISSION_CODE
        }),
        query: query || {},
        authorizationContext
      }),
    createMember: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null
    }) =>
      tenantMemberService.createMember({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_MEMBER_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        authorizationContext
      }),
    updateMemberStatus: async ({
      requestId,
      authorization,
      params,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantMemberService.updateMemberStatus({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_MEMBER_OPERATE_PERMISSION_CODE
        }),
        params: params || {},
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    getMemberDetail: async ({
      requestId,
      authorization,
      params,
      authorizationContext = null
    }) =>
      tenantMemberService.getMemberDetail({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_MEMBER_VIEW_PERMISSION_CODE
        }),
        params: params || {},
        authorizationContext
      }),

    updateMemberProfile: async ({
      requestId,
      authorization,
      params,
      body,
      authorizationContext = null
    }) =>
      tenantMemberService.updateMemberProfile({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_MEMBER_OPERATE_PERMISSION_CODE
        }),
        params: params || {},
        payload: body || {},
        authorizationContext
      }),

    getMemberRoles: async ({
      requestId,
      authorization,
      params,
      authorizationContext = null
    }) =>
      tenantMemberService.getMemberRoles({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_MEMBER_VIEW_PERMISSION_CODE
        }),
        params: params || {},
        authorizationContext
      }),

    replaceMemberRoles: async ({
      requestId,
      authorization,
      params,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantMemberService.replaceMemberRoles({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_MEMBER_OPERATE_PERMISSION_CODE
        }),
        params: params || {},
        payload: body || {},
        traceparent,
        authorizationContext
      })
  };
};

module.exports = { createTenantMemberHandlers };

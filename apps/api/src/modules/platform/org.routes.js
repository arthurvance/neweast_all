const { extractBearerToken } = require('../auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_ORG_VIEW_PERMISSION_CODE,
  PLATFORM_ORG_OPERATE_PERMISSION_CODE,
  PLATFORM_ORG_SCOPE
} = require('./org.constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  expectedPermissionCode = PLATFORM_ORG_OPERATE_PERMISSION_CODE
} = {}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_ORG_SCOPE,
      expectedEntryDomain: PLATFORM_ORG_SCOPE
    })
  );

const resolveAccessToken = ({
  authorization,
  authorizationContext = null,
  expectedPermissionCode = PLATFORM_ORG_OPERATE_PERMISSION_CODE
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

const createPlatformOrgHandlers = (platformOrgService) => {
  if (
    !platformOrgService
    || typeof platformOrgService.listOrgs !== 'function'
    || typeof platformOrgService.createOrg !== 'function'
    || typeof platformOrgService.updateOrgStatus !== 'function'
    || typeof platformOrgService.ownerTransfer !== 'function'
  ) {
    throw new TypeError(
      'createPlatformOrgHandlers requires a platformOrgService with listOrgs, createOrg, updateOrgStatus and ownerTransfer'
    );
  }

  return {
    listOrgs: async ({
      requestId,
      authorization,
      query,
      authorizationContext = null
    }) =>
      platformOrgService.listOrgs({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_ORG_VIEW_PERMISSION_CODE
        }),
        query: query || {},
        authorizationContext
      }),
    createOrg: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformOrgService.createOrg({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_ORG_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      }),
    updateOrgStatus: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformOrgService.updateOrgStatus({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_ORG_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      }),
    ownerTransfer: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformOrgService.ownerTransfer({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_ORG_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      })
  };
};

module.exports = { createPlatformOrgHandlers };

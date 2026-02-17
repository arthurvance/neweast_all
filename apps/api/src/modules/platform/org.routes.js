const { extractBearerToken } = require('../auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_ORG_CREATE_PERMISSION_CODE,
  PLATFORM_ORG_SCOPE
} = require('./org.constants');

const hasTrustedPreauthorizedContext = (authorizationContext = null) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode: PLATFORM_ORG_CREATE_PERMISSION_CODE,
      expectedScope: PLATFORM_ORG_SCOPE,
      expectedEntryDomain: PLATFORM_ORG_SCOPE
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

const createPlatformOrgHandlers = (platformOrgService) => {
  if (!platformOrgService || typeof platformOrgService.createOrg !== 'function') {
    throw new TypeError(
      'createPlatformOrgHandlers requires a platformOrgService with createOrg'
    );
  }

  return {
    createOrg: async ({
      requestId,
      authorization,
      body,
      authorizationContext = null
    }) =>
      platformOrgService.createOrg({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext
        }),
        payload: body || {},
        authorizationContext
      })
  };
};

module.exports = { createPlatformOrgHandlers };

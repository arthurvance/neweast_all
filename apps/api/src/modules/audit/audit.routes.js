const { extractBearerToken } = require('../auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_AUDIT_VIEW_PERMISSION_CODE,
  TENANT_AUDIT_VIEW_PERMISSION_CODE,
  PLATFORM_AUDIT_SCOPE,
  TENANT_AUDIT_SCOPE
} = require('./audit.constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  permissionCode = '',
  scope = '',
  entryDomain = ''
} = {}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode: permissionCode,
      expectedScope: scope,
      expectedEntryDomain: entryDomain
    })
  );

const resolveAccessToken = ({
  authorization,
  authorizationContext = null,
  permissionCode = '',
  scope = '',
  entryDomain = ''
}) => {
  if (
    hasTrustedPreauthorizedContext({
      authorizationContext,
      permissionCode,
      scope,
      entryDomain
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

const createAuditHandlers = (auditService) => {
  if (
    !auditService
    || typeof auditService.listPlatformAuditEvents !== 'function'
    || typeof auditService.listTenantAuditEvents !== 'function'
  ) {
    throw new TypeError(
      'createAuditHandlers requires an auditService with listPlatformAuditEvents and listTenantAuditEvents'
    );
  }

  return {
    listPlatformAuditEvents: async ({
      requestId,
      authorization,
      query = {},
      authorizationContext = null
    }) =>
      auditService.listPlatformAuditEvents({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: PLATFORM_AUDIT_VIEW_PERMISSION_CODE,
          scope: PLATFORM_AUDIT_SCOPE,
          entryDomain: PLATFORM_AUDIT_SCOPE
        }),
        query: query || {},
        authorizationContext
      }),

    listTenantAuditEvents: async ({
      requestId,
      authorization,
      query = {},
      authorizationContext = null
    }) =>
      auditService.listTenantAuditEvents({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_AUDIT_VIEW_PERMISSION_CODE,
          scope: TENANT_AUDIT_SCOPE,
          entryDomain: TENANT_AUDIT_SCOPE
        }),
        query: query || {},
        authorizationContext
      })
  };
};

module.exports = { createAuditHandlers };

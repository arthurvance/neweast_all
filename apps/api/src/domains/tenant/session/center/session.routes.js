const { extractBearerToken } = require('../../../../modules/auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../shared-kernel/auth/route-authz');
const {
  TENANT_SESSION_VIEW_PERMISSION_CODE,
  TENANT_SESSION_OPERATE_PERMISSION_CODE,
  TENANT_SESSION_SCOPE
} = require('./constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  permissionCode = ''
} = {}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode: permissionCode,
      expectedScope: TENANT_SESSION_SCOPE,
      expectedEntryDomain: TENANT_SESSION_SCOPE
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

const createTenantSessionHandlers = (tenantSessionService) => {
  if (
    !tenantSessionService
    || typeof tenantSessionService.ingestConversation !== 'function'
    || typeof tenantSessionService.ingestHistoryMessage !== 'function'
    || typeof tenantSessionService.listChats !== 'function'
    || typeof tenantSessionService.listChatMessages !== 'function'
    || typeof tenantSessionService.listAccountOptions !== 'function'
    || typeof tenantSessionService.createOutboundMessage !== 'function'
    || typeof tenantSessionService.pullOutboundMessages !== 'function'
    || typeof tenantSessionService.updateOutboundMessageStatus !== 'function'
  ) {
    throw new TypeError(
      'createTenantSessionHandlers requires a tenantSessionService with ingestConversation, ingestHistoryMessage, listChats, listChatMessages, listAccountOptions, createOutboundMessage, pullOutboundMessages and updateOutboundMessageStatus'
    );
  }

  return {
    ingestConversation: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantSessionService.ingestConversation({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_SESSION_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    ingestHistoryMessage: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantSessionService.ingestHistoryMessage({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_SESSION_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    listChats: async ({
      requestId,
      authorization,
      query = {},
      authorizationContext = null
    }) =>
      tenantSessionService.listChats({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_SESSION_VIEW_PERMISSION_CODE
        }),
        query: query || {},
        authorizationContext
      }),

    listChatMessages: async ({
      requestId,
      authorization,
      params = {},
      query = {},
      authorizationContext = null
    }) =>
      tenantSessionService.listChatMessages({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_SESSION_VIEW_PERMISSION_CODE
        }),
        params: params || {},
        query: query || {},
        authorizationContext
      }),

    listAccountOptions: async ({
      requestId,
      authorization,
      query = {},
      authorizationContext = null
    }) =>
      tenantSessionService.listAccountOptions({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_SESSION_VIEW_PERMISSION_CODE
        }),
        query: query || {},
        authorizationContext
      }),

    createOutboundMessage: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantSessionService.createOutboundMessage({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_SESSION_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    pullOutboundMessages: async ({
      requestId,
      authorization,
      query = {},
      authorizationContext = null
    }) =>
      tenantSessionService.pullOutboundMessages({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_SESSION_OPERATE_PERMISSION_CODE
        }),
        query: query || {},
        authorizationContext
      }),

    updateOutboundMessageStatus: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantSessionService.updateOutboundMessageStatus({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_SESSION_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      })
  };
};

module.exports = {
  createTenantSessionHandlers
};

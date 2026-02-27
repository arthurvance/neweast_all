const { extractBearerToken } = require('../../../../modules/auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../shared-kernel/auth/route-authz');
const {
  TENANT_ACCOUNT_VIEW_PERMISSION_CODE,
  TENANT_ACCOUNT_OPERATE_PERMISSION_CODE,
  TENANT_ACCOUNT_SCOPE
} = require('./constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  permissionCode = ''
} = {}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode: permissionCode,
      expectedScope: TENANT_ACCOUNT_SCOPE,
      expectedEntryDomain: TENANT_ACCOUNT_SCOPE
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

const createTenantAccountHandlers = (tenantAccountService) => {
  if (
    !tenantAccountService
    || typeof tenantAccountService.listAccounts !== 'function'
    || typeof tenantAccountService.createAccount !== 'function'
    || typeof tenantAccountService.getAccountDetail !== 'function'
    || typeof tenantAccountService.updateAccount !== 'function'
    || typeof tenantAccountService.updateAccountStatus !== 'function'
    || typeof tenantAccountService.listAccountOperationLogs !== 'function'
  ) {
    throw new TypeError(
      'createTenantAccountHandlers requires a tenantAccountService with listAccounts, createAccount, getAccountDetail, updateAccount, updateAccountStatus and listAccountOperationLogs'
    );
  }

  return {
    listAccounts: async ({
      requestId,
      authorization,
      query = {},
      authorizationContext = null
    }) =>
      tenantAccountService.listAccounts({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_ACCOUNT_VIEW_PERMISSION_CODE
        }),
        query: query || {},
        authorizationContext
      }),

    createAccount: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantAccountService.createAccount({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_ACCOUNT_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    getAccountDetail: async ({
      requestId,
      authorization,
      params,
      authorizationContext = null
    }) =>
      tenantAccountService.getAccountDetail({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_ACCOUNT_VIEW_PERMISSION_CODE
        }),
        params: params || {},
        authorizationContext
      }),

    updateAccount: async ({
      requestId,
      authorization,
      params,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantAccountService.updateAccount({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_ACCOUNT_OPERATE_PERMISSION_CODE
        }),
        params: params || {},
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    updateAccountStatus: async ({
      requestId,
      authorization,
      params,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantAccountService.updateAccountStatus({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_ACCOUNT_OPERATE_PERMISSION_CODE
        }),
        params: params || {},
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    listAccountOperationLogs: async ({
      requestId,
      authorization,
      params,
      query = {},
      authorizationContext = null
    }) =>
      tenantAccountService.listAccountOperationLogs({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_ACCOUNT_VIEW_PERMISSION_CODE
        }),
        params: params || {},
        query: query || {},
        authorizationContext
      })
  };
};

module.exports = { createTenantAccountHandlers };

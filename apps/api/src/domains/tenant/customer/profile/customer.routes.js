const { extractBearerToken } = require('../../../../modules/auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../shared-kernel/auth/route-authz');
const {
  TENANT_CUSTOMER_VIEW_PERMISSION_CODE,
  TENANT_CUSTOMER_OPERATE_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE
} = require('./constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  permissionCode = ''
} = {}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode: permissionCode,
      expectedScope: TENANT_CUSTOMER_SCOPE,
      expectedEntryDomain: TENANT_CUSTOMER_SCOPE
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

const createTenantCustomerHandlers = (tenantCustomerService) => {
  if (
    !tenantCustomerService
    || typeof tenantCustomerService.listCustomers !== 'function'
    || typeof tenantCustomerService.createCustomer !== 'function'
    || typeof tenantCustomerService.getCustomerDetail !== 'function'
    || typeof tenantCustomerService.updateCustomer !== 'function'
    || typeof tenantCustomerService.updateCustomerByAccountNickname !== 'function'
    || typeof tenantCustomerService.listCustomerOperationLogs !== 'function'
  ) {
    throw new TypeError(
      'createTenantCustomerHandlers requires a tenantCustomerService with listCustomers, createCustomer, getCustomerDetail, updateCustomer, updateCustomerByAccountNickname and listCustomerOperationLogs'
    );
  }

  return {
    listCustomers: async ({
      requestId,
      authorization,
      query = {},
      authorizationContext = null
    }) =>
      tenantCustomerService.listCustomers({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_CUSTOMER_VIEW_PERMISSION_CODE
        }),
        query: query || {},
        authorizationContext
      }),

    createCustomer: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantCustomerService.createCustomer({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_CUSTOMER_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    getCustomerDetail: async ({
      requestId,
      authorization,
      params,
      authorizationContext = null
    }) =>
      tenantCustomerService.getCustomerDetail({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_CUSTOMER_VIEW_PERMISSION_CODE
        }),
        params: params || {},
        authorizationContext
      }),

    updateCustomer: async ({
      requestId,
      authorization,
      params,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantCustomerService.updateCustomer({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_CUSTOMER_OPERATE_PERMISSION_CODE
        }),
        params: params || {},
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    updateCustomerByAccountNickname: async ({
      requestId,
      authorization,
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      tenantCustomerService.updateCustomerByAccountNickname({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_CUSTOMER_OPERATE_PERMISSION_CODE
        }),
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    listCustomerOperationLogs: async ({
      requestId,
      authorization,
      params,
      query = {},
      authorizationContext = null
    }) =>
      tenantCustomerService.listCustomerOperationLogs({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          permissionCode: TENANT_CUSTOMER_VIEW_PERMISSION_CODE
        }),
        params: params || {},
        query: query || {},
        authorizationContext
      })
  };
};

module.exports = { createTenantCustomerHandlers };

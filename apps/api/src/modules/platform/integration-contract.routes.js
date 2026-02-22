const { extractBearerToken } = require('../auth/auth.routes');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_INTEGRATION_CONTRACT_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_CONTRACT_SCOPE
} = require('./integration-contract.constants');

const hasTrustedPreauthorizedContext = ({
  authorizationContext = null,
  expectedPermissionCode
}) =>
  Boolean(
    resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_INTEGRATION_CONTRACT_SCOPE,
      expectedEntryDomain: PLATFORM_INTEGRATION_CONTRACT_SCOPE
    })
  );

const resolveAccessToken = ({
  authorization,
  authorizationContext = null,
  expectedPermissionCode = PLATFORM_INTEGRATION_CONTRACT_VIEW_PERMISSION_CODE
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

const createPlatformIntegrationContractHandlers = (
  platformIntegrationContractService
) => {
  if (
    !platformIntegrationContractService
    || typeof platformIntegrationContractService.listContracts !== 'function'
    || typeof platformIntegrationContractService.createContract !== 'function'
    || typeof platformIntegrationContractService.evaluateCompatibility !== 'function'
    || typeof platformIntegrationContractService.activateContract !== 'function'
  ) {
    throw new TypeError(
      'createPlatformIntegrationContractHandlers requires a platformIntegrationContractService with listContracts, createContract, evaluateCompatibility, and activateContract'
    );
  }

  return {
    listContracts: async ({
      requestId,
      authorization,
      params = {},
      query = {},
      authorizationContext = null
    }) =>
      platformIntegrationContractService.listContracts({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_CONTRACT_VIEW_PERMISSION_CODE
        }),
        integrationId: params.integration_id,
        query: query || {},
        authorizationContext
      }),

    createContract: async ({
      requestId,
      authorization,
      params = {},
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformIntegrationContractService.createContract({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE
        }),
        integrationId: params.integration_id,
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    evaluateCompatibility: async ({
      requestId,
      authorization,
      params = {},
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformIntegrationContractService.evaluateCompatibility({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE
        }),
        integrationId: params.integration_id,
        payload: body || {},
        traceparent,
        authorizationContext
      }),

    activateContract: async ({
      requestId,
      authorization,
      params = {},
      body,
      traceparent = null,
      authorizationContext = null
    }) =>
      platformIntegrationContractService.activateContract({
        requestId,
        accessToken: resolveAccessToken({
          authorization,
          authorizationContext,
          expectedPermissionCode: PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE
        }),
        integrationId: params.integration_id,
        contractVersion: params.contract_version,
        payload: body || {},
        traceparent,
        authorizationContext
      })
  };
};

module.exports = {
  createPlatformIntegrationContractHandlers
};

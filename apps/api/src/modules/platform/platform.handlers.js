const createPlatformRouteHandlers = ({
  platformOrg,
  platformRole,
  platformUser,
  platformSystemConfig,
  platformIntegration,
  platformIntegrationContract,
  platformIntegrationRecovery,
  platformIntegrationFreeze
}) => ({
  platformListOrgs: async (
    requestId,
    authorization,
    query,
    authorizationContext
  ) =>
    platformOrg.listOrgs({
      requestId,
      authorization,
      query: query || {},
      authorizationContext
    }),

  platformCreateOrg: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformOrg.createOrg({
      requestId,
      authorization,
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformUpdateOrgStatus: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformOrg.updateOrgStatus({
      requestId,
      authorization,
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformOwnerTransfer: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformOrg.ownerTransfer({
      requestId,
      authorization,
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformListRoles: async (
    requestId,
    authorization,
    authorizationContext
  ) =>
    platformRole.listRoles({
      requestId,
      authorization,
      authorizationContext
    }),

  platformCreateRole: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformRole.createRole({
      requestId,
      authorization,
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformUpdateRole: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformRole.updateRole({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformDeleteRole: async (
    requestId,
    authorization,
    params,
    authorizationContext,
    traceparent = null
  ) =>
    platformRole.deleteRole({
      requestId,
      authorization,
      params: params || {},
      traceparent,
      authorizationContext
    }),

  platformGetRolePermissions: async (
    requestId,
    authorization,
    params,
    authorizationContext
  ) =>
    platformRole.getRolePermissions({
      requestId,
      authorization,
      params: params || {},
      authorizationContext
    }),

  platformReplaceRolePermissions: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformRole.replaceRolePermissions({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformListUsers: async (
    requestId,
    authorization,
    query,
    authorizationContext
  ) =>
    platformUser.listUsers({
      requestId,
      authorization,
      query: query || {},
      authorizationContext
    }),

  platformGetUser: async (
    requestId,
    authorization,
    params,
    authorizationContext
  ) =>
    platformUser.getUser({
      requestId,
      authorization,
      params: params || {},
      authorizationContext
    }),

  platformCreateUser: async (
    requestId,
    authorization,
    body,
    authorizationContext
  ) =>
    platformUser.createUser({
      requestId,
      authorization,
      body: body || {},
      authorizationContext
    }),

  platformUpdateUser: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformUser.updateUser({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformSoftDeleteUser: async (
    requestId,
    authorization,
    params,
    authorizationContext,
    traceparent = null
  ) =>
    platformUser.softDeleteUser({
      requestId,
      authorization,
      params: params || {},
      traceparent,
      authorizationContext
    }),

  platformUpdateUserStatus: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformUser.updateUserStatus({
      requestId,
      authorization,
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformGetSystemConfig: async (
    requestId,
    authorization,
    params,
    authorizationContext,
    traceparent = null
  ) =>
    platformSystemConfig.getSystemConfig({
      requestId,
      authorization,
      params: params || {},
      traceparent,
      authorizationContext
    }),

  platformUpdateSystemConfig: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformSystemConfig.updateSystemConfig({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformListIntegrations: async (
    requestId,
    authorization,
    query,
    authorizationContext
  ) =>
    platformIntegration.listIntegrations({
      requestId,
      authorization,
      query: query || {},
      authorizationContext
    }),

  platformGetIntegration: async (
    requestId,
    authorization,
    params,
    authorizationContext
  ) =>
    platformIntegration.getIntegration({
      requestId,
      authorization,
      params: params || {},
      authorizationContext
    }),

  platformCreateIntegration: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformIntegration.createIntegration({
      requestId,
      authorization,
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformUpdateIntegration: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformIntegration.updateIntegration({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformChangeIntegrationLifecycle: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformIntegration.changeIntegrationLifecycle({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformListIntegrationContracts: async (
    requestId,
    authorization,
    params,
    query,
    authorizationContext
  ) =>
    platformIntegrationContract.listContracts({
      requestId,
      authorization,
      params: params || {},
      query: query || {},
      authorizationContext
    }),

  platformCreateIntegrationContract: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformIntegrationContract.createContract({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformEvaluateIntegrationContractCompatibility: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformIntegrationContract.evaluateCompatibility({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformCheckIntegrationContractConsistency: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformIntegrationContract.checkConsistency({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformActivateIntegrationContract: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformIntegrationContract.activateContract({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformListIntegrationRecoveryQueue: async (
    requestId,
    authorization,
    params,
    query,
    authorizationContext
  ) =>
    platformIntegrationRecovery.listRecoveryQueue({
      requestId,
      authorization,
      params: params || {},
      query: query || {},
      authorizationContext
    }),

  platformReplayIntegrationRecoveryQueueItem: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformIntegrationRecovery.replayRecoveryQueueItem({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformGetIntegrationFreezeStatus: async (
    requestId,
    authorization,
    authorizationContext
  ) =>
    platformIntegrationFreeze.getFreezeStatus({
      requestId,
      authorization,
      authorizationContext
    }),

  platformActivateIntegrationFreeze: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformIntegrationFreeze.activateFreeze({
      requestId,
      authorization,
      body: body || {},
      traceparent,
      authorizationContext
    }),

  platformReleaseIntegrationFreeze: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    platformIntegrationFreeze.releaseFreeze({
      requestId,
      authorization,
      body: body || {},
      traceparent,
      authorizationContext
    })
});

module.exports = {
  createPlatformRouteHandlers
};

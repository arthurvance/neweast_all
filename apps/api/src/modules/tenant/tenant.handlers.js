const createTenantRouteHandlers = ({
  tenantMember,
  tenantRole
}) => ({
  tenantListMembers: async (
    requestId,
    authorization,
    query,
    authorizationContext
  ) =>
    tenantMember.listMembers({
      requestId,
      authorization,
      query: query || {},
      authorizationContext
    }),

  tenantCreateMember: async (
    requestId,
    authorization,
    body,
    authorizationContext
  ) =>
    tenantMember.createMember({
      requestId,
      authorization,
      body: body || {},
      authorizationContext
    }),

  tenantUpdateMemberStatus: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantMember.updateMemberStatus({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantGetMemberDetail: async (
    requestId,
    authorization,
    params,
    authorizationContext
  ) =>
    tenantMember.getMemberDetail({
      requestId,
      authorization,
      params: params || {},
      authorizationContext
    }),

  tenantUpdateMemberProfile: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext
  ) =>
    tenantMember.updateMemberProfile({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      authorizationContext
    }),

  tenantGetMemberRoles: async (
    requestId,
    authorization,
    params,
    authorizationContext
  ) =>
    tenantMember.getMemberRoles({
      requestId,
      authorization,
      params: params || {},
      authorizationContext
    }),

  tenantReplaceMemberRoles: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantMember.replaceMemberRoles({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantListRoles: async (
    requestId,
    authorization,
    authorizationContext
  ) =>
    tenantRole.listRoles({
      requestId,
      authorization,
      authorizationContext
    }),

  tenantCreateRole: async (
    requestId,
    authorization,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantRole.createRole({
      requestId,
      authorization,
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantUpdateRole: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantRole.updateRole({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    }),

  tenantDeleteRole: async (
    requestId,
    authorization,
    params,
    authorizationContext,
    traceparent = null
  ) =>
    tenantRole.deleteRole({
      requestId,
      authorization,
      params: params || {},
      traceparent,
      authorizationContext
    }),

  tenantGetRolePermissions: async (
    requestId,
    authorization,
    params,
    authorizationContext
  ) =>
    tenantRole.getRolePermissions({
      requestId,
      authorization,
      params: params || {},
      authorizationContext
    }),

  tenantReplaceRolePermissions: async (
    requestId,
    authorization,
    params,
    body,
    authorizationContext,
    traceparent = null
  ) =>
    tenantRole.replaceRolePermissions({
      requestId,
      authorization,
      params: params || {},
      body: body || {},
      traceparent,
      authorizationContext
    })
});

module.exports = {
  createTenantRouteHandlers
};

const createAuditRouteHandlers = ({ audit }) => ({
  platformListAuditEvents: async (
    requestId,
    authorization,
    query,
    authorizationContext
  ) =>
    audit.listPlatformAuditEvents({
      requestId,
      authorization,
      query: query || {},
      authorizationContext
    }),

  tenantListAuditEvents: async (
    requestId,
    authorization,
    query,
    authorizationContext
  ) =>
    audit.listTenantAuditEvents({
      requestId,
      authorization,
      query: query || {},
      authorizationContext
    })
});

module.exports = {
  createAuditRouteHandlers
};

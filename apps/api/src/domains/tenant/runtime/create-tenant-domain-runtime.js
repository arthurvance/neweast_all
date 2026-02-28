const { createTenantRuntime } = require('./tenant.runtime');
const { createTenantRouteHandlers } = require('./tenant.handlers');

const createTenantDomainRuntime = ({ authService, options = {} } = {}) => {
  const runtime = createTenantRuntime({
    authService,
    options
  });

  return {
    ...runtime,
    handlers: createTenantRouteHandlers({
      tenantUser: runtime.tenantUser,
      tenantRole: runtime.tenantRole,
      tenantAccount: runtime.tenantAccount,
      tenantCustomer: runtime.tenantCustomer,
      tenantSession: runtime.tenantSession
    })
  };
};

module.exports = {
  createTenantDomainRuntime
};

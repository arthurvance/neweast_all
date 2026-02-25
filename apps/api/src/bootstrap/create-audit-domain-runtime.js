const { createAuditRuntime } = require('../modules/audit/audit.runtime');
const { createAuditRouteHandlers } = require('../modules/audit/audit.handlers');

const createAuditDomainRuntime = ({
  authService,
  options = {},
  createDependencyUnavailableError
} = {}) => {
  const runtime = createAuditRuntime({
    authService,
    options,
    createDependencyUnavailableError
  });

  return {
    ...runtime,
    handlers: createAuditRouteHandlers({
      audit: runtime.audit
    })
  };
};

module.exports = {
  createAuditDomainRuntime
};

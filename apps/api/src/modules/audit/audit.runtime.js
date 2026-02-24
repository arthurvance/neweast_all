const { createAuditHandlers } = require('./audit.routes');
const { createAuditService } = require('./audit.service');

const createAuditRuntime = ({
  authService,
  options = {},
  createDependencyUnavailableError
} = {}) => {
  const fallbackAuditService = {
    listPlatformAuditEvents: async () => {
      throw createDependencyUnavailableError();
    },
    listTenantAuditEvents: async () => {
      throw createDependencyUnavailableError();
    },
    _internals: {
      authService
    }
  };

  const auditService =
    options.auditService
    || (
      typeof authService?.listAuditEvents === 'function'
        ? createAuditService({
          authService
        })
        : fallbackAuditService
    );

  return {
    auditService,
    audit: createAuditHandlers(auditService)
  };
};

module.exports = {
  createAuditRuntime
};

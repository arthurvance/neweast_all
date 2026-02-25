const {
  createTenantUserHandlers
} = require('../settings/user/user.routes');
const {
  createTenantUserService
} = require('../settings/user/service');
const {
  createTenantRoleHandlers
} = require('../settings/role/role.routes');
const {
  createTenantRoleService
} = require('../settings/role/service');

const createTenantRuntime = ({
  authService,
  options = {}
} = {}) => {
  const tenantUserService =
    options.tenantUserService
    || createTenantUserService({
      authService
    });
  const tenantRoleService =
    options.tenantRoleService
    || createTenantRoleService({
      authService
    });

  return {
    tenantUserService,
    tenantRoleService,
    tenantUser: createTenantUserHandlers(tenantUserService),
    tenantRole: createTenantRoleHandlers(tenantRoleService)
  };
};

module.exports = {
  createTenantRuntime
};

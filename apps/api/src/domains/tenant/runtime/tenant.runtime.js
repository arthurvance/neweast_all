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
const {
  createTenantAccountHandlers
} = require('../account/account/account.routes');
const {
  createTenantAccountService
} = require('../account/account/service');

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
  const tenantAccountService =
    options.tenantAccountService
    || createTenantAccountService({
      authService
    });

  return {
    tenantUserService,
    tenantRoleService,
    tenantAccountService,
    tenantUser: createTenantUserHandlers(tenantUserService),
    tenantRole: createTenantRoleHandlers(tenantRoleService),
    tenantAccount: createTenantAccountHandlers(tenantAccountService)
  };
};

module.exports = {
  createTenantRuntime
};

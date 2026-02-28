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
const {
  createTenantCustomerHandlers
} = require('../customer/profile/customer.routes');
const {
  createTenantCustomerService
} = require('../customer/profile/service');
const {
  createTenantSessionHandlers
} = require('../session/center/session.routes');
const {
  createTenantSessionService
} = require('../session/center/service');

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
  const tenantCustomerService =
    options.tenantCustomerService
    || createTenantCustomerService({
      authService
    });
  const tenantSessionService =
    options.tenantSessionService
    || createTenantSessionService({
      authService
    });

  return {
    tenantUserService,
    tenantRoleService,
    tenantAccountService,
    tenantCustomerService,
    tenantSessionService,
    tenantUser: createTenantUserHandlers(tenantUserService),
    tenantRole: createTenantRoleHandlers(tenantRoleService),
    tenantAccount: createTenantAccountHandlers(tenantAccountService),
    tenantCustomer: createTenantCustomerHandlers(tenantCustomerService),
    tenantSession: createTenantSessionHandlers(tenantSessionService)
  };
};

module.exports = {
  createTenantRuntime
};

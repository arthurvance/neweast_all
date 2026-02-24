const { createTenantMemberHandlers } = require('./member.routes');
const { createTenantMemberService } = require('./member.service');
const { createTenantRoleHandlers } = require('./role.routes');
const { createTenantRoleService } = require('./role.service');

const createTenantRuntime = ({
  authService,
  options = {}
} = {}) => {
  const tenantMemberService =
    options.tenantMemberService
    || createTenantMemberService({
      authService
    });
  const tenantRoleService =
    options.tenantRoleService
    || createTenantRoleService({
      authService
    });

  return {
    tenantMemberService,
    tenantRoleService,
    tenantMember: createTenantMemberHandlers(tenantMemberService),
    tenantRole: createTenantRoleHandlers(tenantRoleService)
  };
};

module.exports = {
  createTenantRuntime
};

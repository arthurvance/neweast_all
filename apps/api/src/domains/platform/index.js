'use strict';

const {
  createPlatformDomainRuntime
} = require('./runtime/create-platform-domain-runtime');
const orgConstants = require('./settings/org/constants');
const roleConstants = require('./settings/role/constants');
const userConstants = require('./settings/user/constants');
const { createPlatformOrgHandlers } = require('./settings/org/org.routes');
const { createPlatformOrgService } = require('./settings/org/service');
const { createPlatformRoleHandlers } = require('./settings/role/role.routes');
const { createPlatformRoleService } = require('./settings/role/service');
const { createPlatformUserHandlers } = require('./settings/user/user.routes');
const { createPlatformUserService } = require('./settings/user/service');
const systemConfigConstants = require('./config/system-config/constants');
const integrationConstants = require('./config/integration/constants');
const integrationContractConstants = require('./config/integration-contract/constants');
const integrationRecoveryConstants = require('./config/integration-recovery/constants');
const integrationFreezeConstants = require('./config/integration-freeze/constants');

module.exports = {
  createPlatformDomainRuntime,
  createPlatformOrgHandlers,
  createPlatformOrgService,
  createPlatformRoleHandlers,
  createPlatformRoleService,
  createPlatformUserHandlers,
  createPlatformUserService,
  ...orgConstants,
  ...roleConstants,
  ...userConstants,
  ...systemConfigConstants,
  ...integrationConstants,
  ...integrationContractConstants,
  ...integrationRecoveryConstants,
  ...integrationFreezeConstants
};

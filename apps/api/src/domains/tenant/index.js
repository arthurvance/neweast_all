'use strict';

const {
  createTenantDomainRuntime
} = require('./runtime/create-tenant-domain-runtime');
const memberConstants = require('./settings/user/constants');
const roleConstants = require('./settings/role/constants');
const accountConstants = require('./account/account/constants');
const customerConstants = require('./customer/profile/constants');
const sessionConstants = require('./session/center/constants');

module.exports = {
  createTenantDomainRuntime,
  ...memberConstants,
  ...roleConstants,
  ...accountConstants,
  ...customerConstants,
  ...sessionConstants
};

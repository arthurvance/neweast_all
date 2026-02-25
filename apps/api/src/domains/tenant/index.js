'use strict';

const {
  createTenantDomainRuntime
} = require('./runtime/create-tenant-domain-runtime');
const memberConstants = require('./settings/user/constants');
const roleConstants = require('./settings/role/constants');

module.exports = {
  createTenantDomainRuntime,
  ...memberConstants,
  ...roleConstants
};

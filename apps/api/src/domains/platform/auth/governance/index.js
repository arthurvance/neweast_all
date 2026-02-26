'use strict';

const { createPlatformAuthGovernanceService } = require('./governance.service');
const { createPlatformAuthGovernanceMemoryStore } = require('./governance.store.memory');
const { createPlatformAuthGovernanceMySqlStore } = require('./governance.store.mysql');

module.exports = {
  createPlatformAuthGovernanceService,
  createPlatformAuthGovernanceMemoryStore,
  createPlatformAuthGovernanceMySqlStore
};

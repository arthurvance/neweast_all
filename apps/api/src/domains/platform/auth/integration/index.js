'use strict';

const { createPlatformAuthIntegrationService } = require('./integration.service');
const { createPlatformAuthIntegrationMemoryStore } = require('./integration.store.memory');
const { createPlatformAuthIntegrationMySqlStore } = require('./integration.store.mysql');

module.exports = {
  createPlatformAuthIntegrationService,
  createPlatformAuthIntegrationMemoryStore,
  createPlatformAuthIntegrationMySqlStore
};

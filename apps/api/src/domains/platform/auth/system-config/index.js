'use strict';

const { createPlatformAuthSystemConfigService } = require('./system-config.service');
const { createPlatformAuthSystemConfigMemoryStore } = require('./system-config.store.memory');
const { createPlatformAuthSystemConfigMySqlStore } = require('./system-config.store.mysql');

module.exports = {
  createPlatformAuthSystemConfigService,
  createPlatformAuthSystemConfigMemoryStore,
  createPlatformAuthSystemConfigMySqlStore
};

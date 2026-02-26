'use strict';

const {
  createPlatformMysqlAuthStoreSystemConfigRead
} = require('./platform-mysql-auth-store-system-config-read.js');
const {
  createPlatformMysqlAuthStoreSystemConfigWrite
} = require('./platform-mysql-auth-store-system-config-write.js');

const createPlatformMysqlAuthStoreSystemConfigCapability = (dependencies = {}) => ({
  ...createPlatformMysqlAuthStoreSystemConfigRead(dependencies),
  ...createPlatformMysqlAuthStoreSystemConfigWrite(dependencies)
});

module.exports = {
  createPlatformMysqlAuthStoreSystemConfigCapability
};

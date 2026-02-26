'use strict';

const {
  createPlatformMemoryAuthStoreSystemConfigRead
} = require('./platform-memory-auth-store-system-config-read.js');
const {
  createPlatformMemoryAuthStoreSystemConfigWrite
} = require('./platform-memory-auth-store-system-config-write.js');

const createPlatformMemoryAuthStoreSystemConfigCapability = (dependencies = {}) => ({
  ...createPlatformMemoryAuthStoreSystemConfigRead(dependencies),
  ...createPlatformMemoryAuthStoreSystemConfigWrite(dependencies)
});

module.exports = {
  createPlatformMemoryAuthStoreSystemConfigCapability
};

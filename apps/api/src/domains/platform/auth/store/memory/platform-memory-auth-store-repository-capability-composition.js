'use strict';

const {
  createPlatformMemoryAuthStoreRepositoryUserDirectoryGovernance
} = require('./platform-memory-auth-store-repository-user-directory-governance.js');
const {
  createPlatformMemoryAuthStoreRepositoryGovernanceRead
} = require('./platform-memory-auth-store-repository-governance-read.js');
const {
  createPlatformMemoryAuthStoreRepositorySessionAccessGovernance
} = require('./platform-memory-auth-store-repository-session-access-governance.js');

const createPlatformMemoryAuthStoreRepositoryCapabilityComposition = (dependencies = {}) => ({
  ...createPlatformMemoryAuthStoreRepositoryUserDirectoryGovernance(dependencies),
  ...createPlatformMemoryAuthStoreRepositoryGovernanceRead(dependencies),
  ...createPlatformMemoryAuthStoreRepositorySessionAccessGovernance(dependencies),
});

module.exports = {
  createPlatformMemoryAuthStoreRepositoryCapabilityComposition
};

'use strict';

const {
  createSharedMemoryAuthStoreRepositoryUserIdentityGovernance
} = require('./shared-memory-auth-store-repository-user-identity-governance.js');
const {
  createSharedMemoryAuthStoreRepositorySessionAccessTokenLifecycle
} = require('./shared-memory-auth-store-repository-session-access-token-lifecycle.js');

const createSharedMemoryAuthStoreRepositoryCapabilityComposition = (dependencies = {}) => ({
  ...createSharedMemoryAuthStoreRepositoryUserIdentityGovernance(dependencies),
  ...createSharedMemoryAuthStoreRepositorySessionAccessTokenLifecycle(dependencies),
});

module.exports = {
  createSharedMemoryAuthStoreRepositoryCapabilityComposition
};

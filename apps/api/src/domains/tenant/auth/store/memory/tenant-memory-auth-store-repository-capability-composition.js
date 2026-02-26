'use strict';

const {
  createTenantMemoryAuthStoreRepositorySessionAccessGovernance
} = require('./tenant-memory-auth-store-repository-session-access-governance.js');

const createTenantMemoryAuthStoreRepositoryCapabilityComposition = (dependencies = {}) => ({
  ...createTenantMemoryAuthStoreRepositorySessionAccessGovernance(dependencies),
});

module.exports = {
  createTenantMemoryAuthStoreRepositoryCapabilityComposition
};

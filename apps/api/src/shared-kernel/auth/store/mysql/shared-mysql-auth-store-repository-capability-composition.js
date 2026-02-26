'use strict';

const {
  createSharedMysqlAuthStoreRepositoryUserIdentityRead
} = require('./shared-mysql-auth-store-repository-user-identity-read.js');
const {
  createSharedMysqlAuthStoreRepositorySessionAccessGovernance
} = require('./shared-mysql-auth-store-repository-session-access-governance.js');
const {
  createSharedMysqlAuthStoreRepositoryRefreshSessionLifecycle
} = require('./shared-mysql-auth-store-repository-refresh-session-lifecycle.js');

const createSharedMysqlAuthStoreRepositoryCapabilityComposition = (dependencies = {}) => ({
  ...createSharedMysqlAuthStoreRepositoryUserIdentityRead(dependencies),
  ...createSharedMysqlAuthStoreRepositorySessionAccessGovernance(dependencies),
  ...createSharedMysqlAuthStoreRepositoryRefreshSessionLifecycle(dependencies),
});

module.exports = {
  createSharedMysqlAuthStoreRepositoryCapabilityComposition
};

'use strict';

const {
  createPlatformMysqlAuthStoreRepositoryUserDirectoryRead
} = require('./platform-mysql-auth-store-repository-user-directory-read.js');
const {
  createPlatformMysqlAuthStoreRepositoryOrgProfileGovernance
} = require('./platform-mysql-auth-store-repository-org-profile-governance.js');
const {
  createPlatformMysqlAuthStoreRepositoryGovernanceRead
} = require('./platform-mysql-auth-store-repository-governance-read.js');
const {
  createPlatformMysqlAuthStoreRepositorySessionAccessGovernance
} = require('./platform-mysql-auth-store-repository-session-access-governance.js');

const createPlatformMysqlAuthStoreRepositoryCapabilityComposition = (dependencies = {}) => ({
  ...createPlatformMysqlAuthStoreRepositoryUserDirectoryRead(dependencies),
  ...createPlatformMysqlAuthStoreRepositoryOrgProfileGovernance(dependencies),
  ...createPlatformMysqlAuthStoreRepositoryGovernanceRead(dependencies),
  ...createPlatformMysqlAuthStoreRepositorySessionAccessGovernance(dependencies),
});

module.exports = {
  createPlatformMysqlAuthStoreRepositoryCapabilityComposition
};

'use strict';

const {
  createTenantMysqlAuthStoreUsershipGovernance
} = require('./tenant-mysql-auth-store-usership-governance.js');
const {
  createTenantMysqlAuthStoreRolePermission
} = require('./tenant-mysql-auth-store-role-permission.js');

const createTenantMysqlAuthStoreCapabilityComposition = (dependencies = {}) => ({
  ...createTenantMysqlAuthStoreUsershipGovernance(dependencies),
  ...createTenantMysqlAuthStoreRolePermission(dependencies),
});

module.exports = {
  createTenantMysqlAuthStoreCapabilityComposition
};

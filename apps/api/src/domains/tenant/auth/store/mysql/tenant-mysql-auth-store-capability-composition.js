'use strict';

const {
  createTenantMysqlAuthStoreUsershipGovernance
} = require('./tenant-mysql-auth-store-usership-governance.js');
const {
  createTenantMysqlAuthStoreRolePermission
} = require('./tenant-mysql-auth-store-role-permission.js');
const {
  createTenantMysqlAuthStoreAccountMatrix
} = require('./tenant-mysql-auth-store-account-matrix.js');
const {
  createTenantMysqlAuthStoreCustomer
} = require('./tenant-mysql-auth-store-customer.js');
const {
  createTenantMysqlAuthStoreSession
} = require('./tenant-mysql-auth-store-session.js');

const createTenantMysqlAuthStoreCapabilityComposition = (dependencies = {}) => ({
  ...createTenantMysqlAuthStoreUsershipGovernance(dependencies),
  ...createTenantMysqlAuthStoreRolePermission(dependencies),
  ...createTenantMysqlAuthStoreAccountMatrix(dependencies),
  ...createTenantMysqlAuthStoreCustomer(dependencies),
  ...createTenantMysqlAuthStoreSession(dependencies),
});

module.exports = {
  createTenantMysqlAuthStoreCapabilityComposition
};

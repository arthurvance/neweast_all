'use strict';

const {
  createTenantMemoryAuthStoreUsershipGovernance
} = require('./tenant-memory-auth-store-usership-governance.js');
const {
  createTenantMemoryAuthStoreRolePermission
} = require('./tenant-memory-auth-store-role-permission.js');
const {
  createTenantMemoryAuthStoreAccountMatrix
} = require('./tenant-memory-auth-store-account-matrix.js');
const {
  createTenantMemoryAuthStoreCustomer
} = require('./tenant-memory-auth-store-customer.js');

const createTenantMemoryAuthStoreCapabilityComposition = (dependencies = {}) => ({
  ...createTenantMemoryAuthStoreUsershipGovernance(dependencies),
  ...createTenantMemoryAuthStoreRolePermission(dependencies),
  ...createTenantMemoryAuthStoreAccountMatrix(dependencies),
  ...createTenantMemoryAuthStoreCustomer(dependencies),
});

module.exports = {
  createTenantMemoryAuthStoreCapabilityComposition
};

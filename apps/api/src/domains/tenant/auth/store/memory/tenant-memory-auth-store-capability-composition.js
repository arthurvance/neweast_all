'use strict';

const {
  createTenantMemoryAuthStoreUsershipGovernance
} = require('./tenant-memory-auth-store-usership-governance.js');
const {
  createTenantMemoryAuthStoreRolePermission
} = require('./tenant-memory-auth-store-role-permission.js');

const createTenantMemoryAuthStoreCapabilityComposition = (dependencies = {}) => ({
  ...createTenantMemoryAuthStoreUsershipGovernance(dependencies),
  ...createTenantMemoryAuthStoreRolePermission(dependencies),
});

module.exports = {
  createTenantMemoryAuthStoreCapabilityComposition
};

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createAuthService } = require('../../src/shared-kernel/auth/create-auth-service');

const EXPECTED_PUBLIC_METHODS = [
  'acquireOwnerTransferLock',
  'authorizeRoute',
  'changePassword',
  'createOrganizationWithOwner',
  'createPlatformRoleCatalogEntry',
  'deletePlatformRoleCatalogEntry',
  'executeOwnerTransferTakeover',
  'findPlatformRoleCatalogEntryByRoleId',
  'findTenantUsershipByMembershipIdAndTenantId',
  'findTenantUsershipByUserAndTenantId',
  'getOrCreateUserIdentityByPhone',
  'getSystemSensitiveConfig',
  'listAuditEvents',
  'listPlatformPermissionCatalog',
  'listPlatformPermissionCatalogEntries',
  'listPlatformRoleCatalogEntries',
  'listPlatformRolePermissionGrants',
  'listTenantPermissionCatalog',
  'listTenantPermissionCatalogEntries',
  'listTenantRolePermissionGrants',
  'listTenantUserRoleBindings',
  'listTenantUsers',
  'login',
  'loginWithOtp',
  'logout',
  'platformOptions',
  'provisionPlatformUserByPhone',
  'provisionTenantUserByPhone',
  'recordIdempotencyEvent',
  'recordSystemSensitiveConfigAuditEvent',
  'refresh',
  'releaseOwnerTransferLock',
  'replacePlatformRolePermissionGrants',
  'replacePlatformRolesAndSyncSnapshot',
  'replaceTenantRolePermissionGrants',
  'replaceTenantUserRoleBindings',
  'rollbackProvisionedUserIdentity',
  'switchTenant',
  'sendOtp',
  'softDeleteUser',
  'tenantOptions',
  'updateOrganizationStatus',
  'updatePlatformRoleCatalogEntry',
  'updatePlatformUserStatus',
  'updateTenantUserProfile',
  'updateTenantUserStatus',
  'upsertSystemSensitiveConfig',
  'validateOwnerTransferRequest'
].sort();

test('createAuthService exports stable public method surface', () => {
  const service = createAuthService();
  const publicMethods = Object.keys(service)
    .filter((key) => key !== '_internals')
    .sort();

  assert.deepEqual(publicMethods, EXPECTED_PUBLIC_METHODS);
  assert.equal(typeof service._internals, 'object');
});

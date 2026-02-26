'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createAuthService } = require('../../src/shared-kernel/auth/create-auth-service');
const { createInMemoryAuthStore } = require('../../src/shared-kernel/auth/store/create-in-memory-auth-store');

const REQUIRED_SERVICE_METHODS = [
  'login',
  'loginWithOtp',
  'refresh',
  'logout',
  'changePassword',
  'tenantOptions',
  'platformOptions',
  'switchTenant',
  'provisionPlatformUserByPhone',
  'provisionTenantUserByPhone',
  'listAuditEvents',
  'recordIdempotencyEvent'
];

const REQUIRED_STORE_METHODS = [
  'findUserByPhone',
  'findUserById',
  'createRefreshToken',
  'rotateRefreshToken',
  'markRefreshTokenStatus',
  'createSession',
  'findSessionById',
  'listTenantUsersByTenantId',
  'listPlatformUsers'
];

test('auth service incremental guard keeps critical methods available', () => {
  const service = createAuthService();
  for (const methodName of REQUIRED_SERVICE_METHODS) {
    assert.equal(typeof service[methodName], 'function', `missing service method: ${methodName}`);
  }
});

test('auth store incremental guard keeps critical methods available', () => {
  const store = createInMemoryAuthStore();
  for (const methodName of REQUIRED_STORE_METHODS) {
    assert.equal(typeof store[methodName], 'function', `missing store method: ${methodName}`);
  }
});

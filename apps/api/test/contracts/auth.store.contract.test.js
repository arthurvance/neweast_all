'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createInMemoryAuthStore } = require('../../src/shared-kernel/auth/store/create-in-memory-auth-store');
const { createMySqlAuthStore } = require('../../src/shared-kernel/auth/store/create-mysql-auth-store');

function createNoopDbClient() {
  return {
    query: async () => [],
    inTransaction: async (runner) => runner({ query: async () => [] })
  };
}

test('memory/mysql store contract surfaces remain mirrored', () => {
  const memoryStore = createInMemoryAuthStore();
  const mysqlStore = createMySqlAuthStore({ dbClient: createNoopDbClient() });

  const memoryMethods = Object.keys(memoryStore).sort();
  const mysqlMethods = Object.keys(mysqlStore).sort();
  const mysqlOnlyMethods = mysqlMethods.filter((name) => !memoryMethods.includes(name));
  const ALLOWED_MYSQL_ONLY_METHODS = new Set([
    'getPlatformDeadlockMetrics',
    'replacePlatformRolePermissionGrantsAndSyncSnapshots'
  ]);

  for (const methodName of memoryMethods) {
    assert.equal(mysqlMethods.includes(methodName), true, `mysql store missing method: ${methodName}`);
  }
  assert.deepEqual(
    mysqlOnlyMethods.filter((name) => !ALLOWED_MYSQL_ONLY_METHODS.has(name)),
    []
  );
  assert.ok(memoryMethods.length >= 34);
});

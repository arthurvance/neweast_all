const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { readConfig } = require('../src/config/env');

test('createRouteHandlers exposes authIdempotencyStore when store contract is complete', () => {
  const store = {
    claimOrRead: async () => ({ action: 'retry' }),
    read: async () => null,
    resolve: async () => true,
    releasePending: async () => true
  };

  const handlers = createRouteHandlers(
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe: async () => ({
        db: { ok: true, detail: 'db ok' },
        redis: { ok: true, detail: 'redis ok' }
      }),
      authService: {},
      authIdempotencyStore: store
    }
  );

  assert.equal(handlers.authIdempotencyStore, store);
});

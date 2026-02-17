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

test('createRouteHandlers uses default dependency probe when dependencyProbe is omitted', async () => {
  const handlers = createRouteHandlers(
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      authService: {}
    }
  );

  const health = await handlers.health('req-default-probe');
  assert.equal(health.ok, true);
  assert.equal(health.dependencies.db.ok, true);
  assert.equal(health.dependencies.redis.ok, true);

  const smoke = await handlers.smoke('req-default-probe');
  assert.equal(smoke.ok, true);
  assert.equal(smoke.dependencies.db.ok, true);
  assert.equal(smoke.dependencies.redis.ok, true);
});

test('createRouteHandlers degrades health response when dependencyProbe throws', async () => {
  const handlers = createRouteHandlers(
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe: async () => {
        throw new Error('probe boom');
      },
      authService: {}
    }
  );

  const health = await handlers.health('req-probe-throws');
  assert.equal(health.ok, false);
  assert.equal(health.dependencies.db.ok, false);
  assert.equal(health.dependencies.redis.ok, false);
  assert.equal(health.dependencies.db.mode, 'probe-error');
  assert.equal(health.dependencies.redis.mode, 'probe-error');
  assert.equal(health.dependencies.db.detail, 'dependency probe failed');
  assert.equal(health.dependencies.redis.detail, 'dependency probe failed');
});

test('createRouteHandlers normalizes malformed dependencyProbe payloads as degraded', async () => {
  const handlers = createRouteHandlers(
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe: async () => ({
        db: {
          ok: true,
          mode: 'custom',
          detail: 'db ok'
        }
      }),
      authService: {}
    }
  );

  const health = await handlers.health('req-probe-malformed');
  assert.equal(health.ok, false);
  assert.equal(health.dependencies.db.ok, true);
  assert.equal(health.dependencies.redis.ok, false);
  assert.equal(health.dependencies.redis.mode, 'redis-probe');
  assert.equal(
    health.dependencies.redis.detail,
    'dependency probe result missing'
  );
});

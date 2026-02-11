const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { readConfig } = require('../src/config/env');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'false' });

test('openapi endpoint is exposed with auth placeholder', () => {
  const handlers = createRouteHandlers(config, {
    dependencyProbe: async () => ({
      db: { ok: true },
      redis: { ok: true }
    })
  });

  const payload = handlers.openapi('openapi-test');
  assert.equal(payload.openapi, '3.1.0');
  assert.ok(payload.paths['/auth/ping']);
  assert.ok(payload.paths['/health']);
});

test('health returns degraded when backend connectivity fails', async () => {
  const handlers = createRouteHandlers(config, {
    dependencyProbe: async () => ({
      db: { ok: false, detail: 'db down' },
      redis: { ok: true, detail: 'redis up' }
    })
  });

  const body = await handlers.health('t-1');
  assert.equal(body.ok, false);
  assert.equal(body.request_id, 't-1');
  assert.equal(body.dependencies.db.ok, false);
});

test('smoke marks ok when db and redis are both connected', async () => {
  const handlers = createRouteHandlers(config, {
    dependencyProbe: async () => ({
      db: { ok: true, mode: 'mysql-native' },
      redis: { ok: true, mode: 'ioredis' }
    })
  });

  const body = await handlers.smoke('smoke-route');
  assert.equal(body.ok, true);
  assert.equal(body.chain, 'api -> db/redis');
  assert.equal(body.request_id, 'smoke-route');
});

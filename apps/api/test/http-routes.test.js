const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { readConfig } = require('../src/config/env');

const dependencyProbe = async () => ({
  db: { ok: true, detail: 'db ok' },
  redis: { ok: true, detail: 'redis ok' }
});

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

test('createRouteHandlers wires platform integration handlers with provided service', async () => {
  const integrationCalls = [];
  const platformIntegrationService = {
    listIntegrations: async (payload) => {
      integrationCalls.push({ method: 'list', payload });
      return { request_id: payload.requestId, integrations: [] };
    },
    getIntegration: async (payload) => {
      integrationCalls.push({ method: 'get', payload });
      return {
        integration_id: payload.integrationId,
        request_id: payload.requestId
      };
    },
    createIntegration: async (payload) => {
      integrationCalls.push({ method: 'create', payload });
      return {
        integration_id: 'integration-created',
        request_id: payload.requestId
      };
    },
    updateIntegration: async (payload) => {
      integrationCalls.push({ method: 'update', payload });
      return {
        integration_id: payload.integrationId,
        request_id: payload.requestId
      };
    },
    changeIntegrationLifecycle: async (payload) => {
      integrationCalls.push({ method: 'lifecycle', payload });
      return {
        integration_id: payload.integrationId,
        previous_status: 'draft',
        current_status: payload.payload.status,
        request_id: payload.requestId
      };
    }
  };

  const handlers = createRouteHandlers(
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe,
      authService: {},
      platformIntegrationService
    }
  );

  const listed = await handlers.platformListIntegrations(
    'req-http-routes-platform-integration-list',
    'Bearer fake-token',
    { page: '1', page_size: '20' },
    null
  );
  assert.deepEqual(listed, {
    request_id: 'req-http-routes-platform-integration-list',
    integrations: []
  });

  const created = await handlers.platformCreateIntegration(
    'req-http-routes-platform-integration-create',
    'Bearer fake-token',
    {
      code: 'HTTP_ROUTES_INTEGRATION',
      name: 'HTTP Routes Integration',
      direction: 'outbound',
      protocol: 'https',
      auth_mode: 'hmac'
    },
    null,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );
  assert.equal(created.integration_id, 'integration-created');
  assert.equal(created.request_id, 'req-http-routes-platform-integration-create');
  assert.equal(integrationCalls.length, 2);
  assert.equal(integrationCalls[0].method, 'list');
  assert.equal(integrationCalls[1].method, 'create');
  assert.equal(handlers._internals.platformIntegrationService, platformIntegrationService);
});

test('createRouteHandlers enforces shared auth service identity for platformIntegrationService', () => {
  assert.throws(
    () =>
      createRouteHandlers(
        readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
        {
          authService: { serviceName: 'primary-auth' },
          platformIntegrationService: {
            listIntegrations: async () => ({}),
            getIntegration: async () => ({}),
            createIntegration: async () => ({}),
            updateIntegration: async () => ({}),
            changeIntegrationLifecycle: async () => ({}),
            _internals: {
              authService: { serviceName: 'other-auth' }
            }
          }
        }
      ),
    /authService and platformIntegrationService to share the same authService instance/
  );
});

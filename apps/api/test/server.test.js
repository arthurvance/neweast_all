const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { readConfig } = require('../src/config/env');
const { createServer } = require('../src/server');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'false' });
const dependencyProbe = async () => ({
  db: { ok: true },
  redis: { ok: true }
});

const startServer = async (overrides = {}) => {
  const server = createServer(readConfig(overrides), { dependencyProbe });
  await new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', (error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: async () => {
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
    }
  };
};

test('openapi endpoint is exposed with auth placeholder', () => {
  const handlers = createRouteHandlers(config, {
    dependencyProbe
  });

  const payload = handlers.openapi('openapi-test');
  assert.equal(payload.openapi, '3.1.0');
  assert.ok(payload.paths['/auth/ping']);
  assert.ok(payload.paths['/health']);
  assert.ok(payload.paths['/auth/otp/send']);
  assert.ok(payload.paths['/auth/otp/login']);
  assert.ok(payload.paths['/auth/login'].post.responses['400']);
  assert.ok(payload.paths['/auth/login'].post.responses['413']);
  assert.ok(payload.paths['/auth/login'].post.responses['429']);
  assert.ok(payload.paths['/auth/otp/send'].post.responses['413']);
  assert.ok(payload.paths['/auth/otp/login'].post.responses['413']);
  assert.ok(payload.paths['/auth/refresh'].post.responses['400']);
  assert.ok(payload.paths['/auth/refresh'].post.responses['413']);
  assert.ok(payload.paths['/auth/change-password'].post.responses['413']);
  assert.equal(
    payload.components.schemas.ProblemDetails.properties.error_code.type,
    'string'
  );
  assert.equal(
    payload.components.schemas.ProblemDetails.properties.retry_after_seconds.type,
    'integer'
  );
  assert.equal(
    payload.components.schemas.ProblemDetails.properties.rate_limit_action.type,
    'string'
  );
  assert.equal(
    payload.paths['/auth/login'].post.responses['413'].content['application/problem+json'].examples
      .payload_too_large.value.error_code,
    'AUTH-413-PAYLOAD-TOO-LARGE'
  );
  assert.equal(
    payload.paths['/auth/refresh'].post.responses['413'].content['application/problem+json'].examples
      .payload_too_large.value.error_code,
    'AUTH-413-PAYLOAD-TOO-LARGE'
  );
  assert.equal('extensions' in payload.components.schemas.ProblemDetails.properties, false);
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

test('createServer enforces json payload limit with AUTH-413-PAYLOAD-TOO-LARGE', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true',
    API_JSON_BODY_LIMIT_BYTES: '256'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/auth/login`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, application/problem+json'
      },
      body: JSON.stringify({
        phone: '13800000000',
        password: 'x'.repeat(1024)
      })
    });
    const payload = await response.json();
    assert.equal(response.status, 413);
    assert.equal(payload.error_code, 'AUTH-413-PAYLOAD-TOO-LARGE');
    assert.equal(String(response.headers.get('connection') || '').toLowerCase(), 'close');
  } finally {
    await harness.close();
  }
});

test('createServer handles auth routes with trailing slash path', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/auth/login/`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, application/problem+json'
      },
      body: JSON.stringify({
        phone: '13800000000',
        password: 'Passw0rd!'
      })
    });
    const payload = await response.json();
    assert.notEqual(response.status, 404);
    assert.equal(payload.error_code !== undefined || payload.access_token !== undefined, true);
  } finally {
    await harness.close();
  }
});

test('createServer supports CORS preflight for API routes', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/auth/login`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://example.test',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type,authorization,x-request-id'
      }
    });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get('access-control-allow-origin'), '*');
    assert.ok(String(response.headers.get('access-control-allow-methods') || '').includes('POST'));
    assert.ok(
      String(response.headers.get('access-control-allow-headers') || '').includes(
        'Content-Type'
      )
    );
  } finally {
    await harness.close();
  }
});

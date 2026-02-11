const test = require('node:test');
const assert = require('node:assert/strict');
const { handleWebRoute } = require('../src/server');

test('web smoke endpoint validates web->api chain', async () => {
  const route = await handleWebRoute(
    { pathname: '/smoke', headers: { 'x-request-id': 'web-test' } },
    {
      apiBaseUrl: 'http://api',
      apiClient: async () => ({
        status: 200,
        payload: {
          ok: true,
          dependencies: {
            db: { ok: true },
            redis: { ok: true }
          }
        }
      })
    }
  );
  const body = JSON.parse(route.body);
  assert.equal(route.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.request_id, 'web-test');
});

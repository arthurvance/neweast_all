const test = require('node:test');
const assert = require('node:assert/strict');
const { handleWebRoute } = require('../src/server');

test('web smoke endpoint validates web->api chain', async () => {
  const route = await handleWebRoute(
    { pathname: '/smoke', method: 'GET', headers: { 'x-request-id': 'web-test' } },
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

test('web /api proxy forwards request to upstream API', async () => {
  const route = await handleWebRoute(
    {
      pathname: '/api/auth/otp/send?channel=sms',
      method: 'POST',
      headers: {
        'x-request-id': 'proxy-test',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ phone: '13800000000' })
    },
    {
      apiBaseUrl: 'http://api',
      apiClient: async (path, headers, request) => {
        assert.equal(path, '/auth/otp/send?channel=sms');
        assert.equal(headers['x-request-id'], 'proxy-test');
        assert.equal(headers['content-type'], 'application/json');
        assert.equal(request.method, 'POST');
        assert.equal(request.body, JSON.stringify({ phone: '13800000000' }));
        return {
          status: 429,
          headers: { 'content-type': 'application/problem+json' },
          payload: {
            status: 429,
            error_code: 'AUTH-429-RATE-LIMITED',
            retry_after_seconds: 31
          }
        };
      }
    }
  );

  assert.equal(route.status, 429);
  assert.equal(route.headers['content-type'], 'application/problem+json');
  const body = JSON.parse(route.body);
  assert.equal(body.error_code, 'AUTH-429-RATE-LIMITED');
  assert.equal(body.retry_after_seconds, 31);
});

test('web root route accepts query string for invite/deeplink flows', async () => {
  const route = await handleWebRoute(
    {
      pathname: '/?from=invite',
      method: 'GET',
      headers: {
        'x-request-id': 'query-test'
      }
    },
    { apiBaseUrl: 'http://api' }
  );

  assert.equal(route.status, 200);
  assert.equal(route.headers['content-type'], 'text/html; charset=utf-8');
  assert.match(route.body, /<!doctype html>/i);
});

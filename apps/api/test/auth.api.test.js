const test = require('node:test');
const assert = require('node:assert/strict');
const { handleApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');
const { createAuthService } = require('../src/modules/auth/auth.service');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

const dependencyProbe = async () => ({
  db: { ok: true, detail: 'db ok' },
  redis: { ok: true, detail: 'redis ok' }
});

const seedUsers = [
  {
    id: 'user-active',
    phone: '13800000000',
    password: 'Passw0rd!',
    status: 'active'
  },
  {
    id: 'user-disabled',
    phone: '13800000001',
    password: 'Passw0rd!',
    status: 'disabled'
  }
];

const createApiContext = () => ({
  authService: createAuthService({ seedUsers }),
  dependencyProbe
});

const callRoute = async ({ pathname, method = 'GET', body = {}, headers = {} }, context) => {
  const route = await handleApiRoute(
    {
      pathname,
      method,
      body,
      headers
    },
    config,
    context
  );

  return {
    status: route.status,
    headers: route.headers,
    body: JSON.parse(route.body)
  };
};

test('auth login endpoint returns request_id and token pair', async () => {
  const context = createApiContext();

  const res = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );

  assert.equal(res.status, 200);
  assert.equal(res.body.token_type, 'Bearer');
  assert.ok(res.body.access_token);
  assert.ok(res.body.refresh_token);
  assert.ok(res.body.session_id);
  assert.ok(res.body.request_id);
});

test('auth login endpoint supports query string path', async () => {
  const context = createApiContext();

  const res = await callRoute(
    {
      pathname: '/auth/login?next=%2Fdashboard',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );

  assert.equal(res.status, 200);
  assert.ok(res.body.access_token);
  assert.ok(res.body.refresh_token);
});

test('auth login failure returns standardized problem details', async () => {
  const context = createApiContext();

  const res = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13999999999', password: 'not-it' }
    },
    context
  );

  assert.equal(res.status, 401);
  assert.equal(res.headers['content-type'], 'application/problem+json');
  assert.equal(res.body.title, 'Unauthorized');
  assert.equal(res.body.error_code, 'AUTH-401-LOGIN-FAILED');
  assert.equal(res.body.detail, '手机号或密码错误');
});

test('refresh rotation + replay handling via API', async () => {
  const context = createApiContext();

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );

  const refresh = await callRoute(
    {
      pathname: '/auth/refresh',
      method: 'POST',
      body: { refresh_token: login.body.refresh_token }
    },
    context
  );

  assert.equal(refresh.status, 200);
  assert.notEqual(refresh.body.refresh_token, login.body.refresh_token);

  const replay = await callRoute(
    {
      pathname: '/auth/refresh',
      method: 'POST',
      body: { refresh_token: login.body.refresh_token }
    },
    context
  );

  assert.equal(replay.status, 401);
  assert.equal(replay.body.error_code, 'AUTH-401-INVALID-REFRESH');
});

test('logout revokes only current session', async () => {
  const context = createApiContext();

  const sessionA = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );

  const sessionB = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );

  const logout = await callRoute(
    {
      pathname: '/auth/logout',
      method: 'POST',
      headers: {
        authorization: `Bearer ${sessionA.body.access_token}`
      }
    },
    context
  );

  assert.equal(logout.status, 200);
  assert.equal(logout.body.ok, true);

  const refreshB = await callRoute(
    {
      pathname: '/auth/refresh',
      method: 'POST',
      body: { refresh_token: sessionB.body.refresh_token }
    },
    context
  );

  assert.equal(refreshB.status, 200);

  const refreshA = await callRoute(
    {
      pathname: '/auth/refresh',
      method: 'POST',
      body: { refresh_token: sessionA.body.refresh_token }
    },
    context
  );

  assert.equal(refreshA.status, 401);
});

test('change password forces relogin and new password login succeeds', async () => {
  const context = createApiContext();

  const login = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );

  const changed = await callRoute(
    {
      pathname: '/auth/change-password',
      method: 'POST',
      headers: {
        authorization: `Bearer ${login.body.access_token}`
      },
      body: {
        current_password: 'Passw0rd!',
        new_password: 'Passw0rd!2026'
      }
    },
    context
  );

  assert.equal(changed.status, 200);
  assert.equal(changed.body.password_changed, true);
  assert.equal(changed.body.relogin_required, true);

  const oldPasswordLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    },
    context
  );

  assert.equal(oldPasswordLogin.status, 401);

  const newPasswordLogin = await callRoute(
    {
      pathname: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!2026' }
    },
    context
  );

  assert.equal(newPasswordLogin.status, 200);
  assert.ok(newPasswordLogin.body.access_token);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const { createAuthService, AuthProblemError } = require('../src/modules/auth/auth.service');

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

const createService = () => createAuthService({ seedUsers });

test('login success returns token pair and session metadata', () => {
  const service = createService();
  const result = service.login({
    requestId: 'req-login-1',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  assert.equal(result.request_id, 'req-login-1');
  assert.equal(result.token_type, 'Bearer');
  assert.ok(result.access_token);
  assert.ok(result.refresh_token);
  assert.ok(result.session_id);
});

test('login failure keeps unified semantics and does not leak account state', () => {
  const service = createService();

  assert.throws(
    () => {
      service.login({ requestId: 'req-login-2', phone: '13800000000', password: 'wrong' });
    },
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      assert.equal(error.detail, '手机号或密码错误');
      return true;
    }
  );

  assert.throws(
    () => {
      service.login({ requestId: 'req-login-3', phone: '13800000001', password: 'Passw0rd!' });
    },
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      assert.equal(error.detail, '手机号或密码错误');
      return true;
    }
  );

  assert.throws(
    () => {
      service.login({ requestId: 'req-login-4', phone: '13999999999', password: 'Passw0rd!' });
    },
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      assert.equal(error.detail, '手机号或密码错误');
      return true;
    }
  );
});

test('refresh rotation invalidates previous refresh token immediately', () => {
  const service = createService();
  const login = service.login({
    requestId: 'req-login-5',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  const refreshed = service.refresh({
    requestId: 'req-refresh-1',
    refreshToken: login.refresh_token
  });

  assert.ok(refreshed.access_token);
  assert.ok(refreshed.refresh_token);
  assert.notEqual(refreshed.refresh_token, login.refresh_token);

  assert.throws(
    () => {
      service.refresh({ requestId: 'req-refresh-2', refreshToken: login.refresh_token });
    },
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-REFRESH');
      return true;
    }
  );
});

test('logout only revokes current session, keeping concurrent sessions valid', () => {
  const service = createService();

  const sessionA = service.login({ requestId: 'req-login-a', phone: '13800000000', password: 'Passw0rd!' });
  const sessionB = service.login({ requestId: 'req-login-b', phone: '13800000000', password: 'Passw0rd!' });

  const logoutResult = service.logout({
    requestId: 'req-logout-a',
    accessToken: sessionA.access_token
  });

  assert.equal(logoutResult.ok, true);
  assert.equal(logoutResult.session_id, sessionA.session_id);

  const refreshB = service.refresh({
    requestId: 'req-refresh-b',
    refreshToken: sessionB.refresh_token
  });

  assert.ok(refreshB.access_token);
  assert.ok(refreshB.refresh_token);

  assert.throws(
    () => {
      service.refresh({ requestId: 'req-refresh-a', refreshToken: sessionA.refresh_token });
    },
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      return true;
    }
  );
});

test('change password revokes current auth session and only new password is accepted', () => {
  const service = createService();

  const session = service.login({
    requestId: 'req-login-6',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  const changed = service.changePassword({
    requestId: 'req-change-1',
    accessToken: session.access_token,
    currentPassword: 'Passw0rd!',
    newPassword: 'Passw0rd!2026'
  });

  assert.equal(changed.password_changed, true);
  assert.equal(changed.relogin_required, true);

  assert.throws(
    () => {
      service.login({ requestId: 'req-login-7', phone: '13800000000', password: 'Passw0rd!' });
    },
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      return true;
    }
  );

  const relogin = service.login({
    requestId: 'req-login-8',
    phone: '13800000000',
    password: 'Passw0rd!2026'
  });

  assert.ok(relogin.access_token);
  assert.ok(relogin.refresh_token);
});

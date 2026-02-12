const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
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

test('default service does not allow legacy seeded credentials', async () => {
  const service = createAuthService();

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-login-default',
        phone: '13800000000',
        password: 'Passw0rd!'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      return true;
    }
  );
});

test('service uses injected authStore lookup path', async () => {
  const service = createAuthService({
    allowInMemoryOtpStores: true,
    authStore: {
      findUserByPhone: async () => {
        throw new Error('store-called');
      }
    }
  });

  await assert.rejects(
    () =>
      service.login({
        requestId: 'req-login-store',
        phone: '13800000000',
        password: 'Passw0rd!'
      }),
    /store-called/
  );
});

test('service rejects implicit otp/rate-limit fallback for external authStore', () => {
  assert.throws(
    () =>
      createAuthService({
        authStore: {
          findUserByPhone: async () => null
        }
      }),
    /OTP and rate-limit stores must be configured explicitly/
  );
});

test('service requires otpStore.getSentAt in otp store contract', () => {
  assert.throws(
    () =>
      createAuthService({
        seedUsers,
        otpStore: {
          upsertOtp: async () => ({ sent_at_ms: Date.now() }),
          verifyAndConsumeOtp: async () => ({ ok: false, reason: 'missing' })
        }
      }),
    /otpStore\.getSentAt is required/
  );
});

test('service requires external jwt keys when multi-instance mode is enabled', () => {
  assert.throws(
    () => createAuthService({ enforceExternalJwtKeys: true, seedUsers }),
    /External JWT key pair is required/
  );
});

test('service disables access session cache in multi-instance mode', () => {
  const keyPair = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  const service = createAuthService({
    seedUsers,
    jwtKeyPair: keyPair,
    multiInstance: true,
    accessSessionCacheTtlMs: 800
  });

  assert.equal(service._internals.accessSessionCacheTtlMs, 0);
});

test('login success returns token pair and session metadata', async () => {
  const service = createService();
  const result = await service.login({
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

test('login failure keeps unified semantics and does not leak account state', async () => {
  const service = createService();

  await assert.rejects(
    () => service.login({ requestId: 'req-login-2', phone: '13800000000', password: 'wrong' }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      assert.equal(error.detail, '手机号或密码错误');
      return true;
    }
  );

  await assert.rejects(
    () => service.login({ requestId: 'req-login-3', phone: '13800000001', password: 'Passw0rd!' }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      assert.equal(error.detail, '手机号或密码错误');
      return true;
    }
  );

  await assert.rejects(
    () => service.login({ requestId: 'req-login-4', phone: '13999999999', password: 'Passw0rd!' }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      assert.equal(error.detail, '手机号或密码错误');
      return true;
    }
  );

  const lastAudit = service._internals.auditTrail[service._internals.auditTrail.length - 1];
  assert.equal(lastAudit.type, 'auth.login.failed');
  assert.equal(lastAudit.phone_masked, '139****9999');
});

test('refresh rotation invalidates previous refresh token immediately', async () => {
  const service = createService();
  const login = await service.login({
    requestId: 'req-login-5',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  const refreshed = await service.refresh({
    requestId: 'req-refresh-1',
    refreshToken: login.refresh_token
  });

  assert.ok(refreshed.access_token);
  assert.ok(refreshed.refresh_token);
  assert.notEqual(refreshed.refresh_token, login.refresh_token);

  await assert.rejects(
    () => service.refresh({ requestId: 'req-refresh-2', refreshToken: login.refresh_token }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-REFRESH');
      return true;
    }
  );

  await assert.rejects(
    () => service.refresh({ requestId: 'req-refresh-3', refreshToken: refreshed.refresh_token }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-INVALID-REFRESH');
      return true;
    }
  );
});

test('refresh failure writes session metadata into audit trail', async () => {
  const service = createService();

  await assert.rejects(
    () => service.refresh({ requestId: 'req-refresh-invalid-payload', refreshToken: '' }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 400);
      assert.equal(error.errorCode, 'AUTH-400-INVALID-PAYLOAD');
      return true;
    }
  );

  const lastAudit = service._internals.auditTrail[service._internals.auditTrail.length - 1];
  assert.equal(lastAudit.type, 'auth.refresh.replay_or_invalid');
  assert.equal(lastAudit.session_id_hint, 'unknown');
});

test('logout only revokes current session, keeping concurrent sessions valid', async () => {
  const service = createService();

  const sessionA = await service.login({ requestId: 'req-login-a', phone: '13800000000', password: 'Passw0rd!' });
  const sessionB = await service.login({ requestId: 'req-login-b', phone: '13800000000', password: 'Passw0rd!' });

  const logoutResult = await service.logout({
    requestId: 'req-logout-a',
    accessToken: sessionA.access_token
  });

  assert.equal(logoutResult.ok, true);
  assert.equal(logoutResult.session_id, sessionA.session_id);

  const refreshB = await service.refresh({
    requestId: 'req-refresh-b',
    refreshToken: sessionB.refresh_token
  });

  assert.ok(refreshB.access_token);
  assert.ok(refreshB.refresh_token);

  await assert.rejects(
    () => service.refresh({ requestId: 'req-refresh-a', refreshToken: sessionA.refresh_token }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      return true;
    }
  );
});

test('change password revokes current auth session and only new password is accepted', async () => {
  const service = createService();

  const session = await service.login({
    requestId: 'req-login-6',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  const changed = await service.changePassword({
    requestId: 'req-change-1',
    accessToken: session.access_token,
    currentPassword: 'Passw0rd!',
    newPassword: 'Passw0rd!2026'
  });

  assert.equal(changed.password_changed, true);
  assert.equal(changed.relogin_required, true);

  await assert.rejects(
    () => service.login({ requestId: 'req-login-7', phone: '13800000000', password: 'Passw0rd!' }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      return true;
    }
  );

  const relogin = await service.login({
    requestId: 'req-login-8',
    phone: '13800000000',
    password: 'Passw0rd!2026'
  });

  assert.ok(relogin.access_token);
  assert.ok(relogin.refresh_token);
});

test('change password mismatch audit includes masked phone metadata', async () => {
  const service = createService();

  const session = await service.login({
    requestId: 'req-login-9',
    phone: '13800000000',
    password: 'Passw0rd!'
  });

  await assert.rejects(
    () =>
      service.changePassword({
        requestId: 'req-change-2',
        accessToken: session.access_token,
        currentPassword: 'wrong-password',
        newPassword: 'Passw0rd!2027'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, 'AUTH-401-LOGIN-FAILED');
      return true;
    }
  );

  const lastAudit = service._internals.auditTrail[service._internals.auditTrail.length - 1];
  assert.equal(lastAudit.type, 'auth.password_change.rejected');
  assert.equal(lastAudit.phone_masked, '138****0000');
});

test('sendOtp fails closed and logs cooldown_check_failed audit when getSentAt throws', async () => {
  let upsertCalled = false;
  const failingOtpStore = {
    upsertOtp: async () => {
      upsertCalled = true;
      return { sent_at_ms: Date.now() };
    },
    getSentAt: async () => {
      throw new Error('Redis connection failed');
    },
    verifyAndConsumeOtp: async () => ({ ok: false, reason: 'missing' })
  };

  const service = createAuthService({
    seedUsers,
    otpStore: failingOtpStore
  });

  await assert.rejects(
    () =>
      service.sendOtp({
        requestId: 'req-otp-fail',
        phone: '13800000000'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 429);
      assert.equal(error.errorCode, 'AUTH-429-RATE-LIMITED');
      assert.equal(error.extensions.rate_limit_action, 'otp_send');
      assert.equal(error.extensions.retry_after_seconds, 60);
      assert.equal(error.extensions.rate_limit_limit, 1);
      assert.equal(error.extensions.rate_limit_window_seconds, 60);
      return true;
    }
  );

  assert.equal(upsertCalled, false);

  const auditEvents = service._internals.auditTrail;
  const cooldownFailedEvent = auditEvents.find(
    (e) => e.type === 'auth.otp.send.cooldown_check_failed'
  );
  assert.ok(cooldownFailedEvent, 'should have cooldown_check_failed audit event');
  assert.equal(cooldownFailedEvent.detail, 'getSentAt failed: Redis connection failed');
});

test('sendOtp normalizes string getSentAt value and keeps cooldown seconds bounded', async () => {
  const nowMs = Date.UTC(2026, 0, 1, 0, 0, 0);
  let upsertCalled = false;

  const otpStore = {
    upsertOtp: async () => {
      upsertCalled = true;
      return { sent_at_ms: nowMs };
    },
    getSentAt: async () => String(nowMs - 30 * 1000),
    verifyAndConsumeOtp: async () => ({ ok: false, reason: 'missing' })
  };

  const service = createAuthService({
    seedUsers,
    now: () => nowMs,
    otpStore
  });

  await assert.rejects(
    () =>
      service.sendOtp({
        requestId: 'req-otp-string-sent-at',
        phone: '13800000000'
      }),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 429);
      assert.equal(error.errorCode, 'AUTH-429-RATE-LIMITED');
      assert.equal(error.extensions.rate_limit_action, 'otp_send');
      assert.equal(error.extensions.retry_after_seconds, 30);
      assert.ok(error.extensions.retry_after_seconds <= 60);
      return true;
    }
  );

  assert.equal(upsertCalled, false);
});

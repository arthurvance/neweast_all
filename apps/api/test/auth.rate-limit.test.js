const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createApiApp } = require('../src/app');
const { readConfig } = require('../src/config/env');
const { RATE_LIMIT_WINDOW_SECONDS } = require('../src/modules/auth/auth.service');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });

const dependencyProbe = async () => ({
  db: { ok: true, detail: 'db ok' },
  redis: { ok: true, detail: 'redis ok' }
});

const seedUsers = [
  {
    id: 'rate-user-active',
    phone: '13800000000',
    password: 'Passw0rd!',
    status: 'active'
  }
];

const createExpressHarness = async () => {
  let currentNow = Date.now();
  const app = await createApiApp(config, {
    dependencyProbe,
    authService: require('../src/modules/auth/auth.service').createAuthService({
      seedUsers,
      now: () => currentNow
    })
  });

  await app.init();
  await app.listen(0, '127.0.0.1');
  const address = app.getHttpServer().address();
  const port = typeof address === 'object' && address ? address.port : 0;

  return {
    app,
    baseUrl: `http://127.0.0.1:${port}`,
    now: () => currentNow,
    setNow: (nextNow) => {
      currentNow = Number(nextNow);
    },
    close: async () => {
      await app.close();
    }
  };
};

const parseResponseBody = async (response) => {
  const contentType = response.headers.get('content-type') || '';
  if (
    contentType.includes('application/json') ||
    contentType.includes('application/problem+json')
  ) {
    return response.json();
  }
  return response.text();
};

const invokeRoute = async (harness, { method, path, body, headers }) => {
  const normalizedMethod = String(method || 'GET').toUpperCase();
  const requestHeaders = {
    Accept: 'application/json, application/problem+json',
    'x-request-id': `test-${normalizedMethod}-${path}`,
    ...(headers || {})
  };

  let requestBody;
  if (body !== undefined && normalizedMethod !== 'GET' && normalizedMethod !== 'HEAD') {
    requestBody = JSON.stringify(body);
    if (!requestHeaders['content-type'] && !requestHeaders['Content-Type']) {
      requestHeaders['content-type'] = 'application/json';
    }
  }

  const response = await fetch(`${harness.baseUrl}${path}`, {
    method: normalizedMethod,
    headers: requestHeaders,
    body: requestBody
  });
  const payload = await parseResponseBody(response);

  return {
    status: response.status,
    headers: {
      'content-type': response.headers.get('content-type') || ''
    },
    body: payload
  };
};

test('password_login (express) limit is enforced and recovers after sliding window', async () => {
  const harness = await createExpressHarness();
  try {
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const response = await invokeRoute(harness, {
        method: 'post',
        path: '/auth/login',
        body: { phone: '13800000000', password: 'Passw0rd!' }
      });
      assert.equal(response.status, 200);
      assert.ok(response.body.access_token);
    }

    const limited = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    });
    assert.equal(limited.status, 429);
    assert.equal(limited.body.error_code, 'AUTH-429-RATE-LIMITED');

    harness.setNow(harness.now() + RATE_LIMIT_WINDOW_SECONDS * 1000 + 1000);
    const recovered = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    });
    assert.equal(recovered.status, 200);
    assert.ok(recovered.body.access_token);
  } finally {
    await harness.close();
  }
});

test('otp_login (express) is rate-limited independently from otp_send and password_login', async () => {
  const harness = await createExpressHarness();
  try {
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const response = await invokeRoute(harness, {
        method: 'post',
        path: '/auth/otp/login',
        body: { phone: '13800000000', otp_code: '000000' }
      });
      assert.equal(response.status, 401);
      assert.equal(response.body.error_code, 'AUTH-401-OTP-FAILED');
    }

    const limitedOtpLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/login',
      body: { phone: '13800000000', otp_code: '000000' }
    });
    assert.equal(limitedOtpLogin.status, 429);
    assert.equal(limitedOtpLogin.body.error_code, 'AUTH-429-RATE-LIMITED');
    assert.equal(limitedOtpLogin.body.rate_limit_action, 'otp_login');

    const passwordLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    });
    assert.equal(passwordLogin.status, 200);
    assert.ok(passwordLogin.body.access_token);

    const otpSend = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/send',
      body: { phone: '13800000000' }
    });
    assert.equal(otpSend.status, 200);
    assert.equal(otpSend.body.resend_after_seconds, 60);
  } finally {
    await harness.close();
  }
});

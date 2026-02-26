const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createApiApp } = require('../src/app');
const { readConfig } = require('../src/config/env');

const dependencyProbe = async () => ({
  db: { ok: true, detail: 'db ok' },
  redis: { ok: true, detail: 'redis ok' }
});

const seedUsers = [
  {
    id: 'otp-user-active',
    phone: '13800000000',
    password: 'Passw0rd!',
    status: 'active'
  }
];

const createOtpStoreHarness = ({ nowProvider = Date.now } = {}) => {
  const records = new Map();

  return {
    store: {
      upsertOtp: async ({ phone, code, expiresAt }) => {
        const sentAtMs = nowProvider();
        records.set(String(phone), {
          code: String(code),
          expiresAt: Number(expiresAt),
          consumed: false,
          sentAtMs
        });
        return { sent_at_ms: sentAtMs };
      },
      getSentAt: async ({ phone }) => {
        const record = records.get(String(phone));
        return record ? record.sentAtMs : null;
      },
      verifyAndConsumeOtp: async ({ phone, code, nowMs }) => {
        const record = records.get(String(phone));
        if (!record) {
          return { ok: false, reason: 'missing' };
        }
        if (record.consumed) {
          return { ok: false, reason: 'used' };
        }
        if (record.expiresAt <= Number(nowMs)) {
          return { ok: false, reason: 'expired' };
        }
        if (record.code !== String(code)) {
          return { ok: false, reason: 'mismatch' };
        }
        record.consumed = true;
        records.set(String(phone), record);
        return { ok: true, reason: 'ok' };
      }
    },
    getCode: (phone) => records.get(String(phone))?.code || null
  };
};

const createExpressHarness = async (overrides = {}) => {
  let currentNow = Date.now();
  const otpHarness = createOtpStoreHarness({ nowProvider: () => currentNow });
  const effectiveConfig = readConfig({
    ALLOW_MOCK_BACKENDS: 'true',
    ...overrides
  });

  const app = await createApiApp(effectiveConfig, {
    dependencyProbe,
    authService: require('../src/shared-kernel/auth/create-auth-service').createAuthService({
      seedUsers,
      otpStore: otpHarness.store,
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
    setNow: (nextNow) => {
      currentNow = Number(nextNow);
    },
    getCode: otpHarness.getCode,
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

const invokeRawRoute = (harness, { method = 'GET', path, body = '', headers = {} }) =>
  new Promise((resolve, reject) => {
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    const request = http.request(
      `${harness.baseUrl}${path}`,
      {
        method,
        headers: {
          accept: 'application/json, application/problem+json',
          'x-request-id': `raw-${String(method).toUpperCase()}-${path}`,
          ...headers
        }
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          resolve({
            status: response.statusCode || 0,
            headers: response.headers,
            body: raw.length > 0 ? JSON.parse(raw) : {}
          });
        });
      }
    );

    request.on('error', reject);
    if (payload.length > 0) {
      request.write(payload);
    }
    request.end();
  });

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
      'content-type': response.headers.get('content-type') || '',
      'retry-after': response.headers.get('retry-after') || '',
      'x-ratelimit-limit': response.headers.get('x-ratelimit-limit') || '',
      'x-ratelimit-remaining': response.headers.get('x-ratelimit-remaining') || '',
      'x-ratelimit-reset': response.headers.get('x-ratelimit-reset') || ''
    },
    body: payload
  };
};

test('otp send (express) returns server countdown hint and no otp leak', async () => {
  const harness = await createExpressHarness();
  try {
    const response = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/send',
      body: { phone: '13800000000' }
    });

    assert.equal(response.status, 200);
    assert.equal(response.body.sent, true);
    assert.equal(response.body.resend_after_seconds, 60);
    assert.equal('otp_code' in response.body, false);
  } finally {
    await harness.close();
  }
});

test('otp send within cooldown returns 429 rate-limit with remaining seconds', async () => {
  const harness = await createExpressHarness();
  const startTime = Date.now();
  harness.setNow(startTime);

  try {
    const firstSend = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/send',
      body: { phone: '13800000000' }
    });
    assert.equal(firstSend.status, 200);
    assert.equal(firstSend.body.sent, true);
    assert.equal(firstSend.body.resend_after_seconds, 60);

    harness.setNow(startTime + 30 * 1000);

    const secondSend = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/send',
      body: { phone: '13800000000' }
    });
    assert.equal(secondSend.status, 429);
    assert.equal(secondSend.body.error_code, 'AUTH-429-RATE-LIMITED');
    assert.equal(secondSend.body.rate_limit_action, 'otp_send');
    assert.ok(secondSend.body.retry_after_seconds > 0);
    assert.ok(secondSend.body.retry_after_seconds <= 30);
    assert.equal(secondSend.headers['retry-after'], String(secondSend.body.retry_after_seconds));
    assert.equal(secondSend.headers['x-ratelimit-limit'], '1');
    assert.equal(secondSend.headers['x-ratelimit-remaining'], '0');
    assert.equal(secondSend.headers['x-ratelimit-reset'], String(secondSend.body.retry_after_seconds));

    harness.setNow(startTime + 61 * 1000);

    const thirdSend = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/send',
      body: { phone: '13800000000' }
    });
    assert.equal(thirdSend.status, 200);
    assert.equal(thirdSend.body.sent, true);
    assert.equal(thirdSend.body.resend_after_seconds, 60);
  } finally {
    await harness.close();
  }
});

test('otp send repeated retries during cooldown do not consume post-cooldown window', async () => {
  const harness = await createExpressHarness();
  const startTime = Date.now();
  harness.setNow(startTime);

  try {
    const firstSend = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/send',
      body: { phone: '13800000000' }
    });
    assert.equal(firstSend.status, 200);

    for (let attempt = 0; attempt < 12; attempt += 1) {
      harness.setNow(startTime + 5 * 1000 + attempt * 50);
      const retry = await invokeRoute(harness, {
        method: 'post',
        path: '/auth/otp/send',
        body: { phone: '13800000000' }
      });
      assert.equal(retry.status, 429);
      assert.equal(retry.body.error_code, 'AUTH-429-RATE-LIMITED');
      assert.equal(retry.body.rate_limit_action, 'otp_send');
    }

    harness.setNow(startTime + 61 * 1000);
    const recovered = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/send',
      body: { phone: '13800000000' }
    });
    assert.equal(recovered.status, 200);
    assert.equal(recovered.body.sent, true);
  } finally {
    await harness.close();
  }
});

test('json body parser rejects oversized payload with 413 problem details', async () => {
  const harness = await createExpressHarness({
    API_JSON_BODY_LIMIT_BYTES: '256'
  });
  try {
    const response = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: {
        phone: '13800000000',
        password: 'x'.repeat(512)
      }
    });

    assert.equal(response.status, 413);
    assert.equal(response.headers['content-type'].includes('application/problem+json'), true);
    assert.equal(response.body.error_code, 'AUTH-413-PAYLOAD-TOO-LARGE');
  } finally {
    await harness.close();
  }
});

test('json body parser returns 413 for oversized refresh and change-password payloads', async () => {
  const harness = await createExpressHarness({
    API_JSON_BODY_LIMIT_BYTES: '256'
  });
  try {
    const refreshResponse = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/refresh',
      body: {
        refresh_token: 'x'.repeat(1024)
      }
    });
    assert.equal(refreshResponse.status, 413);
    assert.equal(
      refreshResponse.headers['content-type'].includes('application/problem+json'),
      true
    );
    assert.equal(refreshResponse.body.error_code, 'AUTH-413-PAYLOAD-TOO-LARGE');

    const changePasswordResponse = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/change-password',
      headers: {
        authorization: 'Bearer any-token'
      },
      body: {
        current_password: 'Passw0rd!',
        new_password: 'x'.repeat(1024)
      }
    });
    assert.equal(changePasswordResponse.status, 413);
    assert.equal(
      changePasswordResponse.headers['content-type'].includes('application/problem+json'),
      true
    );
    assert.equal(changePasswordResponse.body.error_code, 'AUTH-413-PAYLOAD-TOO-LARGE');
  } finally {
    await harness.close();
  }
});

test('oversized payload actively closes connection to avoid lingering upload sockets', async () => {
  const harness = await createExpressHarness({
    API_JSON_BODY_LIMIT_BYTES: '256'
  });
  try {
    const response = await invokeRawRoute(harness, {
      method: 'POST',
      path: '/auth/login',
      headers: {
        'content-type': 'application/json',
        'content-length': String(
          Buffer.byteLength(
            JSON.stringify({
              phone: '13800000000',
              password: 'x'.repeat(1024)
            })
          )
        )
      },
      body: JSON.stringify({
        phone: '13800000000',
        password: 'x'.repeat(1024)
      })
    });

    assert.equal(response.status, 413);
    assert.equal(response.body.error_code, 'AUTH-413-PAYLOAD-TOO-LARGE');
    assert.equal(String(response.headers.connection || '').toLowerCase(), 'close');
  } finally {
    await harness.close();
  }
});

test('otp login (express) succeeds once and blocks reuse with unified semantics', async () => {
  const harness = await createExpressHarness();
  try {
    const sent = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/send',
      body: { phone: '13800000000' }
    });
    assert.equal(sent.status, 200);

    const otpCode = harness.getCode('13800000000');
    assert.ok(otpCode);

    const login = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/login',
      body: { phone: '13800000000', otp_code: otpCode }
    });
    assert.equal(login.status, 200);
    assert.ok(login.body.access_token);

    const reused = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/login',
      body: { phone: '13800000000', otp_code: otpCode }
    });
    assert.equal(reused.status, 401);
    assert.equal(reused.body.error_code, 'AUTH-401-OTP-FAILED');
  } finally {
    await harness.close();
  }
});

test('otp login (express) allows exactly one success under concurrent reuse', async () => {
  const harness = await createExpressHarness();
  try {
    const sent = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/send',
      body: { phone: '13800000000' }
    });
    assert.equal(sent.status, 200);

    const otpCode = harness.getCode('13800000000');
    assert.ok(otpCode);

    const attempts = await Promise.all([
      invokeRoute(harness, {
        method: 'post',
        path: '/auth/otp/login',
        body: { phone: '13800000000', otp_code: otpCode }
      }),
      invokeRoute(harness, {
        method: 'post',
        path: '/auth/otp/login',
        body: { phone: '13800000000', otp_code: otpCode }
      })
    ]);

    const successCount = attempts.filter((result) => result.status === 200).length;
    const failed = attempts.find((result) => result.status !== 200);

    assert.equal(successCount, 1);
    assert.ok(failed);
    assert.equal(failed.status, 401);
    assert.equal(failed.body.error_code, 'AUTH-401-OTP-FAILED');
  } finally {
    await harness.close();
  }
});

test('otp login (express) rejects invalid and expired code with unified semantics', async () => {
  const harness = await createExpressHarness();
  try {
    await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/send',
      body: { phone: '13800000000' }
    });
    const otpCode = harness.getCode('13800000000');

    const wrong = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/login',
      body: { phone: '13800000000', otp_code: '000000' }
    });
    assert.equal(wrong.status, 401);
    assert.equal(wrong.body.error_code, 'AUTH-401-OTP-FAILED');

    harness.setNow(Date.now() + 16 * 60 * 1000);
    const expired = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/login',
      body: { phone: '13800000000', otp_code: otpCode }
    });
    assert.equal(expired.status, 401);
    assert.equal(expired.body.error_code, 'AUTH-401-OTP-FAILED');
  } finally {
    await harness.close();
  }
});

test('otp_send cooldown limit does not pollute password_login and otp_login actions', async () => {
  const harness = await createExpressHarness();
  try {
    const firstSend = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/send',
      body: { phone: '13800000000' }
    });
    assert.equal(firstSend.status, 200);
    const otpCode = harness.getCode('13800000000');
    assert.ok(otpCode);

    const limitedOtpSend = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/send',
      body: { phone: '13800000000' }
    });
    assert.equal(limitedOtpSend.status, 429);
    assert.equal(limitedOtpSend.body.error_code, 'AUTH-429-RATE-LIMITED');
    assert.equal(limitedOtpSend.body.rate_limit_action, 'otp_send');
    assert.equal(limitedOtpSend.headers['x-ratelimit-limit'], '1');

    const passwordLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/login',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    });
    assert.equal(passwordLogin.status, 200);

    const otpLogin = await invokeRoute(harness, {
      method: 'post',
      path: '/auth/otp/login',
      body: { phone: '13800000000', otp_code: otpCode }
    });
    assert.equal(otpLogin.status, 200);
  } finally {
    await harness.close();
  }
});

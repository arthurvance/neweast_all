const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const Redis = require('ioredis');
const { createApiApp } = require('../src/app');
const { readConfig } = require('../src/config/env');
const { createAuthService } = require('../src/modules/auth/auth.service');
const { createRedisOtpStore } = require('../src/modules/auth/auth.otp.store.redis');
const { createRedisRateLimitStore } = require('../src/modules/auth/auth.rate-limit.redis');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
const dependencyProbe = async () => ({
  db: { ok: true, detail: 'db ok' },
  redis: { ok: true, detail: 'redis ok' }
});

const REDIS_HOST = process.env.AUTH_TEST_REDIS_HOST || process.env.REDIS_HOST || '127.0.0.1';
const REDIS_PORT = Number(process.env.AUTH_TEST_REDIS_PORT || process.env.REDIS_PORT || 6379);

const seedUsers = [
  {
    id: 'otp-redis-user-active',
    phone: '13800000000',
    password: 'Passw0rd!',
    status: 'active'
  }
];

let redisClient = null;
let redisReady = false;
let redisSkipReason = 'Redis unavailable';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const connectWithRetry = async () => {
  const maxAttempts = 6;
  let lastError = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const candidate = new Redis({
      host: REDIS_HOST,
      port: REDIS_PORT,
      connectTimeout: 1200,
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      enableReadyCheck: false
    });
    candidate.on('error', () => {});
    try {
      await candidate.connect();
      await candidate.ping();
      return candidate;
    } catch (error) {
      lastError = error;
      candidate.disconnect();
      await sleep(300 * attempt);
    }
  }

  throw lastError || new Error('redis connection failed');
};

before(async () => {
  try {
    redisClient = await connectWithRetry();
    redisClient.on('error', () => {});
    redisReady = true;
  } catch (error) {
    redisReady = false;
    redisSkipReason = `Redis integration unavailable: ${error.message}`;
  }
});

after(async () => {
  if (!redisClient) {
    return;
  }

  if (redisClient.status === 'ready' || redisClient.status === 'connect') {
    await redisClient.quit();
    return;
  }
  redisClient.disconnect();
});

const requireRedisOrReady = () => {
  if (!redisReady) {
    assert.fail(
      `${redisSkipReason}. Redis backend must be available for otp redis integration tests.`
    );
    return false;
  }
  return true;
};

const createRedisHttpHarness = async () => {
  const prefix = `test:auth-otp:${randomUUID()}`;
  const codesByPhone = new Map();
  const otpStore = createRedisOtpStore({
    redis: redisClient,
    keyPrefix: `${prefix}:otp`
  });
  const rateLimitStore = createRedisRateLimitStore({
    redis: redisClient,
    keyPrefix: `${prefix}:rate`
  });

  const authService = createAuthService({
    seedUsers,
    otpStore: {
      upsertOtp: async ({ phone, code, expiresAt }) => {
        codesByPhone.set(String(phone), String(code));
        return otpStore.upsertOtp({ phone, code, expiresAt });
      },
      getSentAt: otpStore.getSentAt,
      verifyAndConsumeOtp: otpStore.verifyAndConsumeOtp
    },
    rateLimitStore
  });

  const app = await createApiApp(config, {
    dependencyProbe,
    authService
  });
  await app.init();
  await app.listen(0, '127.0.0.1');
  const address = app.getHttpServer().address();
  const port = typeof address === 'object' && address ? address.port : 0;

  return {
    app,
    baseUrl: `http://127.0.0.1:${port}`,
    getCode: (phone) => codesByPhone.get(String(phone)),
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

const invokeRoute = async (harness, { path, method = 'GET', body, headers = {} }) => {
  const normalizedMethod = String(method || 'GET').toUpperCase();
  const requestHeaders = {
    Accept: 'application/json, application/problem+json',
    'x-request-id': `redis-http-${normalizedMethod}-${path}`,
    ...headers
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

test('redis-backed otp api enforces one-time consume', async () => {
  if (!requireRedisOrReady()) {
    return;
  }

  const harness = await createRedisHttpHarness();

  try {
    const sent = await invokeRoute(harness, {
      path: '/auth/otp/send',
      method: 'POST',
      body: { phone: '13800000000' }
    });
    assert.equal(sent.status, 200);
    assert.equal(sent.body.resend_after_seconds, 60);

    const otpCode = harness.getCode('13800000000');
    assert.ok(otpCode);

    const first = await invokeRoute(harness, {
      path: '/auth/otp/login',
      method: 'POST',
      body: { phone: '13800000000', otp_code: otpCode }
    });
    assert.equal(first.status, 200);
    assert.ok(first.body.access_token);

    const second = await invokeRoute(harness, {
      path: '/auth/otp/login',
      method: 'POST',
      body: { phone: '13800000000', otp_code: otpCode }
    });
    assert.equal(second.status, 401);
    assert.equal(second.body.error_code, 'AUTH-401-OTP-FAILED');
  } finally {
    await harness.close();
  }
});

test('redis-backed otp login allows exactly one success under concurrent reuse', async () => {
  if (!requireRedisOrReady()) {
    return;
  }

  const harness = await createRedisHttpHarness();
  try {
    const sent = await invokeRoute(harness, {
      path: '/auth/otp/send',
      method: 'POST',
      body: { phone: '13800000000' }
    });
    assert.equal(sent.status, 200);

    const otpCode = harness.getCode('13800000000');
    assert.ok(otpCode);

    const attempts = await Promise.all([
      invokeRoute(harness, {
        path: '/auth/otp/login',
        method: 'POST',
        body: { phone: '13800000000', otp_code: otpCode }
      }),
      invokeRoute(harness, {
        path: '/auth/otp/login',
        method: 'POST',
        body: { phone: '13800000000', otp_code: otpCode }
      })
    ]);

    const successCount = attempts.filter((result) => result.status === 200).length;
    const failure = attempts.find((result) => result.status !== 200);

    assert.equal(successCount, 1);
    assert.ok(failure);
    assert.equal(failure.status, 401);
    assert.equal(failure.body.error_code, 'AUTH-401-OTP-FAILED');
  } finally {
    await harness.close();
  }
});

test('redis-backed otp cooldown limit does not pollute password_login and otp_login', async () => {
  if (!requireRedisOrReady()) {
    return;
  }

  const harness = await createRedisHttpHarness();
  try {
    const sent = await invokeRoute(harness, {
      path: '/auth/otp/send',
      method: 'POST',
      body: { phone: '13800000000' }
    });
    assert.equal(sent.status, 200);
    const otpCode = harness.getCode('13800000000');
    assert.ok(otpCode);

    const limited = await invokeRoute(harness, {
      path: '/auth/otp/send',
      method: 'POST',
      body: { phone: '13800000000' }
    });
    assert.equal(limited.status, 429);
    assert.equal(limited.body.error_code, 'AUTH-429-RATE-LIMITED');
    assert.equal(limited.body.rate_limit_action, 'otp_send');
    assert.equal(limited.headers['retry-after'], String(limited.body.retry_after_seconds));
    assert.equal(limited.headers['x-ratelimit-limit'], '1');
    assert.equal(limited.headers['x-ratelimit-remaining'], '0');
    assert.equal(limited.headers['x-ratelimit-reset'], String(limited.body.retry_after_seconds));

    const passwordLogin = await invokeRoute(harness, {
      path: '/auth/login',
      method: 'POST',
      body: { phone: '13800000000', password: 'Passw0rd!' }
    });
    assert.equal(passwordLogin.status, 200);

    const otpLogin = await invokeRoute(harness, {
      path: '/auth/otp/login',
      method: 'POST',
      body: { phone: '13800000000', otp_code: otpCode }
    });
    assert.equal(otpLogin.status, 200);
  } finally {
    await harness.close();
  }
});

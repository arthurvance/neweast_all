const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const Redis = require('ioredis');
const {
  createRedisAuthIdempotencyStore
} = require('../src/modules/auth/auth.idempotency.redis');

const REDIS_HOST = process.env.AUTH_TEST_REDIS_HOST || process.env.REDIS_HOST || '127.0.0.1';
const REDIS_PORT = Number(process.env.AUTH_TEST_REDIS_PORT || process.env.REDIS_PORT || 6379);

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

const requireRedisReady = () => {
  if (!redisReady) {
    assert.fail(
      `${redisSkipReason}. Redis backend must be available for idempotency redis tests.`
    );
    return false;
  }
  return true;
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

test('redis idempotency store shares replay state across store instances', async () => {
  if (!requireRedisReady()) {
    return;
  }

  const keyPrefix = `test:auth-idempotency:${randomUUID()}`;
  const storeA = createRedisAuthIdempotencyStore({
    redis: redisClient,
    keyPrefix
  });
  const storeB = createRedisAuthIdempotencyStore({
    redis: redisClient,
    keyPrefix
  });
  const scopeWindowKey = 'POST /auth/platform/member-admin/provision-user:scope-a';
  const scopeKey = `${scopeWindowKey}:idem-key-a`;
  const requestHash = 'request-hash-a';

  const claimed = await storeA.claimOrRead({
    scopeKey,
    scopeWindowKey,
    requestHash,
    pendingToken: 'pending-token-a'
  });
  assert.equal(claimed.action, 'claimed');

  const resolved = await storeA.resolve({
    scopeKey,
    scopeWindowKey,
    pendingToken: 'pending-token-a',
    requestHash,
    response: {
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ok: true })
    }
  });
  assert.equal(resolved, true);

  const replay = await storeB.claimOrRead({
    scopeKey,
    scopeWindowKey,
    requestHash,
    pendingToken: 'pending-token-b'
  });
  assert.equal(replay.action, 'existing');
  assert.equal(replay.entry.state, 'resolved');
  assert.equal(replay.entry.requestHash, requestHash);
  assert.equal(replay.entry.response.status, 200);
  assert.deepEqual(replay.entry.response.headers, {
    'content-type': 'application/json'
  });
  assert.equal(replay.entry.response.body, JSON.stringify({ ok: true }));
});

test('redis idempotency store evicts oldest entry when scope entry count exceeds max', async () => {
  if (!requireRedisReady()) {
    return;
  }

  const keyPrefix = `test:auth-idempotency-evict:${randomUUID()}`;
  const store = createRedisAuthIdempotencyStore({
    redis: redisClient,
    keyPrefix,
    replayTtlMs: 60 * 1000,
    pendingTtlMs: 5 * 1000,
    maxEntriesPerScope: 2
  });
  const scopeWindowKey = 'POST /auth/platform/role-facts/replace:scope-b';

  const claimAndResolve = async (suffix) => {
    const scopeKey = `${scopeWindowKey}:${suffix}`;
    const requestHash = `request-hash-${suffix}`;
    const pendingToken = `pending-token-${suffix}`;

    const claimed = await store.claimOrRead({
      scopeKey,
      scopeWindowKey,
      requestHash,
      pendingToken
    });
    assert.equal(claimed.action, 'claimed');

    const resolved = await store.resolve({
      scopeKey,
      scopeWindowKey,
      pendingToken,
      requestHash,
      response: {
        status: 200,
        headers: {},
        body: JSON.stringify({ suffix })
      }
    });
    assert.equal(resolved, true);
  };

  await claimAndResolve('k1');
  await sleep(5);
  await claimAndResolve('k2');
  await sleep(5);
  await claimAndResolve('k3');

  const replayEvictedOldest = await store.claimOrRead({
    scopeKey: `${scopeWindowKey}:k1`,
    scopeWindowKey,
    requestHash: 'request-hash-k1',
    pendingToken: 'pending-token-k1-retry'
  });
  assert.equal(replayEvictedOldest.action, 'claimed');
});

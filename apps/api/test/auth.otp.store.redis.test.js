const test = require('node:test');
const assert = require('node:assert/strict');
const { createRedisOtpStore } = require('../src/modules/auth/auth.otp.store.redis');

test('redis otp upsert uses one atomic eval script with ttl', async () => {
  const calls = [];
  const redis = {
    eval: async (...args) => {
      calls.push(args);
      return 'ok';
    }
  };
  const store = createRedisOtpStore({ redis, keyPrefix: 'test:otp' });
  const expiresAt = Date.now() + 15 * 60 * 1000;

  await store.upsertOtp({
    phone: '13800000000',
    code: '123456',
    expiresAt
  });

  assert.equal(calls.length, 1);
  const [script, keyCount, key, codeHash, expiresAtMs, ttlMs] = calls[0];

  assert.equal(Number(keyCount), 1);
  assert.equal(key, 'test:otp:13800000000');
  assert.match(String(script), /HSET/);
  assert.match(String(script), /PEXPIRE/);
  assert.match(String(script), /HDEL/);
  assert.match(String(codeHash), /^[a-f0-9]{64}$/);
  assert.equal(Number(expiresAtMs), expiresAt);
  assert.ok(Number(ttlMs) >= 1000);
});

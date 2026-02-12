const { createHash } = require('node:crypto');

const OTP_VERIFY_AND_CONSUME_SCRIPT = `
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local expected_hash = ARGV[2]

local fields = redis.call('HMGET', key, 'code_hash', 'expires_at_ms', 'consumed')
local code_hash = fields[1]
local expires_at_ms = tonumber(fields[2] or '0')
local consumed = fields[3]

if not code_hash then
  return 'missing'
end

if consumed == '1' then
  return 'used'
end

if expires_at_ms <= now_ms then
  return 'expired'
end

if code_hash ~= expected_hash then
  return 'mismatch'
end

redis.call('HSET', key, 'consumed', '1', 'consumed_at_ms', tostring(now_ms))
redis.call('PEXPIRE', key, math.max(60000, expires_at_ms - now_ms + 60000))
return 'ok'
`;

const OTP_UPSERT_SCRIPT = `
local key = KEYS[1]
local code_hash = ARGV[1]
local expires_at_ms = ARGV[2]
local ttl_ms = tonumber(ARGV[3])
local sent_at_ms = ARGV[4]

redis.call('HSET', key, 'code_hash', code_hash, 'expires_at_ms', expires_at_ms, 'consumed', '0', 'sent_at_ms', sent_at_ms)
redis.call('HDEL', key, 'consumed_at_ms')
redis.call('PEXPIRE', key, ttl_ms)
return 'ok'
`;

const OTP_GET_SENT_AT_SCRIPT = `
local key = KEYS[1]
local sent_at_ms = redis.call('HGET', key, 'sent_at_ms')
if not sent_at_ms then
  return nil
end
return sent_at_ms
`;

const hashOtpCode = (code) => createHash('sha256').update(String(code)).digest('hex');

const createRedisOtpStore = ({ redis, keyPrefix = 'auth:otp' }) => {
  if (!redis || typeof redis.eval !== 'function') {
    throw new Error('createRedisOtpStore requires redis client with eval');
  }

  const keyOf = (phone) => `${keyPrefix}:${String(phone)}`;

  return {
    upsertOtp: async ({ phone, code, expiresAt }) => {
      const nowMs = Date.now();
      const ttlMs = Math.max(1000, Number(expiresAt) - nowMs + 60000);
      const key = keyOf(phone);
      await redis.eval(
        OTP_UPSERT_SCRIPT,
        1,
        key,
        hashOtpCode(code),
        String(Number(expiresAt)),
        String(ttlMs),
        String(nowMs)
      );
      return { sent_at_ms: nowMs };
    },

    getSentAt: async ({ phone }) => {
      const result = await redis.eval(
        OTP_GET_SENT_AT_SCRIPT,
        1,
        keyOf(phone)
      );
      return result ? Number(result) : null;
    },

    verifyAndConsumeOtp: async ({ phone, code, nowMs }) => {
      const result = await redis.eval(
        OTP_VERIFY_AND_CONSUME_SCRIPT,
        1,
        keyOf(phone),
        String(Number(nowMs)),
        hashOtpCode(code)
      );

      return {
        ok: result === 'ok',
        reason: String(result || 'unknown')
      };
    }
  };
};

module.exports = { createRedisOtpStore };

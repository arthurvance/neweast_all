const RATE_LIMIT_CONSUME_SCRIPT = `
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now_ms - window_ms)
redis.call('ZADD', key, now_ms, member)
local count = redis.call('ZCARD', key)
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local oldest_score = now_ms

if oldest[2] then
  oldest_score = tonumber(oldest[2])
end

local remaining_ms = math.max(0, oldest_score + window_ms - now_ms)
local remaining_seconds = math.max(1, math.ceil(remaining_ms / 1000))
redis.call('PEXPIRE', key, window_ms)

if count > limit then
  return {0, count, remaining_seconds}
end
return {1, count, remaining_seconds}
`;

const createRedisRateLimitStore = ({ redis, keyPrefix = 'auth:rate-limit' }) => {
  if (!redis || typeof redis.eval !== 'function') {
    throw new Error('createRedisRateLimitStore requires redis client with eval');
  }

  const keyOf = (phone, action) => `${keyPrefix}:${String(action)}:${String(phone)}`;

  return {
    consume: async ({ phone, action, limit, windowSeconds, nowMs }) => {
      const member = `${String(nowMs)}-${Math.random().toString(16).slice(2)}`;
      const [allowedRaw, countRaw, remainingRaw] = await redis.eval(
        RATE_LIMIT_CONSUME_SCRIPT,
        1,
        keyOf(phone, action),
        String(Number(nowMs)),
        String(Number(windowSeconds) * 1000),
        String(Number(limit)),
        member
      );

      return {
        allowed: Number(allowedRaw) === 1,
        count: Number(countRaw),
        remainingSeconds: Math.max(1, Number(remainingRaw))
      };
    }
  };
};

module.exports = { createRedisRateLimitStore };

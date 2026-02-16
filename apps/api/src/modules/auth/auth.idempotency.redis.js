const { createHash } = require('node:crypto');

const CLAIM_OR_READ_SCRIPT = `
local entry_key = KEYS[1]
local scope_index_key = KEYS[2]
local now_ms = tonumber(ARGV[1])
local replay_ttl_ms = tonumber(ARGV[2])
local pending_ttl_ms = tonumber(ARGV[3])
local max_entries_per_scope = tonumber(ARGV[4])
local pending_payload = ARGV[5]

local existing = redis.call('GET', entry_key)
if existing then
  return {0, existing}
end

redis.call('ZREMRANGEBYSCORE', scope_index_key, 0, now_ms)

if max_entries_per_scope > 0 then
  local current_count = redis.call('ZCARD', scope_index_key)
  if current_count >= max_entries_per_scope then
    local evict_count = current_count - max_entries_per_scope + 1
    local victims = redis.call('ZRANGE', scope_index_key, 0, evict_count - 1)
    for _, victim_key in ipairs(victims) do
      redis.call('DEL', victim_key)
      redis.call('ZREM', scope_index_key, victim_key)
    end
  end
end

local claimed = redis.call('SET', entry_key, pending_payload, 'PX', pending_ttl_ms, 'NX')
if claimed then
  redis.call('ZADD', scope_index_key, now_ms + pending_ttl_ms, entry_key)
  redis.call('PEXPIRE', scope_index_key, replay_ttl_ms)
  return {1, ''}
end

local after_claim = redis.call('GET', entry_key)
if after_claim then
  return {0, after_claim}
end

return {2, ''}
`;

const RESOLVE_SCRIPT = `
local entry_key = KEYS[1]
local scope_index_key = KEYS[2]
local now_ms = tonumber(ARGV[1])
local replay_ttl_ms = tonumber(ARGV[2])
local pending_token = ARGV[3]
local request_hash = ARGV[4]
local resolved_payload = ARGV[5]

local raw = redis.call('GET', entry_key)
if not raw then
  return 0
end

local ok, decoded = pcall(cjson.decode, raw)
if not ok then
  return -1
end

if decoded['state'] ~= 'pending' then
  return 1
end

if decoded['pending_token'] ~= pending_token or decoded['request_hash'] ~= request_hash then
  return 0
end

redis.call('SET', entry_key, resolved_payload, 'PX', replay_ttl_ms)
redis.call('ZADD', scope_index_key, now_ms + replay_ttl_ms, entry_key)
redis.call('PEXPIRE', scope_index_key, replay_ttl_ms)
return 1
`;

const RELEASE_PENDING_SCRIPT = `
local entry_key = KEYS[1]
local scope_index_key = KEYS[2]
local pending_token = ARGV[1]
local request_hash = ARGV[2]

local raw = redis.call('GET', entry_key)
if not raw then
  redis.call('ZREM', scope_index_key, entry_key)
  return 1
end

local ok, decoded = pcall(cjson.decode, raw)
if not ok then
  return 0
end

if decoded['state'] == 'pending'
  and decoded['pending_token'] == pending_token
  and decoded['request_hash'] == request_hash then
  redis.call('DEL', entry_key)
  redis.call('ZREM', scope_index_key, entry_key)
  return 1
end

return 0
`;

const DEFAULT_REPLAY_TTL_MS = 10 * 60 * 1000;
const DEFAULT_PENDING_TTL_MS = 30 * 1000;
const DEFAULT_MAX_ENTRIES_PER_SCOPE = 1000;

const asPositiveInteger = (value, fallback) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.ceil(parsed);
};

const asNonNegativeInteger = (value, fallback) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }
  return Math.floor(parsed);
};

const hashKey = (value) =>
  createHash('sha256').update(String(value || '')).digest('hex');

const parseEntry = (raw) => {
  if (typeof raw !== 'string' || raw.length === 0) {
    return null;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (_error) {
    return null;
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return null;
  }

  const state = String(parsed.state || '').trim().toLowerCase();
  const requestHash = String(parsed.request_hash || '').trim();
  if (!requestHash) {
    return null;
  }

  if (state === 'pending') {
    const pendingToken = String(parsed.pending_token || '').trim();
    if (!pendingToken) {
      return null;
    }
    return {
      state: 'pending',
      requestHash,
      pendingToken
    };
  }

  if (state !== 'resolved') {
    return null;
  }

  const response = parsed.response;
  if (!response || typeof response !== 'object' || Array.isArray(response)) {
    return null;
  }

  return {
    state: 'resolved',
    requestHash,
    response: {
      status: Number(response.status),
      headers:
        response.headers && typeof response.headers === 'object' && !Array.isArray(response.headers)
          ? { ...response.headers }
          : {},
      body: String(response.body ?? '')
    }
  };
};

const createRedisAuthIdempotencyStore = ({
  redis,
  keyPrefix = 'auth:idempotency',
  replayTtlMs = DEFAULT_REPLAY_TTL_MS,
  pendingTtlMs = DEFAULT_PENDING_TTL_MS,
  maxEntriesPerScope = DEFAULT_MAX_ENTRIES_PER_SCOPE
}) => {
  if (
    !redis
    || typeof redis.eval !== 'function'
    || typeof redis.get !== 'function'
  ) {
    throw new Error(
      'createRedisAuthIdempotencyStore requires redis client with eval/get'
    );
  }

  const resolvedReplayTtlMs = asPositiveInteger(replayTtlMs, DEFAULT_REPLAY_TTL_MS);
  const resolvedPendingTtlMs = Math.min(
    resolvedReplayTtlMs,
    asPositiveInteger(pendingTtlMs, DEFAULT_PENDING_TTL_MS)
  );
  const resolvedMaxEntriesPerScope = asNonNegativeInteger(
    maxEntriesPerScope,
    DEFAULT_MAX_ENTRIES_PER_SCOPE
  );
  const normalizedPrefix = String(keyPrefix || 'auth:idempotency').trim() || 'auth:idempotency';

  const toEntryKey = (scopeKey) => `${normalizedPrefix}:entry:${hashKey(scopeKey)}`;
  const toScopeIndexKey = (scopeWindowKey) =>
    `${normalizedPrefix}:scope:${hashKey(scopeWindowKey)}`;

  return {
    claimOrRead: async ({
      scopeKey,
      scopeWindowKey,
      requestHash,
      pendingToken,
      nowMs = Date.now()
    }) => {
      const entryKey = toEntryKey(scopeKey);
      const scopeIndexKey = toScopeIndexKey(scopeWindowKey);
      const pendingPayload = JSON.stringify({
        state: 'pending',
        request_hash: String(requestHash || ''),
        pending_token: String(pendingToken || '')
      });

      const [statusRaw, payloadRaw] = await redis.eval(
        CLAIM_OR_READ_SCRIPT,
        2,
        entryKey,
        scopeIndexKey,
        String(Number(nowMs)),
        String(resolvedReplayTtlMs),
        String(resolvedPendingTtlMs),
        String(resolvedMaxEntriesPerScope),
        pendingPayload
      );

      const status = Number(statusRaw);
      if (status === 1) {
        return { action: 'claimed' };
      }

      if (status === 0) {
        return { action: 'existing', entry: parseEntry(String(payloadRaw || '')) };
      }

      const fallbackRaw = await redis.get(entryKey);
      return {
        action: fallbackRaw ? 'existing' : 'retry',
        entry: parseEntry(String(fallbackRaw || ''))
      };
    },

    read: async ({ scopeKey }) => {
      const raw = await redis.get(toEntryKey(scopeKey));
      return parseEntry(String(raw || ''));
    },

    resolve: async ({
      scopeKey,
      scopeWindowKey,
      pendingToken,
      requestHash,
      response,
      nowMs = Date.now()
    }) => {
      const entryKey = toEntryKey(scopeKey);
      const scopeIndexKey = toScopeIndexKey(scopeWindowKey);
      const resolvedPayload = JSON.stringify({
        state: 'resolved',
        request_hash: String(requestHash || ''),
        response: {
          status: Number(response?.status),
          headers:
            response?.headers
            && typeof response.headers === 'object'
            && !Array.isArray(response.headers)
              ? { ...response.headers }
              : {},
          body: String(response?.body ?? '')
        }
      });

      const resultRaw = await redis.eval(
        RESOLVE_SCRIPT,
        2,
        entryKey,
        scopeIndexKey,
        String(Number(nowMs)),
        String(resolvedReplayTtlMs),
        String(pendingToken || ''),
        String(requestHash || ''),
        resolvedPayload
      );
      return Number(resultRaw) === 1;
    },

    releasePending: async ({
      scopeKey,
      scopeWindowKey,
      pendingToken,
      requestHash
    }) => {
      const resultRaw = await redis.eval(
        RELEASE_PENDING_SCRIPT,
        2,
        toEntryKey(scopeKey),
        toScopeIndexKey(scopeWindowKey),
        String(pendingToken || ''),
        String(requestHash || '')
      );
      return Number(resultRaw) === 1;
    }
  };
};

module.exports = {
  createRedisAuthIdempotencyStore
};

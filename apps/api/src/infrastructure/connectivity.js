const Redis = require('ioredis');
const { log } = require('../common/logger');
const { connectMySql } = require('./mysql-client');

const checkMySql = async (config) => {
  const client = await connectMySql({
    host: config.DB_HOST,
    port: config.DB_PORT,
    user: config.DB_USER,
    password: config.DB_PASSWORD,
    database: config.DB_NAME,
    connectTimeoutMs: config.DB_CONNECT_TIMEOUT_MS
  });

  try {
    await client.ping();
    await client.query('SELECT 1');
    return { ok: true, mode: 'mysql-native', detail: 'connected' };
  } finally {
    await client.close();
  }
};

const checkRedis = async (config) => {
  const redis = new Redis({
    host: config.REDIS_HOST,
    port: config.REDIS_PORT,
    connectTimeout: config.REDIS_CONNECT_TIMEOUT_MS,
    lazyConnect: true,
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
    enableReadyCheck: false
  });

  try {
    await redis.connect();
    const pong = await redis.ping();
    return { ok: pong === 'PONG', mode: 'ioredis', detail: pong };
  } finally {
    if (redis.status === 'ready' || redis.status === 'connect') {
      await redis.quit();
    } else {
      redis.disconnect();
    }
  }
};

const checkDependencies = async (config, requestId = 'request_id_unset') => {
  if (config.ALLOW_MOCK_BACKENDS) {
    return {
      db: { ok: true, mode: 'mock', detail: 'mocked by ALLOW_MOCK_BACKENDS' },
      redis: { ok: true, mode: 'mock', detail: 'mocked by ALLOW_MOCK_BACKENDS' }
    };
  }

  const [dbResult, redisResult] = await Promise.allSettled([
    checkMySql(config),
    checkRedis(config)
  ]);

  const db =
    dbResult.status === 'fulfilled'
      ? dbResult.value
      : { ok: false, mode: 'mysql-native', detail: dbResult.reason.message };

  const redis =
    redisResult.status === 'fulfilled'
      ? redisResult.value
      : { ok: false, mode: 'ioredis', detail: redisResult.reason.message };

  if (!db.ok) {
    log('error', 'Database connectivity check failed', {
      request_id: requestId,
      dependency: 'mysql',
      detail: db.detail
    });
  }

  if (!redis.ok) {
    log('error', 'Redis connectivity check failed', {
      request_id: requestId,
      dependency: 'redis',
      detail: redis.detail
    });
  }

  return { db, redis };
};

module.exports = { checkDependencies };

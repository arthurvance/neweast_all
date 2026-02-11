const asNumber = (value, fallback) => {
  const parsed = Number(value ?? fallback);
  if (Number.isNaN(parsed)) {
    return fallback;
  }
  return parsed;
};

const asBool = (value, fallback) => {
  if (value === undefined || value === null) {
    return fallback;
  }
  return String(value).toLowerCase() === 'true';
};

const readConfig = (env = process.env) => ({
  NODE_ENV: env.NODE_ENV ?? 'development',
  API_HOST: env.API_HOST ?? '0.0.0.0',
  API_PORT: asNumber(env.API_PORT, 3000),
  DB_HOST: env.DB_HOST ?? 'mysql',
  DB_PORT: asNumber(env.DB_PORT, 3306),
  DB_USER: env.DB_USER ?? 'neweast',
  DB_PASSWORD: env.DB_PASSWORD ?? 'neweast',
  DB_NAME: env.DB_NAME ?? 'neweast',
  DB_CONNECT_TIMEOUT_MS: asNumber(env.DB_CONNECT_TIMEOUT_MS, 1500),
  REDIS_HOST: env.REDIS_HOST ?? 'redis',
  REDIS_PORT: asNumber(env.REDIS_PORT, 6379),
  REDIS_CONNECT_TIMEOUT_MS: asNumber(env.REDIS_CONNECT_TIMEOUT_MS, 1200),
  LOG_FORMAT: env.LOG_FORMAT ?? 'json',
  ALLOW_MOCK_BACKENDS: asBool(env.ALLOW_MOCK_BACKENDS, false)
});

module.exports = { readConfig };

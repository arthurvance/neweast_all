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

const DEFAULT_AUTH_DEFAULT_PASSWORD_ENCRYPTED =
  'enc:v1:6rJ33ZxXgkxCHR4E:b94w-yzmcyEsEEG35K5zmg:OW85WJOd';
const DEFAULT_AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY =
  'fc53f83e2ea8525575fe71d404f368498162a3b9b5953c23b19940feed5d1fd9';

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
  AUTH_JWT_PRIVATE_KEY: env.AUTH_JWT_PRIVATE_KEY ?? '',
  AUTH_JWT_PUBLIC_KEY: env.AUTH_JWT_PUBLIC_KEY ?? '',
  AUTH_DEFAULT_PASSWORD_ENCRYPTED:
    env.AUTH_DEFAULT_PASSWORD_ENCRYPTED ?? DEFAULT_AUTH_DEFAULT_PASSWORD_ENCRYPTED,
  AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY:
    env.AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY ?? DEFAULT_AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY,
  AUTH_MULTI_INSTANCE: asBool(env.AUTH_MULTI_INSTANCE, false),
  REDIS_HOST: env.REDIS_HOST ?? 'redis',
  REDIS_PORT: asNumber(env.REDIS_PORT, 6379),
  REDIS_CONNECT_TIMEOUT_MS: asNumber(env.REDIS_CONNECT_TIMEOUT_MS, 1200),
  LOG_FORMAT: env.LOG_FORMAT ?? 'json',
  ALLOW_MOCK_BACKENDS: asBool(env.ALLOW_MOCK_BACKENDS, false),
  API_JSON_BODY_LIMIT_BYTES: asNumber(env.API_JSON_BODY_LIMIT_BYTES, 1024 * 1024),
  API_CORS_ALLOWED_ORIGINS:
    env.API_CORS_ALLOWED_ORIGINS
    ?? (env.NODE_ENV === 'production'
      ? ''
      : 'http://localhost:4173,http://127.0.0.1:4173')
});

module.exports = { readConfig };

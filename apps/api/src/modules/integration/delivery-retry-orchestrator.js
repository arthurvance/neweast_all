const RETRYABLE_HTTP_STATUS = new Set([408, 429]);
const TRANSIENT_NETWORK_ERROR_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'EHOSTUNREACH',
  'ETIMEDOUT',
  'EAI_AGAIN',
  'ENETUNREACH',
  'ECONNABORTED'
]);

const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_BASE_DELAY_MS = 1000;
const DEFAULT_MAX_DELAY_MS = 60000;
const DEFAULT_JITTER_RATIO = 0.2;

const asInteger = (value, fallback) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.floor(parsed);
};

const normalizeAttemptBound = (value, fallback) => {
  const parsed = asInteger(value, fallback);
  if (parsed < 1) {
    return fallback;
  }
  return Math.min(DEFAULT_MAX_ATTEMPTS, parsed);
};

const normalizeDelayBound = (value, fallback, minValue) => {
  const parsed = asInteger(value, fallback);
  if (parsed < minValue) {
    return fallback;
  }
  return parsed;
};

const normalizeJitterRatio = (value) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return DEFAULT_JITTER_RATIO;
  }
  if (parsed < 0) {
    return 0;
  }
  if (parsed > 1) {
    return 1;
  }
  return parsed;
};

const normalizeErrorCode = (value) =>
  String(value || '')
    .trim()
    .toUpperCase();

const isRetryableHttpStatus = (statusCode) => {
  const parsed = Number(statusCode);
  if (!Number.isInteger(parsed)) {
    return false;
  }
  if (RETRYABLE_HTTP_STATUS.has(parsed)) {
    return true;
  }
  return parsed >= 500 && parsed <= 599;
};

const isRetryableNetworkErrorCode = (errorCode) => {
  const normalized = normalizeErrorCode(errorCode);
  return normalized.length > 0 && TRANSIENT_NETWORK_ERROR_CODES.has(normalized);
};

const isRetryableDeliveryFailure = ({
  httpStatus = null,
  errorCode = null,
  networkErrorCode = null
} = {}) =>
  isRetryableHttpStatus(httpStatus)
  || isRetryableNetworkErrorCode(errorCode)
  || isRetryableNetworkErrorCode(networkErrorCode);

const computeExponentialBackoffDelayMs = ({
  retryNumber,
  baseDelayMs = DEFAULT_BASE_DELAY_MS,
  maxDelayMs = DEFAULT_MAX_DELAY_MS,
  jitterRatio = DEFAULT_JITTER_RATIO,
  random = Math.random
} = {}) => {
  const normalizedRetryNumber = Math.max(1, asInteger(retryNumber, 1));
  const normalizedBaseDelayMs = normalizeDelayBound(
    baseDelayMs,
    DEFAULT_BASE_DELAY_MS,
    1
  );
  const normalizedMaxDelayMs = Math.max(
    normalizedBaseDelayMs,
    normalizeDelayBound(maxDelayMs, DEFAULT_MAX_DELAY_MS, 1)
  );
  const normalizedJitterRatio = normalizeJitterRatio(jitterRatio);

  const exponentialDelay = normalizedBaseDelayMs * (2 ** (normalizedRetryNumber - 1));
  const boundedDelay = Math.min(normalizedMaxDelayMs, exponentialDelay);
  if (normalizedJitterRatio === 0) {
    return boundedDelay;
  }

  const randomValue = typeof random === 'function' ? Number(random()) : Math.random();
  const normalizedRandom = Number.isFinite(randomValue)
    ? Math.min(1, Math.max(0, randomValue))
    : Math.random();
  const jitterAmplitude = Math.round(boundedDelay * normalizedJitterRatio);
  if (jitterAmplitude <= 0) {
    return boundedDelay;
  }
  const jitterOffset = Math.round((normalizedRandom * 2 - 1) * jitterAmplitude);
  const jitteredDelay = Math.max(0, boundedDelay + jitterOffset);
  return Math.min(normalizedMaxDelayMs, jitteredDelay);
};

const computeRetrySchedule = ({
  attemptCount = 0,
  maxAttempts = DEFAULT_MAX_ATTEMPTS,
  baseDelayMs = DEFAULT_BASE_DELAY_MS,
  maxDelayMs = DEFAULT_MAX_DELAY_MS,
  jitterRatio = DEFAULT_JITTER_RATIO,
  now = Date.now(),
  random = Math.random
} = {}) => {
  const normalizedAttemptCount = Math.max(0, asInteger(attemptCount, 0));
  const normalizedMaxAttempts = normalizeAttemptBound(
    maxAttempts,
    DEFAULT_MAX_ATTEMPTS
  );
  const nextAttemptCount = normalizedAttemptCount + 1;
  if (nextAttemptCount > normalizedMaxAttempts) {
    return {
      exhausted: true,
      nextAttemptCount,
      delayMs: null,
      nextRetryAt: null
    };
  }

  const delayMs = computeExponentialBackoffDelayMs({
    retryNumber: nextAttemptCount,
    baseDelayMs,
    maxDelayMs,
    jitterRatio,
    random
  });
  const nowEpochMs = now instanceof Date ? now.getTime() : Number(now);
  const safeNowEpochMs = Number.isFinite(nowEpochMs)
    ? nowEpochMs
    : Date.now();

  return {
    exhausted: false,
    nextAttemptCount,
    delayMs,
    nextRetryAt: new Date(safeNowEpochMs + delayMs).toISOString()
  };
};

module.exports = {
  RETRYABLE_HTTP_STATUS,
  TRANSIENT_NETWORK_ERROR_CODES,
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_BASE_DELAY_MS,
  DEFAULT_MAX_DELAY_MS,
  DEFAULT_JITTER_RATIO,
  isRetryableHttpStatus,
  isRetryableNetworkErrorCode,
  isRetryableDeliveryFailure,
  computeExponentialBackoffDelayMs,
  computeRetrySchedule
};

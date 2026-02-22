const test = require('node:test');
const assert = require('node:assert/strict');

const {
  isRetryableHttpStatus,
  isRetryableNetworkErrorCode,
  isRetryableDeliveryFailure,
  computeExponentialBackoffDelayMs,
  computeRetrySchedule
} = require('../src/modules/integration/delivery-retry-orchestrator');

test('isRetryableHttpStatus accepts 408/429 and 5xx only', () => {
  assert.equal(isRetryableHttpStatus(408), true);
  assert.equal(isRetryableHttpStatus(429), true);
  assert.equal(isRetryableHttpStatus(500), true);
  assert.equal(isRetryableHttpStatus(599), true);
  assert.equal(isRetryableHttpStatus(400), false);
  assert.equal(isRetryableHttpStatus('abc'), false);
});

test('isRetryableNetworkErrorCode is case-insensitive', () => {
  assert.equal(isRetryableNetworkErrorCode('ECONNRESET'), true);
  assert.equal(isRetryableNetworkErrorCode('econnrefused'), true);
  assert.equal(isRetryableNetworkErrorCode(' EAI_AGAIN '), true);
  assert.equal(isRetryableNetworkErrorCode('EACCES'), false);
});

test('isRetryableDeliveryFailure combines http and network checks', () => {
  assert.equal(
    isRetryableDeliveryFailure({ httpStatus: 503 }),
    true
  );
  assert.equal(
    isRetryableDeliveryFailure({ errorCode: 'ETIMEDOUT' }),
    true
  );
  assert.equal(
    isRetryableDeliveryFailure({ networkErrorCode: 'enetunreach' }),
    true
  );
  assert.equal(
    isRetryableDeliveryFailure({ httpStatus: 404, errorCode: 'EACCES' }),
    false
  );
});

test('computeExponentialBackoffDelayMs returns exponential delay with cap when jitter disabled', () => {
  assert.equal(
    computeExponentialBackoffDelayMs({
      retryNumber: 1,
      baseDelayMs: 1000,
      maxDelayMs: 3000,
      jitterRatio: 0
    }),
    1000
  );
  assert.equal(
    computeExponentialBackoffDelayMs({
      retryNumber: 3,
      baseDelayMs: 1000,
      maxDelayMs: 3000,
      jitterRatio: 0
    }),
    3000
  );
});

test('computeExponentialBackoffDelayMs keeps jittered delay within [0, maxDelayMs]', () => {
  assert.equal(
    computeExponentialBackoffDelayMs({
      retryNumber: 5,
      baseDelayMs: 1000,
      maxDelayMs: 3000,
      jitterRatio: 0.5,
      random: () => 1
    }),
    3000
  );
  assert.equal(
    computeExponentialBackoffDelayMs({
      retryNumber: 1,
      baseDelayMs: 1000,
      maxDelayMs: 3000,
      jitterRatio: 1,
      random: () => 0
    }),
    0
  );
});

test('computeRetrySchedule returns next retry metadata and exhaustion state', () => {
  const next = computeRetrySchedule({
    attemptCount: 1,
    maxAttempts: 3,
    baseDelayMs: 1000,
    maxDelayMs: 3000,
    jitterRatio: 0,
    now: Date.parse('2026-02-22T00:00:00.000Z')
  });
  assert.equal(next.exhausted, false);
  assert.equal(next.nextAttemptCount, 2);
  assert.equal(next.delayMs, 2000);
  assert.equal(next.nextRetryAt, '2026-02-22T00:00:02.000Z');

  const exhausted = computeRetrySchedule({
    attemptCount: 3,
    maxAttempts: 3
  });
  assert.equal(exhausted.exhausted, true);
  assert.equal(exhausted.nextAttemptCount, 4);
  assert.equal(exhausted.delayMs, null);
  assert.equal(exhausted.nextRetryAt, null);
});

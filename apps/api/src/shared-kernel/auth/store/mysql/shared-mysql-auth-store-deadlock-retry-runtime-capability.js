'use strict';

const createSharedMysqlAuthStoreDeadlockRetryRuntimeCapability = ({
  random,
  sleepFn,
  onDeadlockMetric,
  defaultRetryConfig,
  defaultFallbackResult,
  deadlockRetryConfig,
  isDeadlockError,
  log
} = {}) => {
  const retryConfig = {
    maxRetries: Math.max(
      0,
      Math.floor(
        Number(
          deadlockRetryConfig?.maxRetries
            ?? defaultRetryConfig.maxRetries
        )
      )
    ),
    baseDelayMs: Math.max(
      0,
      Math.floor(
        Number(
          deadlockRetryConfig?.baseDelayMs
            ?? defaultRetryConfig.baseDelayMs
        )
      )
    ),
    maxDelayMs: Math.max(
      0,
      Math.floor(
        Number(
          deadlockRetryConfig?.maxDelayMs
            ?? defaultRetryConfig.maxDelayMs
        )
      )
    ),
    jitterMs: Math.max(
      0,
      Math.floor(
        Number(
          deadlockRetryConfig?.jitterMs
            ?? defaultRetryConfig.jitterMs
        )
      )
    )
  };
  if (retryConfig.maxDelayMs < retryConfig.baseDelayMs) {
    retryConfig.maxDelayMs = retryConfig.baseDelayMs;
  }

  const deadlockMetricsByOperation = new Map();
  const getDeadlockMetricsByOperation = (operation) => {
    const normalizedOperation = String(operation || 'unknown');
    if (!deadlockMetricsByOperation.has(normalizedOperation)) {
      deadlockMetricsByOperation.set(normalizedOperation, {
        deadlockCount: 0,
        retrySuccessCount: 0,
        finalFailureCount: 0
      });
    }
    return deadlockMetricsByOperation.get(normalizedOperation);
  };

  const toDeadlockRates = (metrics) => {
    const resolutionCount =
      Number(metrics?.retrySuccessCount || 0) + Number(metrics?.finalFailureCount || 0);
    if (resolutionCount <= 0) {
      return {
        retrySuccessRate: 0,
        finalFailureRate: 0
      };
    }
    return {
      retrySuccessRate: Number((Number(metrics.retrySuccessCount) / resolutionCount).toFixed(6)),
      finalFailureRate: Number((Number(metrics.finalFailureCount) / resolutionCount).toFixed(6))
    };
  };

  const emitDeadlockMetric = ({
    operation,
    event,
    attemptsUsed,
    retriesUsed,
    retryDelayMs = null,
    error = null
  }) => {
    const metrics = getDeadlockMetricsByOperation(operation);
    if (event === 'deadlock-detected') {
      metrics.deadlockCount += 1;
    } else if (event === 'retry-succeeded') {
      metrics.retrySuccessCount += 1;
    } else if (event === 'final-failure') {
      metrics.finalFailureCount += 1;
    }
    const rates = toDeadlockRates(metrics);
    const payload = {
      operation: String(operation || 'unknown'),
      event: String(event || 'unknown'),
      deadlock_count: Number(metrics.deadlockCount),
      retry_success_count: Number(metrics.retrySuccessCount),
      final_failure_count: Number(metrics.finalFailureCount),
      retry_success_rate: Number(rates.retrySuccessRate),
      final_failure_rate: Number(rates.finalFailureRate),
      attempts_used: Number(attemptsUsed || 0),
      retries_used: Number(retriesUsed || 0),
      max_retries: Number(retryConfig.maxRetries),
      retry_delay_ms: retryDelayMs === null ? null : Number(retryDelayMs),
      error_code: String(error?.code || ''),
      error_errno: Number(error?.errno || 0),
      error_sql_state: String(error?.sqlState || '')
    };
    if (typeof onDeadlockMetric === 'function') {
      try {
        onDeadlockMetric(payload);
      } catch (_error) {}
    }
    return payload;
  };

  const computeRetryDelayMs = (retryNumber) => {
    const exponent = Math.max(0, Number(retryNumber || 1) - 1);
    const baseDelay = retryConfig.baseDelayMs * (2 ** exponent);
    const boundedDelay = Math.min(retryConfig.maxDelayMs, baseDelay);
    const randomValue = Number(random());
    const normalizedRandom = Number.isFinite(randomValue)
      ? Math.min(1, Math.max(0, randomValue))
      : 0;
    const jitter = retryConfig.jitterMs > 0
      ? Math.floor(normalizedRandom * (retryConfig.jitterMs + 1))
      : 0;
    return Math.max(0, Math.floor(boundedDelay + jitter));
  };

  const executeWithDeadlockRetry = async ({
    operation,
    execute,
    onExhausted = 'return-fallback',
    fallbackResult = defaultFallbackResult
  }) => {
    let retriesUsed = 0;
    while (true) {
      try {
        const result = await execute();
        if (retriesUsed > 0) {
          const recoveredMetric = emitDeadlockMetric({
            operation,
            event: 'retry-succeeded',
            attemptsUsed: retriesUsed + 1,
            retriesUsed
          });
          log('info', 'MySQL deadlock recovered after retry', {
            component: 'auth.store.mysql',
            ...recoveredMetric
          });
        }
        return result;
      } catch (error) {
        if (!isDeadlockError(error)) {
          throw error;
        }
        const canRetry = retriesUsed < retryConfig.maxRetries;
        const retryDelayMs = canRetry ? computeRetryDelayMs(retriesUsed + 1) : null;
        const deadlockMetric = emitDeadlockMetric({
          operation,
          event: 'deadlock-detected',
          attemptsUsed: retriesUsed + 1,
          retriesUsed,
          retryDelayMs,
          error
        });
        if (canRetry) {
          log('warn', 'MySQL deadlock detected, retrying auth store operation', {
            component: 'auth.store.mysql',
            ...deadlockMetric
          });
          retriesUsed += 1;
          if (retryDelayMs > 0) {
            await sleepFn(retryDelayMs);
          }
          continue;
        }
        const finalFailureMetric = emitDeadlockMetric({
          operation,
          event: 'final-failure',
          attemptsUsed: retriesUsed + 1,
          retriesUsed,
          retryDelayMs: null,
          error
        });
        log('error', 'MySQL deadlock retries exhausted in auth store', {
          component: 'auth.store.mysql',
          alert: true,
          ...finalFailureMetric
        });
        if (onExhausted === 'throw') {
          throw error;
        }
        if (typeof fallbackResult === 'function') {
          return fallbackResult(error);
        }
        if (
          fallbackResult
          && typeof fallbackResult === 'object'
          && !Array.isArray(fallbackResult)
        ) {
          return { ...fallbackResult };
        }
        return defaultFallbackResult;
      }
    }
  };

  return {
    retryConfig,
    deadlockMetricsByOperation,
    getDeadlockMetricsByOperation,
    toDeadlockRates,
    emitDeadlockMetric,
    computeRetryDelayMs,
    executeWithDeadlockRetry
  };
};

module.exports = {
  createSharedMysqlAuthStoreDeadlockRetryRuntimeCapability
};

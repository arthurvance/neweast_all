const {
  resolveContractVersionForInvocation,
  resolveVersionByStrategy,
  assertProductionInvocationAllowed,
  createIntegrationInvocationBlockedError,
  createIntegrationContractVersionMismatchError,
  createIntegrationContractStrategyInvalidError
} = require('./contract-resolver');
const {
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
} = require('./delivery-retry-orchestrator');

module.exports = {
  resolveContractVersionForInvocation,
  resolveVersionByStrategy,
  assertProductionInvocationAllowed,
  createIntegrationInvocationBlockedError,
  createIntegrationContractVersionMismatchError,
  createIntegrationContractStrategyInvalidError,
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

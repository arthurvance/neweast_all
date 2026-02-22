const {
  resolveContractVersionForInvocation,
  resolveVersionByStrategy,
  assertProductionInvocationAllowed,
  createIntegrationInvocationBlockedError,
  createIntegrationContractVersionMismatchError,
  createIntegrationContractStrategyInvalidError
} = require('./contract-resolver');

module.exports = {
  resolveContractVersionForInvocation,
  resolveVersionByStrategy,
  assertProductionInvocationAllowed,
  createIntegrationInvocationBlockedError,
  createIntegrationContractVersionMismatchError,
  createIntegrationContractStrategyInvalidError
};

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;

const normalizeRequiredString = (value) => {
  if (typeof value !== 'string') {
    return '';
  }
  const normalized = value.trim();
  if (!normalized || normalized !== value || CONTROL_CHAR_PATTERN.test(normalized)) {
    return '';
  }
  return normalized;
};

const normalizeOptionalString = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    return null;
  }
  const normalized = value.trim();
  if (!normalized || normalized !== value || CONTROL_CHAR_PATTERN.test(normalized)) {
    return null;
  }
  return normalized;
};

const normalizeLifecycleStatus = (status) =>
  String(status || '').trim().toLowerCase();

const normalizeHeaderMap = (headers = {}) => {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) {
    return new Map();
  }
  const normalized = new Map();
  for (const [key, value] of Object.entries(headers)) {
    const normalizedKey = String(key || '').trim().toLowerCase();
    if (!normalizedKey) {
      continue;
    }
    const normalizedValue = normalizeOptionalString(
      Array.isArray(value) ? String(value[0] || '') : String(value || '')
    );
    if (!normalizedValue) {
      continue;
    }
    normalized.set(normalizedKey, normalizedValue);
  }
  return normalized;
};

const normalizeQueryObject = (query = {}) => {
  if (!query || typeof query !== 'object' || Array.isArray(query)) {
    return Object.create(null);
  }
  const normalized = Object.create(null);
  for (const [key, value] of Object.entries(query)) {
    const normalizedKey = String(key || '').trim();
    if (!normalizedKey) {
      continue;
    }
    const normalizedValue = normalizeOptionalString(
      Array.isArray(value) ? String(value[0] || '') : String(value || '')
    );
    if (!normalizedValue) {
      continue;
    }
    normalized[normalizedKey] = normalizedValue;
  }
  return normalized;
};

const createIntegrationInvocationBlockedError = ({
  lifecycleStatus = null
} = {}) => {
  const error = new Error('integration invocation blocked by lifecycle status');
  error.code = 'ERR_INTEGRATION_INVOCATION_BLOCKED';
  error.reason = 'lifecycle_not_active';
  error.lifecycleStatus = normalizeLifecycleStatus(lifecycleStatus) || null;
  return error;
};

const createIntegrationContractVersionMismatchError = ({
  expectedContractVersion = null,
  resolvedContractVersion = null,
  resolvedBy = null
} = {}) => {
  const error = new Error('integration contract version mismatch');
  error.code = 'ERR_INTEGRATION_CONTRACT_VERSION_MISMATCH';
  error.reason = 'contract_version_mismatch';
  error.expectedContractVersion = expectedContractVersion || null;
  error.resolvedContractVersion = resolvedContractVersion || null;
  error.resolvedBy = resolvedBy || null;
  return error;
};

const createIntegrationContractStrategyInvalidError = ({
  versionStrategy = null,
  reason = 'invalid_version_strategy'
} = {}) => {
  const error = new Error('integration contract version strategy invalid');
  error.code = 'ERR_INTEGRATION_CONTRACT_STRATEGY_INVALID';
  error.reason = String(reason || 'invalid_version_strategy').trim().toLowerCase();
  error.versionStrategy = normalizeOptionalString(versionStrategy);
  return error;
};

const assertProductionInvocationAllowed = ({
  lifecycleStatus
} = {}) => {
  const normalizedLifecycleStatus = normalizeLifecycleStatus(lifecycleStatus);
  if (normalizedLifecycleStatus !== 'active') {
    throw createIntegrationInvocationBlockedError({
      lifecycleStatus: normalizedLifecycleStatus
    });
  }
};

const resolveVersionByStrategy = ({
  versionStrategy = null,
  requestedContractVersion = null,
  requestHeaders = {},
  requestQuery = {},
  activeContractVersion
} = {}) => {
  const hasExplicitRequestedVersion =
    requestedContractVersion !== null && requestedContractVersion !== undefined;
  const requestedVersion = normalizeOptionalString(requestedContractVersion);
  if (hasExplicitRequestedVersion && !requestedVersion) {
    throw createIntegrationContractStrategyInvalidError({
      versionStrategy: normalizeOptionalString(versionStrategy),
      reason: 'requested_version_invalid'
    });
  }
  if (requestedVersion) {
    return {
      resolvedContractVersion: requestedVersion,
      resolvedBy: 'request:explicit'
    };
  }

  const normalizedActiveContractVersion = normalizeRequiredString(activeContractVersion);
  if (!normalizedActiveContractVersion) {
    return {
      resolvedContractVersion: '',
      resolvedBy: 'invalid:active'
    };
  }

  const normalizedStrategy = normalizeOptionalString(versionStrategy);
  if (!normalizedStrategy) {
    return {
      resolvedContractVersion: normalizedActiveContractVersion,
      resolvedBy: 'strategy:active'
    };
  }

  const [strategyTypeRaw, ...strategyArgs] = normalizedStrategy.split(':');
  const strategyType = String(strategyTypeRaw || '').trim().toLowerCase();
  const strategyArg = strategyArgs.join(':').trim();
  if (!strategyType || !strategyArg) {
    throw createIntegrationContractStrategyInvalidError({
      versionStrategy: normalizedStrategy,
      reason: 'strategy_malformed'
    });
  }

  if (strategyType === 'fixed') {
    const fixedVersion = normalizeOptionalString(strategyArg);
    if (!fixedVersion) {
      throw createIntegrationContractStrategyInvalidError({
        versionStrategy: normalizedStrategy,
        reason: 'strategy_fixed_missing_version'
      });
    }
    return {
      resolvedContractVersion: fixedVersion,
      resolvedBy: 'strategy:fixed'
    };
  }

  if (strategyType === 'header') {
    const headerKey = strategyArg.toLowerCase();
    const headerMap = normalizeHeaderMap(requestHeaders);
    const headerVersion = normalizeOptionalString(headerMap.get(headerKey));
    if (!headerVersion) {
      throw createIntegrationContractStrategyInvalidError({
        versionStrategy: normalizedStrategy,
        reason: 'strategy_header_missing'
      });
    }
    return {
      resolvedContractVersion: headerVersion,
      resolvedBy: 'strategy:header'
    };
  }

  if (strategyType === 'query') {
    const queryObject = normalizeQueryObject(requestQuery);
    const queryVersion = normalizeOptionalString(queryObject[strategyArg]);
    if (!queryVersion) {
      throw createIntegrationContractStrategyInvalidError({
        versionStrategy: normalizedStrategy,
        reason: 'strategy_query_missing'
      });
    }
    return {
      resolvedContractVersion: queryVersion,
      resolvedBy: 'strategy:query'
    };
  }

  throw createIntegrationContractStrategyInvalidError({
    versionStrategy: normalizedStrategy,
    reason: 'strategy_unsupported'
  });
};

const resolveContractVersionForInvocation = ({
  integration,
  activeContract,
  requestedContractVersion = null,
  requestHeaders = {},
  requestQuery = {},
  direction = 'outbound'
} = {}) => {
  if (!integration || typeof integration !== 'object') {
    throw new Error('resolveContractVersionForInvocation requires integration record');
  }
  if (!activeContract || typeof activeContract !== 'object') {
    throw new Error('resolveContractVersionForInvocation requires active contract record');
  }

  const normalizedDirection = String(direction || '').trim().toLowerCase();
  if (normalizedDirection !== 'outbound' && normalizedDirection !== 'inbound') {
    throw new Error('resolveContractVersionForInvocation requires direction outbound|inbound');
  }

  const integrationLifecycleStatus = normalizeLifecycleStatus(
    integration.lifecycle_status ?? integration.lifecycleStatus
  );
  assertProductionInvocationAllowed({
    lifecycleStatus: integrationLifecycleStatus
  });

  const activeContractVersion = normalizeRequiredString(
    activeContract.contract_version ?? activeContract.contractVersion
  );
  const activeContractStatus = normalizeLifecycleStatus(
    activeContract.status
  );
  if (!activeContractVersion || activeContractStatus !== 'active') {
    throw new Error('resolveContractVersionForInvocation requires active contract status=active');
  }

  const versionStrategy =
    integration.version_strategy === undefined
      ? integration.versionStrategy
      : integration.version_strategy;
  const resolved = resolveVersionByStrategy({
    versionStrategy,
    requestedContractVersion,
    requestHeaders,
    requestQuery,
    activeContractVersion
  });

  if (resolved.resolvedContractVersion !== activeContractVersion) {
    throw createIntegrationContractVersionMismatchError({
      expectedContractVersion: activeContractVersion,
      resolvedContractVersion: resolved.resolvedContractVersion,
      resolvedBy: resolved.resolvedBy
    });
  }

  return {
    contract_version: activeContractVersion,
    resolved_by: resolved.resolvedBy,
    direction: normalizedDirection,
    lifecycle_status: integrationLifecycleStatus,
    invocation_allowed: true
  };
};

module.exports = {
  resolveContractVersionForInvocation,
  resolveVersionByStrategy,
  assertProductionInvocationAllowed,
  createIntegrationInvocationBlockedError,
  createIntegrationContractVersionMismatchError,
  createIntegrationContractStrategyInvalidError
};

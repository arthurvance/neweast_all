const { log } = require('../../common/logger');
const { AuthProblemError } = require('../auth/auth.service');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_INTEGRATION_RECOVERY_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_RECOVERY_SCOPE,
  PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM
} = require('./integration-recovery.constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const MAX_INTEGRATION_ID_LENGTH = 64;
const MAX_RECOVERY_ID_LENGTH = 64;
const MAX_OPERATOR_USER_ID_LENGTH = 64;
const MAX_CONTRACT_VERSION_LENGTH = 64;
const MAX_REQUEST_ID_LENGTH = 128;
const MAX_TRACEPARENT_LENGTH = 128;
const MAX_IDEMPOTENCY_KEY_LENGTH = 128;
const MAX_FAILURE_CODE_LENGTH = 128;
const MAX_FAILURE_DETAIL_LENGTH = 65535;
const MAX_REPLAY_REASON_LENGTH = 256;
const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 200;

const VALID_RECOVERY_STATUSES = new Set(PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM);
const VALID_INTEGRATION_LIFECYCLE_STATUSES = new Set([
  'draft',
  'active',
  'paused',
  'retired'
]);
const VALID_CONTRACT_TYPES = new Set(['openapi', 'event']);
const LIST_ALLOWED_QUERY_FIELDS = new Set(['status', 'limit']);
const REPLAY_ALLOWED_FIELDS = new Set(['reason']);

const isPlainObject = (candidate) =>
  candidate !== null
  && typeof candidate === 'object'
  && !Array.isArray(candidate);

const normalizeStrictRequiredString = (candidate) => {
  if (typeof candidate !== 'string') {
    return '';
  }
  const normalized = candidate.trim();
  if (
    !normalized
    || normalized !== candidate
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    return '';
  }
  return normalized;
};

const normalizeStrictOptionalString = ({
  value,
  maxLength
} = {}) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    return undefined;
  }
  const normalized = value.trim();
  if (
    !normalized
    || normalized !== value
    || CONTROL_CHAR_PATTERN.test(normalized)
    || normalized.length > maxLength
  ) {
    return undefined;
  }
  return normalized;
};

const parseJsonValue = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value === 'object') {
    return value;
  }
  if (typeof value !== 'string') {
    return null;
  }
  const normalized = value.trim();
  if (!normalized) {
    return null;
  }
  try {
    return JSON.parse(normalized);
  } catch (_error) {
    return null;
  }
};

const normalizeStoreIsoTimestamp = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (typeof value !== 'string') {
    return '';
  }
  const normalized = value.trim();
  if (!normalized) {
    return null;
  }
  if (normalized !== value || CONTROL_CHAR_PATTERN.test(normalized)) {
    return '';
  }
  const parsedDate = new Date(normalized);
  if (Number.isNaN(parsedDate.getTime())) {
    return '';
  }
  return parsedDate.toISOString();
};

const resolveStoreFieldValue = ({
  record,
  camelCaseKey,
  snakeCaseKey
}) =>
  record[camelCaseKey] === undefined
    ? record[snakeCaseKey]
    : record[camelCaseKey];

const normalizeStoreOptionalString = ({
  record,
  camelCaseKey,
  snakeCaseKey,
  maxLength
}) =>
  normalizeStrictOptionalString({
    value: resolveStoreFieldValue({
      record,
      camelCaseKey,
      snakeCaseKey
    }),
    maxLength
  });

const normalizeIntegrationId = (integrationId) =>
  normalizeStrictRequiredString(integrationId).toLowerCase();

const normalizeRecoveryId = (recoveryId) =>
  normalizeStrictRequiredString(recoveryId).toLowerCase();

const normalizeContractType = (contractType) =>
  String(contractType || '').trim().toLowerCase();

const normalizeContractVersion = (contractVersion) =>
  normalizeStrictRequiredString(contractVersion);

const normalizeRecoveryStatus = (status) =>
  String(status || '').trim().toLowerCase();

const normalizeLastHttpStatus = (statusCode) => {
  if (statusCode === null || statusCode === undefined) {
    return null;
  }
  const parsed = Number(statusCode);
  if (!Number.isInteger(parsed) || parsed < 100 || parsed > 599) {
    return null;
  }
  return parsed;
};

const recoveryProblem = ({
  status,
  title,
  detail,
  errorCode,
  extensions = {}
}) =>
  new AuthProblemError({
    status,
    title,
    detail,
    errorCode,
    extensions
  });

const recoveryErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    recoveryProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'INT-400-INVALID-PAYLOAD'
    }),

  forbidden: () =>
    recoveryProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  integrationNotFound: ({
    integrationId = null
  } = {}) =>
    recoveryProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标集成目录不存在',
      errorCode: 'INT-404-NOT-FOUND',
      extensions: {
        retryable: false,
        integration_id: integrationId
      }
    }),

  recoveryNotFound: ({
    integrationId = null,
    recoveryId = null
  } = {}) =>
    recoveryProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标恢复队列项不存在',
      errorCode: 'INT-404-RECOVERY-NOT-FOUND',
      extensions: {
        retryable: false,
        integration_id: integrationId,
        recovery_id: recoveryId
      }
    }),

  replayConflict: ({
    integrationId = null,
    recoveryId = null,
    previousStatus = null,
    requestedStatus = 'replayed'
  } = {}) =>
    recoveryProblem({
      status: 409,
      title: 'Conflict',
      detail: '恢复队列状态冲突，当前不可重放',
      errorCode: 'INT-409-RECOVERY-REPLAY-CONFLICT',
      extensions: {
        retryable: false,
        integration_id: integrationId,
        recovery_id: recoveryId,
        previous_status: previousStatus,
        requested_status: requestedStatus
      }
    }),

  dependencyUnavailable: ({ reason = 'dependency-unavailable' } = {}) =>
    recoveryProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '集成恢复治理依赖暂不可用，请稍后重试',
      errorCode: 'INT-503-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: String(reason || 'dependency-unavailable').trim()
      }
    })
};

const mapStoreError = (error) => {
  if (error instanceof AuthProblemError) {
    return error;
  }
  const normalizedErrorCode = String(error?.code || '').trim();
  if (normalizedErrorCode === 'ERR_PLATFORM_INTEGRATION_RECOVERY_REPLAY_CONFLICT') {
    return recoveryErrors.replayConflict({
      integrationId: normalizeIntegrationId(error?.integrationId),
      recoveryId: normalizeRecoveryId(error?.recoveryId),
      previousStatus: normalizeRecoveryStatus(error?.previousStatus) || null
    });
  }
  return recoveryErrors.dependencyUnavailable({
    reason: normalizedErrorCode
      || String(error?.message || 'dependency-unavailable').trim().toLowerCase()
  });
};

const mapRecoveryRecord = ({
  record
} = {}) => {
  if (!record || typeof record !== 'object') {
    return null;
  }

  const integrationId = normalizeIntegrationId(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'integrationId',
      snakeCaseKey: 'integration_id'
    })
  );
  const recoveryId = normalizeRecoveryId(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'recoveryId',
      snakeCaseKey: 'recovery_id'
    })
  );
  const contractType = normalizeContractType(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'contractType',
      snakeCaseKey: 'contract_type'
    })
  );
  const contractVersion = normalizeContractVersion(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'contractVersion',
      snakeCaseKey: 'contract_version'
    })
  );
  const sourceRequestId = normalizeStrictRequiredString(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'requestId',
      snakeCaseKey: 'request_id'
    })
  );
  const traceparent = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'traceparent',
    snakeCaseKey: 'traceparent',
    maxLength: MAX_TRACEPARENT_LENGTH
  });
  const idempotencyKeyRaw = resolveStoreFieldValue({
    record,
    camelCaseKey: 'idempotencyKey',
    snakeCaseKey: 'idempotency_key'
  });
  const idempotencyKey = normalizeStrictOptionalString({
    value: idempotencyKeyRaw === '' ? null : idempotencyKeyRaw,
    maxLength: MAX_IDEMPOTENCY_KEY_LENGTH
  });

  const attemptCount = Number(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'attemptCount',
      snakeCaseKey: 'attempt_count'
    })
  );
  const maxAttempts = Number(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'maxAttempts',
      snakeCaseKey: 'max_attempts'
    })
  );
  const status = normalizeRecoveryStatus(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'status',
      snakeCaseKey: 'status'
    })
  );
  const failureCode = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'failureCode',
    snakeCaseKey: 'failure_code',
    maxLength: MAX_FAILURE_CODE_LENGTH
  });
  const failureDetail = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'failureDetail',
    snakeCaseKey: 'failure_detail',
    maxLength: MAX_FAILURE_DETAIL_LENGTH
  });
  const lastHttpStatus = normalizeLastHttpStatus(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'lastHttpStatus',
      snakeCaseKey: 'last_http_status'
    })
  );
  const retryableRaw = resolveStoreFieldValue({
    record,
    camelCaseKey: 'retryable',
    snakeCaseKey: 'retryable'
  });
  const payloadSnapshot = parseJsonValue(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'payloadSnapshot',
      snakeCaseKey: 'payload_snapshot'
    })
  );
  const responseSnapshot = parseJsonValue(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'responseSnapshot',
      snakeCaseKey: 'response_snapshot'
    })
  );

  const nextRetryAt = normalizeStoreIsoTimestamp(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'nextRetryAt',
      snakeCaseKey: 'next_retry_at'
    })
  );
  const lastAttemptAt = normalizeStoreIsoTimestamp(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'lastAttemptAt',
      snakeCaseKey: 'last_attempt_at'
    })
  );
  const createdAt = normalizeStoreIsoTimestamp(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'createdAt',
      snakeCaseKey: 'created_at'
    })
  );
  const updatedAt = normalizeStoreIsoTimestamp(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'updatedAt',
      snakeCaseKey: 'updated_at'
    })
  );
  const createdByUserId = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'createdByUserId',
    snakeCaseKey: 'created_by_user_id',
    maxLength: MAX_OPERATOR_USER_ID_LENGTH
  });
  const updatedByUserId = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'updatedByUserId',
    snakeCaseKey: 'updated_by_user_id',
    maxLength: MAX_OPERATOR_USER_ID_LENGTH
  });

  if (
    !integrationId
    || integrationId.length > MAX_INTEGRATION_ID_LENGTH
    || !recoveryId
    || recoveryId.length > MAX_RECOVERY_ID_LENGTH
    || !VALID_CONTRACT_TYPES.has(contractType)
    || !contractVersion
    || contractVersion.length > MAX_CONTRACT_VERSION_LENGTH
    || !sourceRequestId
    || sourceRequestId.length > MAX_REQUEST_ID_LENGTH
    || traceparent === undefined
    || idempotencyKey === undefined
    || !Number.isInteger(attemptCount)
    || attemptCount < 0
    || !Number.isInteger(maxAttempts)
    || maxAttempts < 1
    || maxAttempts > 5
    || !VALID_RECOVERY_STATUSES.has(status)
    || failureCode === undefined
    || failureDetail === undefined
    || payloadSnapshot === null
    || (typeof payloadSnapshot !== 'object' && !Array.isArray(payloadSnapshot))
    || !createdAt
    || !updatedAt
    || (nextRetryAt === '')
    || (lastAttemptAt === '')
  ) {
    return null;
  }

  return {
    recovery_id: recoveryId,
    integration_id: integrationId,
    contract_type: contractType,
    contract_version: contractVersion,
    request_id: sourceRequestId,
    traceparent: traceparent || null,
    idempotency_key: idempotencyKey || null,
    attempt_count: attemptCount,
    max_attempts: maxAttempts,
    next_retry_at: nextRetryAt,
    last_attempt_at: lastAttemptAt,
    status,
    failure_code: failureCode,
    failure_detail: failureDetail,
    last_http_status: lastHttpStatus,
    retryable: Boolean(retryableRaw),
    payload_snapshot: payloadSnapshot,
    response_snapshot: responseSnapshot,
    created_by_user_id: createdByUserId,
    updated_by_user_id: updatedByUserId,
    created_at: createdAt,
    updated_at: updatedAt
  };
};

const parseListQuery = (query) => {
  if (!isPlainObject(query)) {
    throw recoveryErrors.invalidPayload('query 参数非法');
  }
  const unknownKeys = Object.keys(query).filter(
    (key) => !LIST_ALLOWED_QUERY_FIELDS.has(key)
  );
  if (unknownKeys.length > 0) {
    throw recoveryErrors.invalidPayload('query 包含未支持字段');
  }

  const statusRaw = query.status;
  const status = statusRaw === undefined || statusRaw === null
    ? null
    : normalizeRecoveryStatus(statusRaw);
  if (statusRaw !== undefined && statusRaw !== null && !VALID_RECOVERY_STATUSES.has(status)) {
    throw recoveryErrors.invalidPayload('status 非法');
  }

  const limitRaw = query.limit;
  const limit = limitRaw === undefined || limitRaw === null
    ? DEFAULT_LIST_LIMIT
    : Number(limitRaw);
  if (
    !Number.isInteger(limit)
    || limit < 1
    || limit > MAX_LIST_LIMIT
  ) {
    throw recoveryErrors.invalidPayload(`limit 需为 1-${MAX_LIST_LIMIT} 的整数`);
  }

  return {
    status,
    limit
  };
};

const parseReplayPayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw recoveryErrors.invalidPayload();
  }
  const unknownKeys = Object.keys(payload).filter(
    (key) => !REPLAY_ALLOWED_FIELDS.has(key)
  );
  if (unknownKeys.length > 0) {
    throw recoveryErrors.invalidPayload('payload 包含未支持字段');
  }
  const reason = Object.prototype.hasOwnProperty.call(payload, 'reason')
    ? normalizeStrictOptionalString({
      value: payload.reason,
      maxLength: MAX_REPLAY_REASON_LENGTH
    })
    : null;
  if (reason === undefined) {
    throw recoveryErrors.invalidPayload(
      `reason 长度不能超过 ${MAX_REPLAY_REASON_LENGTH}`
    );
  }
  return {
    reason
  };
};

const createPlatformIntegrationRecoveryService = ({
  authService,
  deliveryExecutor = null
} = {}) => {
  const auditTrail = [];

  const addAuditEvent = ({
    type,
    requestId,
    operatorUserId = 'unknown',
    integrationId = null,
    recoveryId = null,
    detail,
    metadata = {}
  }) => {
    const event = {
      type: String(type || '').trim() || 'platform.integration.recovery.unknown',
      at: new Date().toISOString(),
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      integration_id: integrationId ? String(integrationId) : null,
      recovery_id: recoveryId ? String(recoveryId) : null,
      detail: String(detail || '').trim(),
      ...metadata
    };
    auditTrail.push(event);
    if (auditTrail.length > MAX_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Platform integration recovery audit event', event);
  };

  const assertAuthServiceMethod = (methodName) => {
    if (!authService || typeof authService[methodName] !== 'function') {
      throw recoveryErrors.dependencyUnavailable();
    }
  };

  const resolveAuthStore = () => authService?._internals?.authStore || null;

  const resolveDeliveryExecutor = () => {
    if (typeof deliveryExecutor === 'function') {
      return deliveryExecutor;
    }
    if (typeof authService?.executePlatformIntegrationRecoveryDelivery === 'function') {
      return authService.executePlatformIntegrationRecoveryDelivery.bind(authService);
    }
    return null;
  };

  const assertAuthStoreMethod = (methodName) => {
    const authStore = resolveAuthStore();
    if (!authStore || typeof authStore[methodName] !== 'function') {
      throw recoveryErrors.dependencyUnavailable({
        reason: `auth-store-${methodName}-unsupported`
      });
    }
    return authStore;
  };

  const resolvePreauthorizedOperatorContext = ({
    authorizationContext = null,
    expectedPermissionCode = PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE
  } = {}) => {
    const preauthorizedContext = resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_INTEGRATION_RECOVERY_SCOPE,
      expectedEntryDomain: PLATFORM_INTEGRATION_RECOVERY_SCOPE
    });
    if (!preauthorizedContext) {
      return null;
    }
    return {
      operatorUserId: preauthorizedContext.userId,
      operatorSessionId: preauthorizedContext.sessionId
    };
  };

  const resolveOperatorContext = async ({
    requestId,
    accessToken,
    authorizationContext = null,
    permissionCode = PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE
  }) => {
    const preauthorizedContext = resolvePreauthorizedOperatorContext({
      authorizationContext,
      expectedPermissionCode: permissionCode
    });
    if (preauthorizedContext) {
      return preauthorizedContext;
    }
    assertAuthServiceMethod('authorizeRoute');
    const authorized = await authService.authorizeRoute({
      requestId,
      accessToken,
      permissionCode,
      scope: PLATFORM_INTEGRATION_RECOVERY_SCOPE,
      authorizationContext
    });
    const operatorUserId = normalizeStrictRequiredString(
      authorized?.user_id || authorized?.userId
    );
    const operatorSessionId = normalizeStrictRequiredString(
      authorized?.session_id || authorized?.sessionId
    );
    if (!operatorUserId || !operatorSessionId) {
      throw recoveryErrors.forbidden();
    }
    return {
      operatorUserId,
      operatorSessionId
    };
  };

  const getIntegrationEntry = async ({ integrationId }) => {
    const authStore = assertAuthStoreMethod(
      'findPlatformIntegrationCatalogEntryByIntegrationId'
    );
    let record;
    try {
      record = await authStore.findPlatformIntegrationCatalogEntryByIntegrationId({
        integrationId
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    if (!record) {
      return null;
    }
    const requestedIntegrationId = normalizeIntegrationId(integrationId);
    const recordIntegrationId = normalizeIntegrationId(
      record.integrationId || record.integration_id
    );
    const lifecycleStatus = String(
      record.lifecycleStatus === undefined
        ? record.lifecycle_status
        : record.lifecycleStatus
    ).trim().toLowerCase();
    if (
      !requestedIntegrationId
      || !recordIntegrationId
      || recordIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
      || requestedIntegrationId !== recordIntegrationId
      || !VALID_INTEGRATION_LIFECYCLE_STATUSES.has(lifecycleStatus)
    ) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-catalog-record-invalid'
      });
    }
    return {
      integration_id: recordIntegrationId,
      lifecycle_status: lifecycleStatus
    };
  };

  const listRecoveryQueue = async ({
    requestId,
    accessToken,
    integrationId,
    query = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    if (
      !normalizedIntegrationId
      || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
    ) {
      throw recoveryErrors.invalidPayload('integration_id 非法');
    }
    const filters = parseListQuery(query || {});

    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_RECOVERY_VIEW_PERMISSION_CODE
    });

    const integrationEntry = await getIntegrationEntry({
      integrationId: normalizedIntegrationId
    });
    if (!integrationEntry) {
      throw recoveryErrors.integrationNotFound({
        integrationId: normalizedIntegrationId
      });
    }

    const authStore = assertAuthStoreMethod('listPlatformIntegrationRecoveryQueueEntries');
    let records = [];
    try {
      records = await authStore.listPlatformIntegrationRecoveryQueueEntries({
        integrationId: normalizedIntegrationId,
        status: filters.status,
        limit: filters.limit
      });
    } catch (error) {
      const mappedError = mapStoreError(error);
      addAuditEvent({
        type: 'platform.integration.recovery.queue.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        integrationId: normalizedIntegrationId,
        detail: 'integration recovery queue list failed',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    if (!Array.isArray(records)) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-list-result-malformed'
      });
    }
    const queue = records.map((record) => mapRecoveryRecord({ record }));
    if (
      queue.some((record) => !record)
      || queue.some((record) => record.integration_id !== normalizedIntegrationId)
      || (
        filters.status
        && queue.some((record) => record.status !== filters.status)
      )
    ) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-list-result-malformed'
      });
    }

    addAuditEvent({
      type: 'platform.integration.recovery.queue.list.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      integrationId: normalizedIntegrationId,
      detail: 'integration recovery queue listed',
      metadata: {
        total: queue.length,
        status: filters.status
      }
    });

    return {
      integration_id: normalizedIntegrationId,
      lifecycle_status: integrationEntry.lifecycle_status,
      status: filters.status,
      limit: filters.limit,
      queue,
      request_id: resolvedRequestId
    };
  };

  const replayRecoveryQueueItem = async ({
    requestId,
    accessToken,
    integrationId,
    recoveryId,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    const normalizedRecoveryId = normalizeRecoveryId(recoveryId);
    if (
      !normalizedIntegrationId
      || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
      || !normalizedRecoveryId
      || normalizedRecoveryId.length > MAX_RECOVERY_ID_LENGTH
    ) {
      throw recoveryErrors.invalidPayload('integration_id 或 recovery_id 非法');
    }
    const parsedPayload = parseReplayPayload(payload || {});

    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE
    });

    const integrationEntry = await getIntegrationEntry({
      integrationId: normalizedIntegrationId
    });
    if (!integrationEntry) {
      throw recoveryErrors.integrationNotFound({
        integrationId: normalizedIntegrationId
      });
    }

    const authStore = assertAuthStoreMethod('replayPlatformIntegrationRecoveryQueueEntry');
    let replayResult = null;
    try {
      replayResult = await authStore.replayPlatformIntegrationRecoveryQueueEntry({
        integrationId: normalizedIntegrationId,
        recoveryId: normalizedRecoveryId,
        reason: parsedPayload.reason,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        auditContext: {
          requestId: resolvedRequestId,
          traceparent,
          actorUserId: operatorContext.operatorUserId,
          actorSessionId: operatorContext.operatorSessionId
        }
      });
    } catch (error) {
      const mappedError = mapStoreError(error);
      addAuditEvent({
        type: 'platform.integration.recovery.queue.replay.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        integrationId: normalizedIntegrationId,
        recoveryId: normalizedRecoveryId,
        detail: 'integration recovery replay failed',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    if (!replayResult) {
      throw recoveryErrors.recoveryNotFound({
        integrationId: normalizedIntegrationId,
        recoveryId: normalizedRecoveryId
      });
    }

    const mappedRecovery = mapRecoveryRecord({
      record: replayResult
    });
    const previousStatus = normalizeRecoveryStatus(
      replayResult.previousStatus || replayResult.previous_status || ''
    );
    const currentStatus = normalizeRecoveryStatus(
      replayResult.currentStatus || replayResult.current_status || mappedRecovery?.status || ''
    );
    if (
      !mappedRecovery
      || mappedRecovery.integration_id !== normalizedIntegrationId
      || mappedRecovery.recovery_id !== normalizedRecoveryId
      || !VALID_RECOVERY_STATUSES.has(previousStatus)
      || !VALID_RECOVERY_STATUSES.has(currentStatus)
      || (previousStatus !== 'failed' && previousStatus !== 'dlq')
      || currentStatus !== 'replayed'
      || mappedRecovery.status !== 'replayed'
      || currentStatus !== mappedRecovery.status
    ) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-replay-result-malformed'
      });
    }

    addAuditEvent({
      type: 'platform.integration.recovery.queue.replay.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      integrationId: normalizedIntegrationId,
      recoveryId: normalizedRecoveryId,
      detail: 'integration recovery queue replay requested',
      metadata: {
        previous_status: previousStatus,
        current_status: currentStatus
      }
    });

    return {
      recovery: mappedRecovery,
      previous_status: previousStatus,
      current_status: currentStatus,
      replayed: currentStatus === 'replayed',
      request_id: resolvedRequestId
    };
  };

  const processNextRecoveryQueueItem = async ({
    requestId,
    integrationId = null,
    now = new Date().toISOString(),
    traceparent = null,
    operatorUserId = null,
    operatorSessionId = null
  } = {}) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = integrationId === null || integrationId === undefined
      ? null
      : normalizeIntegrationId(integrationId);
    if (
      normalizedIntegrationId !== null
      && (
        !normalizedIntegrationId
        || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
      )
    ) {
      throw recoveryErrors.invalidPayload('integration_id 非法');
    }
    const normalizedOperatorUserId = normalizeStrictOptionalString({
      value: operatorUserId,
      maxLength: MAX_OPERATOR_USER_ID_LENGTH
    });
    const normalizedOperatorSessionId = normalizeStrictOptionalString({
      value: operatorSessionId,
      maxLength: MAX_REQUEST_ID_LENGTH
    });
    if (normalizedOperatorUserId === undefined || normalizedOperatorSessionId === undefined) {
      throw recoveryErrors.invalidPayload('operator 标识非法');
    }

    const resolvedDeliveryExecutor = resolveDeliveryExecutor();
    if (!resolvedDeliveryExecutor) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-delivery-executor-unavailable'
      });
    }

    const authStore = assertAuthStoreMethod('claimNextDuePlatformIntegrationRecoveryQueueEntry');
    assertAuthStoreMethod('completePlatformIntegrationRecoveryQueueAttempt');

    let claimedRecord = null;
    try {
      claimedRecord = await authStore.claimNextDuePlatformIntegrationRecoveryQueueEntry({
        integrationId: normalizedIntegrationId,
        now,
        operatorUserId: normalizedOperatorUserId,
        operatorSessionId: normalizedOperatorSessionId,
        auditContext: {
          requestId: resolvedRequestId,
          traceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId
        }
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    if (!claimedRecord) {
      return {
        processed: false,
        request_id: resolvedRequestId
      };
    }

    const mappedClaimedRecord = mapRecoveryRecord({
      record: claimedRecord
    });
    if (!mappedClaimedRecord) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-claim-result-malformed'
      });
    }
    const claimedPreviousStatus = normalizeRecoveryStatus(
      claimedRecord.previousStatus
      || claimedRecord.previous_status
      || mappedClaimedRecord.status
    );
    if (!VALID_RECOVERY_STATUSES.has(claimedPreviousStatus)) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-claim-result-malformed'
      });
    }

    let completionInput = null;
    try {
      const executionResult = await resolvedDeliveryExecutor({
        requestId: resolvedRequestId,
        traceparent,
        recovery: mappedClaimedRecord
      });
      if (!isPlainObject(executionResult)) {
        throw recoveryErrors.dependencyUnavailable({
          reason: 'integration-recovery-delivery-result-malformed'
        });
      }
      completionInput = {
        succeeded: Boolean(executionResult.succeeded),
        retryable: executionResult.retryable === undefined
          ? true
          : Boolean(executionResult.retryable),
        nextRetryAt: executionResult.nextRetryAt ?? null,
        failureCode: executionResult.failureCode ?? null,
        failureDetail: executionResult.failureDetail ?? null,
        lastHttpStatus: executionResult.lastHttpStatus ?? null,
        responseSnapshot: executionResult.responseSnapshot ?? null
      };
    } catch (error) {
      const fallbackFailureCode = normalizeStrictOptionalString({
        value: typeof error?.code === 'string'
          ? error.code
          : 'DELIVERY_EXECUTION_FAILED',
        maxLength: MAX_FAILURE_CODE_LENGTH
      }) || 'DELIVERY_EXECUTION_FAILED';
      const fallbackFailureDetail = normalizeStrictOptionalString({
        value: String(error?.message || 'delivery execution failed').trim(),
        maxLength: MAX_FAILURE_DETAIL_LENGTH
      }) || 'delivery execution failed';
      completionInput = {
        succeeded: false,
        retryable: error?.retryable === undefined ? true : Boolean(error?.retryable),
        nextRetryAt: error?.nextRetryAt ?? null,
        failureCode: fallbackFailureCode,
        failureDetail: fallbackFailureDetail,
        lastHttpStatus: normalizeLastHttpStatus(
          error?.httpStatus ?? error?.statusCode ?? error?.status
        ),
        responseSnapshot: {
          error_code: fallbackFailureCode,
          message: fallbackFailureDetail
        }
      };
    }

    let completionResult = null;
    try {
      completionResult = await authStore.completePlatformIntegrationRecoveryQueueAttempt({
        integrationId: mappedClaimedRecord.integration_id,
        recoveryId: mappedClaimedRecord.recovery_id,
        succeeded: completionInput.succeeded,
        retryable: completionInput.retryable,
        nextRetryAt: completionInput.nextRetryAt,
        failureCode: completionInput.failureCode,
        failureDetail: completionInput.failureDetail,
        lastHttpStatus: completionInput.lastHttpStatus,
        responseSnapshot: completionInput.responseSnapshot,
        operatorUserId: normalizedOperatorUserId,
        operatorSessionId: normalizedOperatorSessionId,
        auditContext: {
          requestId: resolvedRequestId,
          traceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId
        }
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    if (!completionResult) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-complete-result-missing'
      });
    }
    const mappedCompletion = mapRecoveryRecord({
      record: completionResult
    });
    if (
      !mappedCompletion
      || mappedCompletion.integration_id !== mappedClaimedRecord.integration_id
      || mappedCompletion.recovery_id !== mappedClaimedRecord.recovery_id
    ) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-complete-result-malformed'
      });
    }

    addAuditEvent({
      type: 'platform.integration.recovery.queue.processed',
      requestId: resolvedRequestId,
      operatorUserId: normalizedOperatorUserId || 'system',
      integrationId: mappedClaimedRecord.integration_id,
      recoveryId: mappedClaimedRecord.recovery_id,
      detail: 'integration recovery queue item processed',
      metadata: {
        previous_status: claimedPreviousStatus,
        current_status: mappedCompletion.status
      }
    });

    return {
      processed: true,
      recovery: mappedCompletion,
      previous_status: claimedPreviousStatus,
      current_status: mappedCompletion.status,
      request_id: resolvedRequestId
    };
  };

  return {
    listRecoveryQueue,
    replayRecoveryQueueItem,
    processNextRecoveryQueueItem,
    _internals: {
      authService,
      deliveryExecutor: resolveDeliveryExecutor(),
      auditTrail
    }
  };
};

module.exports = {
  createPlatformIntegrationRecoveryService
};

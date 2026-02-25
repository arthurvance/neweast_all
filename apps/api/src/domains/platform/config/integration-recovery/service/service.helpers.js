'use strict';

const { log } = require('../../../../../common/logger');
const { AuthProblemError } = require('../../../../../shared-kernel/auth/auth-problem-error');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../../shared-kernel/auth/route-authz');
const {
  PLATFORM_INTEGRATION_RECOVERY_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_RECOVERY_SCOPE,
  PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM
} = require('../constants');

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

module.exports = {
  CONTROL_CHAR_PATTERN,
  DEFAULT_LIST_LIMIT,
  LIST_ALLOWED_QUERY_FIELDS,
  MAX_AUDIT_TRAIL_ENTRIES,
  MAX_CONTRACT_VERSION_LENGTH,
  MAX_FAILURE_CODE_LENGTH,
  MAX_FAILURE_DETAIL_LENGTH,
  MAX_IDEMPOTENCY_KEY_LENGTH,
  MAX_INTEGRATION_ID_LENGTH,
  MAX_LIST_LIMIT,
  MAX_OPERATOR_USER_ID_LENGTH,
  MAX_RECOVERY_ID_LENGTH,
  MAX_REPLAY_REASON_LENGTH,
  MAX_REQUEST_ID_LENGTH,
  MAX_TRACEPARENT_LENGTH,
  REPLAY_ALLOWED_FIELDS,
  VALID_CONTRACT_TYPES,
  VALID_INTEGRATION_LIFECYCLE_STATUSES,
  VALID_RECOVERY_STATUSES,
  isPlainObject,
  mapRecoveryRecord,
  mapStoreError,
  normalizeContractType,
  normalizeContractVersion,
  normalizeIntegrationId,
  normalizeLastHttpStatus,
  normalizeRecoveryId,
  normalizeRecoveryStatus,
  normalizeStoreIsoTimestamp,
  normalizeStoreOptionalString,
  normalizeStrictOptionalString,
  normalizeStrictRequiredString,
  parseJsonValue,
  parseListQuery,
  parseReplayPayload,
  recoveryErrors,
  recoveryProblem,
  resolveStoreFieldValue
};

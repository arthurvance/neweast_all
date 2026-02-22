const { log } = require('../../common/logger');
const { AuthProblemError } = require('../auth/auth.service');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_INTEGRATION_DIRECTIONS,
  PLATFORM_INTEGRATION_LIFECYCLE_STATUSES,
  PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_SCOPE
} = require('./integration.constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const MAX_INTEGRATION_ID_LENGTH = 64;
const MAX_OPERATOR_USER_ID_LENGTH = 64;
const MAX_CODE_LENGTH = 64;
const MAX_NAME_LENGTH = 128;
const MAX_PROTOCOL_LENGTH = 64;
const MAX_AUTH_MODE_LENGTH = 64;
const MAX_ENDPOINT_LENGTH = 512;
const MAX_BASE_URL_LENGTH = 512;
const MAX_VERSION_STRATEGY_LENGTH = 128;
const MAX_RUNBOOK_URL_LENGTH = 512;
const MAX_LIFECYCLE_REASON_LENGTH = 256;
const MAX_LIST_KEYWORD_LENGTH = 128;
const MAX_FREEZE_ID_LENGTH = 64;
const MAX_FREEZE_REASON_LENGTH = 256;
const DEFAULT_TIMEOUT_MS = 3000;
const MAX_TIMEOUT_MS = 300000;
const DEFAULT_PAGE = 1;
const DEFAULT_PAGE_SIZE = 20;
const MAX_PAGE_SIZE = 100;

const VALID_DIRECTIONS = new Set(PLATFORM_INTEGRATION_DIRECTIONS);
const VALID_LIFECYCLE_STATUSES = new Set(PLATFORM_INTEGRATION_LIFECYCLE_STATUSES);
const CREATE_ALLOWED_FIELDS = new Set([
  'integration_id',
  'code',
  'name',
  'direction',
  'protocol',
  'auth_mode',
  'endpoint',
  'base_url',
  'timeout_ms',
  'retry_policy',
  'idempotency_policy',
  'version_strategy',
  'runbook_url',
  'lifecycle_status',
  'lifecycle_reason'
]);
const UPDATE_ALLOWED_FIELDS = new Set([
  'code',
  'name',
  'direction',
  'protocol',
  'auth_mode',
  'endpoint',
  'base_url',
  'timeout_ms',
  'retry_policy',
  'idempotency_policy',
  'version_strategy',
  'runbook_url',
  'lifecycle_reason'
]);
const LIFECYCLE_ALLOWED_FIELDS = new Set(['status', 'reason']);
const LIST_ALLOWED_QUERY_FIELDS = new Set([
  'page',
  'page_size',
  'direction',
  'protocol',
  'auth_mode',
  'lifecycle_status',
  'keyword'
]);

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

const normalizeIntegrationId = (integrationId) =>
  normalizeStrictRequiredString(integrationId).toLowerCase();

const normalizeDirection = (direction) =>
  String(direction || '').trim().toLowerCase();

const normalizeLifecycleStatus = (status) =>
  String(status || '').trim().toLowerCase();

const normalizePolicyPayload = (value) => {
  if (value === undefined) {
    return undefined;
  }
  if (value === null) {
    return null;
  }
  if (isPlainObject(value) || Array.isArray(value)) {
    return value;
  }
  return undefined;
};

const normalizeStoreIsoTimestamp = (value) => {
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (typeof value !== 'string') {
    return '';
  }
  const normalized = value.trim();
  if (!normalized) {
    return '';
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

const integrationProblem = ({
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

const integrationErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    integrationProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'INT-400-INVALID-PAYLOAD'
    }),

  forbidden: () =>
    integrationProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  integrationNotFound: () =>
    integrationProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标集成目录不存在',
      errorCode: 'INT-404-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  codeConflict: () =>
    integrationProblem({
      status: 409,
      title: 'Conflict',
      detail: '集成编码冲突，请使用其他 code',
      errorCode: 'INT-409-CODE-CONFLICT',
      extensions: {
        retryable: false
      }
    }),

  integrationIdConflict: () =>
    integrationProblem({
      status: 409,
      title: 'Conflict',
      detail: '集成标识冲突，请重试创建流程',
      errorCode: 'INT-409-INTEGRATION-ID-CONFLICT',
      extensions: {
        retryable: false
      }
    }),

  lifecycleConflict: ({
    previousStatus = null,
    requestedStatus = null
  } = {}) =>
    integrationProblem({
      status: 409,
      title: 'Conflict',
      detail: '生命周期状态流转冲突',
      errorCode: 'INT-409-LIFECYCLE-CONFLICT',
      extensions: {
        retryable: false,
        previous_status: previousStatus,
        requested_status: requestedStatus
      }
    }),

  freezeBlocked: ({
    freezeId = null,
    frozenAt = null
  } = {}) =>
    integrationProblem({
      status: 409,
      title: 'Conflict',
      detail: '发布冻结窗口生效，当前集成变更操作已阻断',
      errorCode: 'INT-409-INTEGRATION-FREEZE-BLOCKED',
      extensions: {
        retryable: false,
        freeze_id: freezeId,
        frozen_at: frozenAt
      }
    }),

  dependencyUnavailable: ({ reason = 'dependency-unavailable' } = {}) =>
    integrationProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '集成目录治理依赖暂不可用，请稍后重试',
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
  if (
    normalizedErrorCode === 'ER_DUP_ENTRY'
    || Number(error?.errno || 0) === 1062
  ) {
    const conflictTarget = String(
      error?.platformIntegrationCatalogConflictTarget
      || error?.conflictTarget
      || ''
    ).trim().toLowerCase();
    return conflictTarget === 'integration_id'
      ? integrationErrors.integrationIdConflict()
      : integrationErrors.codeConflict();
  }
  if (normalizedErrorCode === 'ERR_PLATFORM_INTEGRATION_LIFECYCLE_CONFLICT') {
    return integrationErrors.lifecycleConflict({
      previousStatus: error?.previousStatus || null,
      requestedStatus: error?.requestedStatus || null
    });
  }
  if (normalizedErrorCode === 'ERR_PLATFORM_INTEGRATION_FREEZE_ACTIVE_CONFLICT') {
    return integrationErrors.freezeBlocked({
      freezeId: normalizeIntegrationId(error?.freezeId) || null,
      frozenAt: normalizeStoreIsoTimestamp(error?.frozenAt) || null
    });
  }
  return integrationErrors.dependencyUnavailable({
    reason: normalizedErrorCode
      || String(error?.message || 'dependency-unavailable').trim().toLowerCase()
  });
};

const mapIntegrationRecord = ({
  record,
  requestId
} = {}) => {
  if (!record || typeof record !== 'object') {
    return null;
  }
  const integrationId = normalizeIntegrationId(
    record.integrationId || record.integration_id
  );
  const code = normalizeStrictRequiredString(record.code);
  const name = normalizeStrictRequiredString(record.name);
  const direction = normalizeDirection(record.direction);
  const protocol = normalizeStrictRequiredString(record.protocol);
  const authMode = normalizeStrictRequiredString(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'authMode',
      snakeCaseKey: 'auth_mode'
    })
  );
  const lifecycleStatus = normalizeLifecycleStatus(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'lifecycleStatus',
      snakeCaseKey: 'lifecycle_status'
    })
  );
  const timeoutMs = Number(record.timeoutMs ?? record.timeout_ms);
  const endpoint = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'endpoint',
    snakeCaseKey: 'endpoint',
    maxLength: MAX_ENDPOINT_LENGTH
  });
  const baseUrl = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'baseUrl',
    snakeCaseKey: 'base_url',
    maxLength: MAX_BASE_URL_LENGTH
  });
  const versionStrategy = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'versionStrategy',
    snakeCaseKey: 'version_strategy',
    maxLength: MAX_VERSION_STRATEGY_LENGTH
  });
  const runbookUrl = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'runbookUrl',
    snakeCaseKey: 'runbook_url',
    maxLength: MAX_RUNBOOK_URL_LENGTH
  });
  const lifecycleReason = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'lifecycleReason',
    snakeCaseKey: 'lifecycle_reason',
    maxLength: MAX_LIFECYCLE_REASON_LENGTH
  });
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
  const retryPolicy =
    record.retryPolicy === undefined
      ? (record.retry_policy ?? null)
      : (record.retryPolicy ?? null);
  const idempotencyPolicy =
    record.idempotencyPolicy === undefined
      ? (record.idempotency_policy ?? null)
      : (record.idempotencyPolicy ?? null);
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
  if (
    !integrationId
    || integrationId.length > MAX_INTEGRATION_ID_LENGTH
    || !code
    || code.length > MAX_CODE_LENGTH
    || !name
    || name.length > MAX_NAME_LENGTH
    || !VALID_DIRECTIONS.has(direction)
    || !protocol
    || protocol.length > MAX_PROTOCOL_LENGTH
    || !authMode
    || authMode.length > MAX_AUTH_MODE_LENGTH
    || !VALID_LIFECYCLE_STATUSES.has(lifecycleStatus)
    || !Number.isInteger(timeoutMs)
    || timeoutMs < 1
    || timeoutMs > MAX_TIMEOUT_MS
    || endpoint === undefined
    || baseUrl === undefined
    || versionStrategy === undefined
    || runbookUrl === undefined
    || lifecycleReason === undefined
    || createdByUserId === undefined
    || updatedByUserId === undefined
    || (
      retryPolicy !== null
      && !isPlainObject(retryPolicy)
      && !Array.isArray(retryPolicy)
    )
    || (
      idempotencyPolicy !== null
      && !isPlainObject(idempotencyPolicy)
      && !Array.isArray(idempotencyPolicy)
    )
    || !createdAt
    || !updatedAt
  ) {
    return null;
  }
  return {
    integration_id: integrationId,
    code,
    name,
    direction,
    protocol,
    auth_mode: authMode,
    endpoint,
    base_url: baseUrl,
    timeout_ms: timeoutMs,
    retry_policy: retryPolicy,
    idempotency_policy: idempotencyPolicy,
    version_strategy: versionStrategy,
    runbook_url: runbookUrl,
    lifecycle_status: lifecycleStatus,
    lifecycle_reason: lifecycleReason,
    created_by_user_id: createdByUserId,
    updated_by_user_id: updatedByUserId,
    created_at: createdAt,
    updated_at: updatedAt,
    effective_invocation_enabled: lifecycleStatus === 'active',
    request_id: String(requestId || '').trim() || 'request_id_unset'
  };
};

const mapActiveFreezeRecordForWriteGate = ({
  record
} = {}) => {
  if (!record || typeof record !== 'object') {
    return null;
  }
  const freezeId = normalizeIntegrationId(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'freezeId',
      snakeCaseKey: 'freeze_id'
    })
  );
  const status = String(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'status',
      snakeCaseKey: 'status'
    })
  ).trim().toLowerCase();
  const freezeReason = normalizeStrictRequiredString(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'freezeReason',
      snakeCaseKey: 'freeze_reason'
    })
  );
  const frozenAt = normalizeStoreIsoTimestamp(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'frozenAt',
      snakeCaseKey: 'frozen_at'
    })
  );
  if (
    !freezeId
    || freezeId.length > MAX_FREEZE_ID_LENGTH
    || status !== 'active'
    || !freezeReason
    || freezeReason.length > MAX_FREEZE_REASON_LENGTH
    || !frozenAt
  ) {
    return null;
  }
  return {
    freeze_id: freezeId,
    status,
    freeze_reason: freezeReason,
    frozen_at: frozenAt
  };
};

const parseListQuery = (query = {}) => {
  if (!isPlainObject(query)) {
    throw integrationErrors.invalidPayload();
  }
  const unknownQueryKeys = Object.keys(query).filter(
    (key) => !LIST_ALLOWED_QUERY_FIELDS.has(key)
  );
  if (unknownQueryKeys.length > 0) {
    throw integrationErrors.invalidPayload();
  }
  const parsedPage = Number(
    Object.prototype.hasOwnProperty.call(query, 'page')
      ? query.page
      : DEFAULT_PAGE
  );
  const parsedPageSize = Number(
    Object.prototype.hasOwnProperty.call(query, 'page_size')
      ? query.page_size
      : DEFAULT_PAGE_SIZE
  );
  if (
    !Number.isInteger(parsedPage)
    || parsedPage < 1
    || !Number.isInteger(parsedPageSize)
    || parsedPageSize < 1
    || parsedPageSize > MAX_PAGE_SIZE
  ) {
    throw integrationErrors.invalidPayload();
  }
  const direction = query.direction === undefined
    ? null
    : normalizeDirection(query.direction);
  if (direction !== null && !VALID_DIRECTIONS.has(direction)) {
    throw integrationErrors.invalidPayload('direction 非法');
  }
  const lifecycleStatus = query.lifecycle_status === undefined
    ? null
    : normalizeLifecycleStatus(query.lifecycle_status);
  if (
    lifecycleStatus !== null
    && !VALID_LIFECYCLE_STATUSES.has(lifecycleStatus)
  ) {
    throw integrationErrors.invalidPayload('lifecycle_status 非法');
  }
  const protocol = query.protocol === undefined
    ? null
    : normalizeStrictRequiredString(query.protocol);
  if (
    query.protocol !== undefined
    && (
      !protocol
      || protocol.length > MAX_PROTOCOL_LENGTH
    )
  ) {
    throw integrationErrors.invalidPayload('protocol 非法');
  }
  const authMode = query.auth_mode === undefined
    ? null
    : normalizeStrictRequiredString(query.auth_mode);
  if (
    query.auth_mode !== undefined
    && (
      !authMode
      || authMode.length > MAX_AUTH_MODE_LENGTH
    )
  ) {
    throw integrationErrors.invalidPayload('auth_mode 非法');
  }
  const keyword = query.keyword === undefined
    ? null
    : normalizeStrictRequiredString(query.keyword);
  if (
    query.keyword !== undefined
    && (
      !keyword
      || keyword.length > MAX_LIST_KEYWORD_LENGTH
    )
  ) {
    throw integrationErrors.invalidPayload('keyword 非法');
  }
  return {
    page: parsedPage,
    pageSize: parsedPageSize,
    direction,
    protocol,
    authMode,
    lifecycleStatus,
    keyword
  };
};

const parseCreatePayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw integrationErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !CREATE_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw integrationErrors.invalidPayload();
  }
  const requiredFields = [
    'code',
    'name',
    'direction',
    'protocol',
    'auth_mode'
  ];
  for (const field of requiredFields) {
    if (!Object.prototype.hasOwnProperty.call(payload, field)) {
      throw integrationErrors.invalidPayload(`${field} 必填`);
    }
  }
  const integrationId = Object.prototype.hasOwnProperty.call(payload, 'integration_id')
    ? normalizeIntegrationId(payload.integration_id)
    : '';
  if (
    payload.integration_id !== undefined
    && (
      !integrationId
      || integrationId.length > MAX_INTEGRATION_ID_LENGTH
    )
  ) {
    throw integrationErrors.invalidPayload('integration_id 非法');
  }
  const code = normalizeStrictRequiredString(payload.code);
  const name = normalizeStrictRequiredString(payload.name);
  const direction = normalizeDirection(payload.direction);
  const protocol = normalizeStrictRequiredString(payload.protocol);
  const authMode = normalizeStrictRequiredString(payload.auth_mode);
  if (!code || code.length > MAX_CODE_LENGTH) {
    throw integrationErrors.invalidPayload(`code 长度不能超过 ${MAX_CODE_LENGTH}`);
  }
  if (!name || name.length > MAX_NAME_LENGTH) {
    throw integrationErrors.invalidPayload(`name 长度不能超过 ${MAX_NAME_LENGTH}`);
  }
  if (!VALID_DIRECTIONS.has(direction)) {
    throw integrationErrors.invalidPayload('direction 必须为 inbound/outbound/bidirectional');
  }
  if (!protocol || protocol.length > MAX_PROTOCOL_LENGTH) {
    throw integrationErrors.invalidPayload(
      `protocol 长度不能超过 ${MAX_PROTOCOL_LENGTH}`
    );
  }
  if (!authMode || authMode.length > MAX_AUTH_MODE_LENGTH) {
    throw integrationErrors.invalidPayload(
      `auth_mode 长度不能超过 ${MAX_AUTH_MODE_LENGTH}`
    );
  }
  const endpoint = Object.prototype.hasOwnProperty.call(payload, 'endpoint')
    ? normalizeStrictOptionalString({
      value: payload.endpoint,
      maxLength: MAX_ENDPOINT_LENGTH
    })
    : null;
  if (endpoint === undefined) {
    throw integrationErrors.invalidPayload(`endpoint 长度不能超过 ${MAX_ENDPOINT_LENGTH}`);
  }
  const baseUrl = Object.prototype.hasOwnProperty.call(payload, 'base_url')
    ? normalizeStrictOptionalString({
      value: payload.base_url,
      maxLength: MAX_BASE_URL_LENGTH
    })
    : null;
  if (baseUrl === undefined) {
    throw integrationErrors.invalidPayload(`base_url 长度不能超过 ${MAX_BASE_URL_LENGTH}`);
  }
  const parsedTimeoutMs = Object.prototype.hasOwnProperty.call(payload, 'timeout_ms')
    ? Number(payload.timeout_ms)
    : DEFAULT_TIMEOUT_MS;
  if (
    !Number.isInteger(parsedTimeoutMs)
    || parsedTimeoutMs < 1
    || parsedTimeoutMs > MAX_TIMEOUT_MS
  ) {
    throw integrationErrors.invalidPayload(
      `timeout_ms 必须为 1 到 ${MAX_TIMEOUT_MS} 的整数`
    );
  }
  const retryPolicy = Object.prototype.hasOwnProperty.call(payload, 'retry_policy')
    ? normalizePolicyPayload(payload.retry_policy)
    : null;
  const idempotencyPolicy = Object.prototype.hasOwnProperty.call(
    payload,
    'idempotency_policy'
  )
    ? normalizePolicyPayload(payload.idempotency_policy)
    : null;
  if (retryPolicy === undefined || idempotencyPolicy === undefined) {
    throw integrationErrors.invalidPayload('retry_policy/idempotency_policy 必须为对象或数组');
  }
  const versionStrategy = Object.prototype.hasOwnProperty.call(payload, 'version_strategy')
    ? normalizeStrictOptionalString({
      value: payload.version_strategy,
      maxLength: MAX_VERSION_STRATEGY_LENGTH
    })
    : null;
  if (versionStrategy === undefined) {
    throw integrationErrors.invalidPayload(
      `version_strategy 长度不能超过 ${MAX_VERSION_STRATEGY_LENGTH}`
    );
  }
  const runbookUrl = Object.prototype.hasOwnProperty.call(payload, 'runbook_url')
    ? normalizeStrictOptionalString({
      value: payload.runbook_url,
      maxLength: MAX_RUNBOOK_URL_LENGTH
    })
    : null;
  if (runbookUrl === undefined) {
    throw integrationErrors.invalidPayload(`runbook_url 长度不能超过 ${MAX_RUNBOOK_URL_LENGTH}`);
  }
  const lifecycleStatus = Object.prototype.hasOwnProperty.call(payload, 'lifecycle_status')
    ? normalizeLifecycleStatus(payload.lifecycle_status)
    : 'draft';
  if (!VALID_LIFECYCLE_STATUSES.has(lifecycleStatus)) {
    throw integrationErrors.invalidPayload('lifecycle_status 非法');
  }
  const lifecycleReason = Object.prototype.hasOwnProperty.call(payload, 'lifecycle_reason')
    ? normalizeStrictOptionalString({
      value: payload.lifecycle_reason,
      maxLength: MAX_LIFECYCLE_REASON_LENGTH
    })
    : null;
  if (lifecycleReason === undefined) {
    throw integrationErrors.invalidPayload(
      `lifecycle_reason 长度不能超过 ${MAX_LIFECYCLE_REASON_LENGTH}`
    );
  }
  return {
    integrationId: integrationId || undefined,
    code,
    name,
    direction,
    protocol,
    authMode,
    endpoint,
    baseUrl,
    timeoutMs: parsedTimeoutMs,
    retryPolicy,
    idempotencyPolicy,
    versionStrategy,
    runbookUrl,
    lifecycleStatus,
    lifecycleReason
  };
};

const parseUpdatePayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw integrationErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !UPDATE_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw integrationErrors.invalidPayload();
  }
  const hasAnyField = Object.keys(payload).length > 0;
  if (!hasAnyField) {
    throw integrationErrors.invalidPayload('至少提供一个可更新字段');
  }
  const updates = {};
  if (Object.prototype.hasOwnProperty.call(payload, 'code')) {
    const code = normalizeStrictRequiredString(payload.code);
    if (!code || code.length > MAX_CODE_LENGTH) {
      throw integrationErrors.invalidPayload(`code 长度不能超过 ${MAX_CODE_LENGTH}`);
    }
    updates.code = code;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'name')) {
    const name = normalizeStrictRequiredString(payload.name);
    if (!name || name.length > MAX_NAME_LENGTH) {
      throw integrationErrors.invalidPayload(`name 长度不能超过 ${MAX_NAME_LENGTH}`);
    }
    updates.name = name;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'direction')) {
    const direction = normalizeDirection(payload.direction);
    if (!VALID_DIRECTIONS.has(direction)) {
      throw integrationErrors.invalidPayload('direction 非法');
    }
    updates.direction = direction;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'protocol')) {
    const protocol = normalizeStrictRequiredString(payload.protocol);
    if (!protocol || protocol.length > MAX_PROTOCOL_LENGTH) {
      throw integrationErrors.invalidPayload(
        `protocol 长度不能超过 ${MAX_PROTOCOL_LENGTH}`
      );
    }
    updates.protocol = protocol;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'auth_mode')) {
    const authMode = normalizeStrictRequiredString(payload.auth_mode);
    if (!authMode || authMode.length > MAX_AUTH_MODE_LENGTH) {
      throw integrationErrors.invalidPayload(
        `auth_mode 长度不能超过 ${MAX_AUTH_MODE_LENGTH}`
      );
    }
    updates.authMode = authMode;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'endpoint')) {
    const endpoint = normalizeStrictOptionalString({
      value: payload.endpoint,
      maxLength: MAX_ENDPOINT_LENGTH
    });
    if (endpoint === undefined) {
      throw integrationErrors.invalidPayload(
        `endpoint 长度不能超过 ${MAX_ENDPOINT_LENGTH}`
      );
    }
    updates.endpoint = endpoint;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'base_url')) {
    const baseUrl = normalizeStrictOptionalString({
      value: payload.base_url,
      maxLength: MAX_BASE_URL_LENGTH
    });
    if (baseUrl === undefined) {
      throw integrationErrors.invalidPayload(
        `base_url 长度不能超过 ${MAX_BASE_URL_LENGTH}`
      );
    }
    updates.baseUrl = baseUrl;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'timeout_ms')) {
    const parsedTimeoutMs = Number(payload.timeout_ms);
    if (
      !Number.isInteger(parsedTimeoutMs)
      || parsedTimeoutMs < 1
      || parsedTimeoutMs > MAX_TIMEOUT_MS
    ) {
      throw integrationErrors.invalidPayload(
        `timeout_ms 必须为 1 到 ${MAX_TIMEOUT_MS} 的整数`
      );
    }
    updates.timeoutMs = parsedTimeoutMs;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'retry_policy')) {
    const retryPolicy = normalizePolicyPayload(payload.retry_policy);
    if (retryPolicy === undefined) {
      throw integrationErrors.invalidPayload('retry_policy 必须为对象或数组');
    }
    updates.retryPolicy = retryPolicy;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'idempotency_policy')) {
    const idempotencyPolicy = normalizePolicyPayload(payload.idempotency_policy);
    if (idempotencyPolicy === undefined) {
      throw integrationErrors.invalidPayload('idempotency_policy 必须为对象或数组');
    }
    updates.idempotencyPolicy = idempotencyPolicy;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'version_strategy')) {
    const versionStrategy = normalizeStrictOptionalString({
      value: payload.version_strategy,
      maxLength: MAX_VERSION_STRATEGY_LENGTH
    });
    if (versionStrategy === undefined) {
      throw integrationErrors.invalidPayload(
        `version_strategy 长度不能超过 ${MAX_VERSION_STRATEGY_LENGTH}`
      );
    }
    updates.versionStrategy = versionStrategy;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'runbook_url')) {
    const runbookUrl = normalizeStrictOptionalString({
      value: payload.runbook_url,
      maxLength: MAX_RUNBOOK_URL_LENGTH
    });
    if (runbookUrl === undefined) {
      throw integrationErrors.invalidPayload(
        `runbook_url 长度不能超过 ${MAX_RUNBOOK_URL_LENGTH}`
      );
    }
    updates.runbookUrl = runbookUrl;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'lifecycle_reason')) {
    const lifecycleReason = normalizeStrictOptionalString({
      value: payload.lifecycle_reason,
      maxLength: MAX_LIFECYCLE_REASON_LENGTH
    });
    if (lifecycleReason === undefined) {
      throw integrationErrors.invalidPayload(
        `lifecycle_reason 长度不能超过 ${MAX_LIFECYCLE_REASON_LENGTH}`
      );
    }
    updates.lifecycleReason = lifecycleReason;
  }
  return updates;
};

const parseLifecyclePayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw integrationErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !LIFECYCLE_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw integrationErrors.invalidPayload();
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'status')) {
    throw integrationErrors.invalidPayload('status 必填');
  }
  const nextStatus = normalizeLifecycleStatus(payload.status);
  if (!VALID_LIFECYCLE_STATUSES.has(nextStatus)) {
    throw integrationErrors.invalidPayload('status 非法');
  }
  const reason = Object.prototype.hasOwnProperty.call(payload, 'reason')
    ? normalizeStrictOptionalString({
      value: payload.reason,
      maxLength: MAX_LIFECYCLE_REASON_LENGTH
    })
    : null;
  if (reason === undefined) {
    throw integrationErrors.invalidPayload(
      `reason 长度不能超过 ${MAX_LIFECYCLE_REASON_LENGTH}`
    );
  }
  return {
    nextStatus,
    reason
  };
};

const createPlatformIntegrationService = ({ authService } = {}) => {
  const auditTrail = [];

  const addAuditEvent = ({
    type,
    requestId,
    operatorUserId = 'unknown',
    targetIntegrationId = null,
    detail,
    metadata = {}
  }) => {
    const event = {
      type: String(type || '').trim() || 'platform.integration.unknown',
      at: new Date().toISOString(),
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      target_integration_id: targetIntegrationId ? String(targetIntegrationId) : null,
      detail: String(detail || '').trim(),
      ...metadata
    };
    auditTrail.push(event);
    if (auditTrail.length > MAX_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Platform integration audit event', event);
  };

  const assertAuthServiceMethod = (methodName) => {
    if (!authService || typeof authService[methodName] !== 'function') {
      throw integrationErrors.dependencyUnavailable();
    }
  };

  const resolveAuthStore = () => authService?._internals?.authStore || null;

  const assertAuthStoreMethod = (methodName) => {
    const authStore = resolveAuthStore();
    if (!authStore || typeof authStore[methodName] !== 'function') {
      throw integrationErrors.dependencyUnavailable({
        reason: `auth-store-${methodName}-unsupported`
      });
    }
    return authStore;
  };

  const recordFreezeChangeBlockedAuditEvent = async ({
    requestId,
    traceparent = null,
    operatorUserId = null,
    operatorSessionId = null,
    targetIntegrationId = null,
    changeOperation = 'unknown',
    activeFreeze = null,
    changePayload = null
  } = {}) => {
    const authStore = assertAuthStoreMethod('recordAuditEvent');
    try {
      await authStore.recordAuditEvent({
        domain: 'platform',
        requestId,
        traceparent,
        eventType: 'platform.integration.freeze.change_blocked',
        actorUserId: operatorUserId,
        actorSessionId: operatorSessionId,
        targetType: 'integration',
        targetId: targetIntegrationId,
        result: 'rejected',
        beforeState: activeFreeze
          ? {
            freeze_id: activeFreeze.freeze_id,
            status: activeFreeze.status,
            freeze_reason: activeFreeze.freeze_reason,
            frozen_at: activeFreeze.frozen_at
          }
          : null,
        afterState: null,
        metadata: {
          change_operation: String(changeOperation || '').trim() || 'unknown',
          change_payload: isPlainObject(changePayload) ? changePayload : null
        }
      });
    } catch (error) {
      throw mapStoreError(error);
    }
  };

  const maybeRecordFreezeBlockedAuditEvent = async ({
    mappedError = null,
    requestId,
    traceparent = null,
    operatorUserId = null,
    operatorSessionId = null,
    targetIntegrationId = null,
    changeOperation = 'unknown',
    changePayload = null
  } = {}) => {
    if (
      !(mappedError instanceof AuthProblemError)
      || mappedError.errorCode !== 'INT-409-INTEGRATION-FREEZE-BLOCKED'
    ) {
      return;
    }
    let activeFreeze = null;
    try {
      const authStore = assertAuthStoreMethod('findActivePlatformIntegrationFreeze');
      activeFreeze = mapActiveFreezeRecordForWriteGate({
        record: await authStore.findActivePlatformIntegrationFreeze()
      });
    } catch (_error) {
      activeFreeze = null;
    }
    if (!activeFreeze) {
      const freezeId = normalizeIntegrationId(mappedError?.extensions?.freeze_id);
      const frozenAt = normalizeStoreIsoTimestamp(mappedError?.extensions?.frozen_at);
      if (freezeId && frozenAt) {
        activeFreeze = {
          freeze_id: freezeId,
          status: 'active',
          freeze_reason: null,
          frozen_at: frozenAt
        };
      }
    }
    if (!activeFreeze) {
      return;
    }
    await recordFreezeChangeBlockedAuditEvent({
      requestId,
      traceparent,
      operatorUserId,
      operatorSessionId,
      targetIntegrationId,
      changeOperation,
      activeFreeze,
      changePayload
    });
  };

  const assertNotFrozenForWrite = async ({
    requestId,
    traceparent = null,
    operatorUserId = null,
    operatorSessionId = null,
    targetIntegrationId = null,
    changeOperation = 'unknown',
    changePayload = null
  } = {}) => {
    const authStore = assertAuthStoreMethod('findActivePlatformIntegrationFreeze');
    let activeFreezeRecord;
    try {
      activeFreezeRecord = await authStore.findActivePlatformIntegrationFreeze();
    } catch (error) {
      throw mapStoreError(error);
    }
    if (!activeFreezeRecord) {
      return;
    }
    const activeFreeze = mapActiveFreezeRecordForWriteGate({
      record: activeFreezeRecord
    });
    if (!activeFreeze) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-freeze-state-malformed'
      });
    }
    await recordFreezeChangeBlockedAuditEvent({
      requestId,
      traceparent,
      operatorUserId,
      operatorSessionId,
      targetIntegrationId,
      changeOperation,
      activeFreeze,
      changePayload
    });
    throw integrationErrors.freezeBlocked({
      freezeId: activeFreeze.freeze_id,
      frozenAt: activeFreeze.frozen_at
    });
  };

  const resolvePreauthorizedOperatorContext = ({
    authorizationContext = null,
    expectedPermissionCode = PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE
  } = {}) => {
    const preauthorizedContext = resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_INTEGRATION_SCOPE,
      expectedEntryDomain: PLATFORM_INTEGRATION_SCOPE
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
    permissionCode = PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE
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
      scope: PLATFORM_INTEGRATION_SCOPE,
      authorizationContext
    });
    const operatorUserId = normalizeStrictRequiredString(
      authorized?.user_id || authorized?.userId
    );
    const operatorSessionId = normalizeStrictRequiredString(
      authorized?.session_id || authorized?.sessionId
    );
    if (!operatorUserId || !operatorSessionId) {
      throw integrationErrors.forbidden();
    }
    return {
      operatorUserId,
      operatorSessionId
    };
  };

  const listIntegrations = async ({
    requestId,
    accessToken,
    query = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const filters = parseListQuery(query || {});
    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      addAuditEvent({
        type: 'platform.integration.list.rejected',
        requestId: resolvedRequestId,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: String(error?.errorCode || 'AUTH-403-FORBIDDEN')
        }
      });
      throw error;
    }
    const authStore = assertAuthStoreMethod('listPlatformIntegrationCatalogEntries');
    let list;
    try {
      list = await authStore.listPlatformIntegrationCatalogEntries({
        direction: filters.direction,
        protocol: filters.protocol,
        authMode: filters.authMode,
        lifecycleStatus: filters.lifecycleStatus,
        keyword: filters.keyword
      });
    } catch (error) {
      const mappedError = mapStoreError(error);
      addAuditEvent({
        type: 'platform.integration.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        detail: 'integration catalog list dependency unavailable',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    if (!Array.isArray(list)) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-catalog-list-invalid'
      });
    }
    const mappedIntegrations = list.map((record) =>
      mapIntegrationRecord({
        record,
        requestId: resolvedRequestId
      })
    );
    if (mappedIntegrations.some((record) => !record)) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-catalog-list-result-malformed'
      });
    }
    const total = mappedIntegrations.length;
    const start = (filters.page - 1) * filters.pageSize;
    const end = start + filters.pageSize;
    const pagedIntegrations = mappedIntegrations.slice(start, end);
    addAuditEvent({
      type: 'platform.integration.list.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      detail: 'integration catalog listed',
      metadata: {
        total
      }
    });
    return {
      page: filters.page,
      page_size: filters.pageSize,
      total,
      integrations: pagedIntegrations,
      request_id: resolvedRequestId
    };
  };

  const getIntegration = async ({
    requestId,
    accessToken,
    integrationId,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    if (
      !normalizedIntegrationId
      || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
    ) {
      throw integrationErrors.invalidPayload('integration_id 非法');
    }
    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      addAuditEvent({
        type: 'platform.integration.read.rejected',
        requestId: resolvedRequestId,
        targetIntegrationId: normalizedIntegrationId,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: String(error?.errorCode || 'AUTH-403-FORBIDDEN')
        }
      });
      throw error;
    }
    const authStore = assertAuthStoreMethod(
      'findPlatformIntegrationCatalogEntryByIntegrationId'
    );
    let record = null;
    try {
      record = await authStore.findPlatformIntegrationCatalogEntryByIntegrationId({
        integrationId: normalizedIntegrationId
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    if (!record) {
      throw integrationErrors.integrationNotFound();
    }
    const mapped = mapIntegrationRecord({
      record,
      requestId: resolvedRequestId
    });
    if (!mapped) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-catalog-read-result-invalid'
      });
    }
    addAuditEvent({
      type: 'platform.integration.read.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetIntegrationId: normalizedIntegrationId,
      detail: 'integration catalog entry loaded'
    });
    return mapped;
  };

  const createIntegration = async ({
    requestId,
    accessToken,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const parsedPayload = parseCreatePayload(payload);
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE
    });
    await assertNotFrozenForWrite({
      requestId: resolvedRequestId,
      traceparent,
      operatorUserId: operatorContext.operatorUserId,
      operatorSessionId: operatorContext.operatorSessionId,
      targetIntegrationId: parsedPayload.integrationId || null,
      changeOperation: 'create',
      changePayload: {
        integration_id: parsedPayload.integrationId || null,
        code: parsedPayload.code,
        direction: parsedPayload.direction,
        lifecycle_status: parsedPayload.lifecycleStatus
      }
    });
    const authStore = assertAuthStoreMethod('createPlatformIntegrationCatalogEntry');
    let createdRecord = null;
    try {
      createdRecord = await authStore.createPlatformIntegrationCatalogEntry({
        integrationId: parsedPayload.integrationId,
        code: parsedPayload.code,
        name: parsedPayload.name,
        direction: parsedPayload.direction,
        protocol: parsedPayload.protocol,
        authMode: parsedPayload.authMode,
        endpoint: parsedPayload.endpoint,
        baseUrl: parsedPayload.baseUrl,
        timeoutMs: parsedPayload.timeoutMs,
        retryPolicy: parsedPayload.retryPolicy,
        idempotencyPolicy: parsedPayload.idempotencyPolicy,
        versionStrategy: parsedPayload.versionStrategy,
        runbookUrl: parsedPayload.runbookUrl,
        lifecycleStatus: parsedPayload.lifecycleStatus,
        lifecycleReason: parsedPayload.lifecycleReason,
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
      await maybeRecordFreezeBlockedAuditEvent({
        mappedError,
        requestId: resolvedRequestId,
        traceparent,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        targetIntegrationId: parsedPayload.integrationId || null,
        changeOperation: 'create',
        changePayload: {
          integration_id: parsedPayload.integrationId || null,
          code: parsedPayload.code,
          direction: parsedPayload.direction,
          lifecycle_status: parsedPayload.lifecycleStatus
        }
      });
      addAuditEvent({
        type: 'platform.integration.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        detail: 'integration catalog create failed',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    const mapped = mapIntegrationRecord({
      record: createdRecord,
      requestId: resolvedRequestId
    });
    if (!mapped) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-catalog-create-result-invalid'
      });
    }
    addAuditEvent({
      type: 'platform.integration.create.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetIntegrationId: mapped.integration_id,
      detail: 'integration catalog entry created'
    });
    return mapped;
  };

  const updateIntegration = async ({
    requestId,
    accessToken,
    integrationId,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    if (
      !normalizedIntegrationId
      || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
    ) {
      throw integrationErrors.invalidPayload('integration_id 非法');
    }
    const parsedPayload = parseUpdatePayload(payload);
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE
    });
    await assertNotFrozenForWrite({
      requestId: resolvedRequestId,
      traceparent,
      operatorUserId: operatorContext.operatorUserId,
      operatorSessionId: operatorContext.operatorSessionId,
      targetIntegrationId: normalizedIntegrationId,
      changeOperation: 'update',
      changePayload: {
        integration_id: normalizedIntegrationId,
        fields: Object.keys(parsedPayload)
      }
    });
    const authStore = assertAuthStoreMethod('updatePlatformIntegrationCatalogEntry');
    let updatedRecord = null;
    try {
      updatedRecord = await authStore.updatePlatformIntegrationCatalogEntry({
        integrationId: normalizedIntegrationId,
        code: parsedPayload.code,
        name: parsedPayload.name,
        direction: parsedPayload.direction,
        protocol: parsedPayload.protocol,
        authMode: parsedPayload.authMode,
        endpoint: parsedPayload.endpoint,
        baseUrl: parsedPayload.baseUrl,
        timeoutMs: parsedPayload.timeoutMs,
        retryPolicy: parsedPayload.retryPolicy,
        idempotencyPolicy: parsedPayload.idempotencyPolicy,
        versionStrategy: parsedPayload.versionStrategy,
        runbookUrl: parsedPayload.runbookUrl,
        lifecycleReason: parsedPayload.lifecycleReason,
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
      await maybeRecordFreezeBlockedAuditEvent({
        mappedError,
        requestId: resolvedRequestId,
        traceparent,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        targetIntegrationId: normalizedIntegrationId,
        changeOperation: 'update',
        changePayload: {
          integration_id: normalizedIntegrationId,
          fields: Object.keys(parsedPayload)
        }
      });
      addAuditEvent({
        type: 'platform.integration.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetIntegrationId: normalizedIntegrationId,
        detail: 'integration catalog update failed',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    if (!updatedRecord) {
      throw integrationErrors.integrationNotFound();
    }
    const mapped = mapIntegrationRecord({
      record: updatedRecord,
      requestId: resolvedRequestId
    });
    if (!mapped) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-catalog-update-result-invalid'
      });
    }
    addAuditEvent({
      type: 'platform.integration.update.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetIntegrationId: normalizedIntegrationId,
      detail: 'integration catalog entry updated'
    });
    return mapped;
  };

  const changeIntegrationLifecycle = async ({
    requestId,
    accessToken,
    integrationId,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    if (
      !normalizedIntegrationId
      || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
    ) {
      throw integrationErrors.invalidPayload('integration_id 非法');
    }
    const parsedPayload = parseLifecyclePayload(payload);
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE
    });
    await assertNotFrozenForWrite({
      requestId: resolvedRequestId,
      traceparent,
      operatorUserId: operatorContext.operatorUserId,
      operatorSessionId: operatorContext.operatorSessionId,
      targetIntegrationId: normalizedIntegrationId,
      changeOperation: 'change_lifecycle',
      changePayload: {
        integration_id: normalizedIntegrationId,
        requested_status: parsedPayload.nextStatus,
        reason: parsedPayload.reason
      }
    });
    const authStore = assertAuthStoreMethod('transitionPlatformIntegrationLifecycle');
    let transitionResult = null;
    try {
      transitionResult = await authStore.transitionPlatformIntegrationLifecycle({
        integrationId: normalizedIntegrationId,
        nextStatus: parsedPayload.nextStatus,
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
      await maybeRecordFreezeBlockedAuditEvent({
        mappedError,
        requestId: resolvedRequestId,
        traceparent,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        targetIntegrationId: normalizedIntegrationId,
        changeOperation: 'change_lifecycle',
        changePayload: {
          integration_id: normalizedIntegrationId,
          requested_status: parsedPayload.nextStatus,
          reason: parsedPayload.reason
        }
      });
      addAuditEvent({
        type: 'platform.integration.lifecycle.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetIntegrationId: normalizedIntegrationId,
        detail: 'integration lifecycle transition failed',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    if (!transitionResult) {
      throw integrationErrors.integrationNotFound();
    }
    const mapped = mapIntegrationRecord({
      record: transitionResult,
      requestId: resolvedRequestId
    });
    if (!mapped) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-lifecycle-result-invalid'
      });
    }
    const previousStatus = normalizeLifecycleStatus(
      transitionResult.previousStatus || transitionResult.previous_status || ''
    );
    const currentStatus = normalizeLifecycleStatus(
      transitionResult.currentStatus || transitionResult.current_status || ''
    );
    if (
      !VALID_LIFECYCLE_STATUSES.has(previousStatus)
      || !VALID_LIFECYCLE_STATUSES.has(currentStatus)
      || currentStatus !== mapped.lifecycle_status
    ) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-lifecycle-result-malformed'
      });
    }
    const hasExplicitEffectiveInvocationEnabled =
      Object.prototype.hasOwnProperty.call(
        transitionResult,
        'effectiveInvocationEnabled'
      )
      || Object.prototype.hasOwnProperty.call(
        transitionResult,
        'effective_invocation_enabled'
      );
    const explicitEffectiveInvocationEnabled =
      transitionResult.effectiveInvocationEnabled === undefined
        ? transitionResult.effective_invocation_enabled
        : transitionResult.effectiveInvocationEnabled;
    if (
      hasExplicitEffectiveInvocationEnabled
      && typeof explicitEffectiveInvocationEnabled !== 'boolean'
    ) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-lifecycle-result-malformed'
      });
    }
    const derivedEffectiveInvocationEnabled = currentStatus === 'active';
    if (
      hasExplicitEffectiveInvocationEnabled
      && explicitEffectiveInvocationEnabled !== derivedEffectiveInvocationEnabled
    ) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-lifecycle-result-malformed'
      });
    }
    const effectiveInvocationEnabled = derivedEffectiveInvocationEnabled;
    addAuditEvent({
      type: 'platform.integration.lifecycle.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetIntegrationId: normalizedIntegrationId,
      detail: 'integration lifecycle transitioned',
      metadata: {
        previous_status: previousStatus,
        current_status: currentStatus
      }
    });
    return {
      ...mapped,
      previous_status: previousStatus,
      current_status: currentStatus,
      effective_invocation_enabled: effectiveInvocationEnabled
    };
  };

  return {
    listIntegrations,
    getIntegration,
    createIntegration,
    updateIntegration,
    changeIntegrationLifecycle,
    _internals: {
      authService,
      auditTrail
    }
  };
};

module.exports = {
  createPlatformIntegrationService
};

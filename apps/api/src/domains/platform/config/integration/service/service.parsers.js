'use strict';

const { log } = require('../../../../../common/logger');
const { AuthProblemError } = require('../../../../../shared-kernel/auth/auth-problem-error');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../../shared-kernel/auth/route-authz');
const {
  PLATFORM_INTEGRATION_DIRECTIONS,
  PLATFORM_INTEGRATION_LIFECYCLE_STATUSES,
  PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_SCOPE
} = require('../constants');

const { integrationErrors } = require('./service.errors');
const { CREATE_ALLOWED_FIELDS, DEFAULT_PAGE, DEFAULT_PAGE_SIZE, DEFAULT_TIMEOUT_MS, LIFECYCLE_ALLOWED_FIELDS, LIST_ALLOWED_QUERY_FIELDS, MAX_AUTH_MODE_LENGTH, MAX_BASE_URL_LENGTH, MAX_CODE_LENGTH, MAX_ENDPOINT_LENGTH, MAX_INTEGRATION_ID_LENGTH, MAX_LIFECYCLE_REASON_LENGTH, MAX_LIST_KEYWORD_LENGTH, MAX_NAME_LENGTH, MAX_PAGE_SIZE, MAX_PROTOCOL_LENGTH, MAX_RUNBOOK_URL_LENGTH, MAX_TIMEOUT_MS, MAX_VERSION_STRATEGY_LENGTH, UPDATE_ALLOWED_FIELDS, VALID_DIRECTIONS, VALID_LIFECYCLE_STATUSES, isPlainObject, normalizeDirection, normalizeIntegrationId, normalizeLifecycleStatus, normalizePolicyPayload, normalizeStrictOptionalString, normalizeStrictRequiredString } = require('./service.helpers');

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

module.exports = {
  parseCreatePayload,
  parseLifecyclePayload,
  parseListQuery,
  parseUpdatePayload
};

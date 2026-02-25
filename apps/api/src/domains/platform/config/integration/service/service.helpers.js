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

module.exports = {
  CONTROL_CHAR_PATTERN,
  CREATE_ALLOWED_FIELDS,
  DEFAULT_PAGE,
  DEFAULT_PAGE_SIZE,
  DEFAULT_TIMEOUT_MS,
  LIFECYCLE_ALLOWED_FIELDS,
  LIST_ALLOWED_QUERY_FIELDS,
  MAX_AUDIT_TRAIL_ENTRIES,
  MAX_AUTH_MODE_LENGTH,
  MAX_BASE_URL_LENGTH,
  MAX_CODE_LENGTH,
  MAX_ENDPOINT_LENGTH,
  MAX_FREEZE_ID_LENGTH,
  MAX_FREEZE_REASON_LENGTH,
  MAX_INTEGRATION_ID_LENGTH,
  MAX_LIFECYCLE_REASON_LENGTH,
  MAX_LIST_KEYWORD_LENGTH,
  MAX_NAME_LENGTH,
  MAX_OPERATOR_USER_ID_LENGTH,
  MAX_PAGE_SIZE,
  MAX_PROTOCOL_LENGTH,
  MAX_RUNBOOK_URL_LENGTH,
  MAX_TIMEOUT_MS,
  MAX_VERSION_STRATEGY_LENGTH,
  UPDATE_ALLOWED_FIELDS,
  VALID_DIRECTIONS,
  VALID_LIFECYCLE_STATUSES,
  isPlainObject,
  mapActiveFreezeRecordForWriteGate,
  mapIntegrationRecord,
  normalizeDirection,
  normalizeIntegrationId,
  normalizeLifecycleStatus,
  normalizePolicyPayload,
  normalizeStoreIsoTimestamp,
  normalizeStoreOptionalString,
  normalizeStrictOptionalString,
  normalizeStrictRequiredString,
  resolveStoreFieldValue
};

'use strict';

const { normalizeTraceparent } = require('../../../../common/trace-context');
const { isRetryableDeliveryFailure } = require('../../../../modules/integration');
const {
  AUDIT_EVENT_ALLOWED_DOMAINS,
  AUDIT_EVENT_ALLOWED_RESULTS,
  AUDIT_EVENT_REDACTION_COUNT_KEY_PATTERN,
  AUDIT_EVENT_REDACTION_KEY_PATTERN,
  MYSQL_AUDIT_DATETIME_PATTERN
} = require('./shared-mysql-auth-store-runtime-domain-constraint-constants');
const {
  normalizePlatformIntegrationOptionalText
} = require('./shared-mysql-auth-store-runtime-domain-normalization-guard-capability');

const toBoolean = (value) =>
  value === true || value === 1 || value === '1' || String(value || '').toLowerCase() === 'true';

const normalizeAuditDomain = (domain) => {
  const normalized = String(domain || '').trim().toLowerCase();
  return AUDIT_EVENT_ALLOWED_DOMAINS.has(normalized) ? normalized : '';
};

const normalizeAuditResult = (result) => {
  const normalized = String(result || '').trim().toLowerCase();
  return AUDIT_EVENT_ALLOWED_RESULTS.has(normalized) ? normalized : '';
};

const normalizeAuditStringOrNull = (value, maxLength = 256) => {
  if (value === null || value === undefined) {
    return null;
  }
  const normalized = String(value).trim();
  if (!normalized || normalized.length > maxLength) {
    return null;
  }
  return normalized;
};

const normalizeAuditTraceparentOrNull = (value) => {
  const normalized = normalizeAuditStringOrNull(value, 128);
  if (!normalized) {
    return null;
  }
  return normalizeTraceparent(normalized);
};

const parseMySqlAuditDateTimeAsUtc = (value) => {
  const normalizedValue = String(value || '').trim();
  const match = MYSQL_AUDIT_DATETIME_PATTERN.exec(normalizedValue);
  if (!match) {
    return null;
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const fraction = String(match[7] || '');
  const milliseconds = Number((fraction + '000').slice(0, 3));
  const epochMs = Date.UTC(year, month - 1, day, hour, minute, second, milliseconds);
  if (Number.isNaN(epochMs)) {
    return null;
  }
  return new Date(epochMs);
};

const resolveAuditOccurredAtDate = (value) => {
  if (value === null || value === undefined) {
    return new Date();
  }
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      return new Date();
    }
    return value;
  }
  if (typeof value === 'string') {
    const parsedMySqlDateTime = parseMySqlAuditDateTimeAsUtc(value);
    if (parsedMySqlDateTime) {
      return parsedMySqlDateTime;
    }
  }
  const dateValue = new Date(value);
  if (Number.isNaN(dateValue.getTime())) {
    return new Date();
  }
  return dateValue;
};

const normalizeAuditOccurredAt = (value) =>
  resolveAuditOccurredAtDate(value).toISOString();

const formatAuditDateTimeForMySql = (dateValue) => {
  const resolvedDateValue = resolveAuditOccurredAtDate(dateValue);
  const iso = resolvedDateValue.toISOString();
  return `${iso.slice(0, 19).replace('T', ' ')}.${iso.slice(20, 23)}`;
};

const safeParseJsonValue = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value === 'object') {
    return value;
  }
  if (typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  try {
    return JSON.parse(trimmed);
  } catch (_error) {
    return null;
  }
};

const resolvePlatformIntegrationNetworkErrorCodeFromSnapshot = (snapshot = null) => {
  const parsedSnapshot = safeParseJsonValue(snapshot);
  if (!parsedSnapshot || typeof parsedSnapshot !== 'object' || Array.isArray(parsedSnapshot)) {
    return null;
  }
  return normalizePlatformIntegrationOptionalText(
    parsedSnapshot.network_error_code
    ?? parsedSnapshot.networkErrorCode
    ?? parsedSnapshot.error_code
    ?? parsedSnapshot.errorCode
  );
};

const isPlatformIntegrationRecoveryFailureRetryable = ({
  retryable = true,
  lastHttpStatus = null,
  failureCode = null,
  responseSnapshot = null
} = {}) => {
  if (!Boolean(retryable)) {
    return false;
  }
  return isRetryableDeliveryFailure({
    httpStatus: lastHttpStatus,
    errorCode: failureCode,
    networkErrorCode: resolvePlatformIntegrationNetworkErrorCodeFromSnapshot(
      responseSnapshot
    )
  });
};

const sanitizeAuditState = (value, depth = 0) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (depth > 8) {
    return null;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeAuditState(item, depth + 1));
  }
  if (typeof value === 'object') {
    const sanitized = {};
    for (const [key, itemValue] of Object.entries(value)) {
      const keyString = String(key);
      if (
        AUDIT_EVENT_REDACTION_KEY_PATTERN.test(keyString)
        && !AUDIT_EVENT_REDACTION_COUNT_KEY_PATTERN.test(keyString)
      ) {
        sanitized[key] = '[REDACTED]';
        continue;
      }
      sanitized[key] = sanitizeAuditState(itemValue, depth + 1);
    }
    return sanitized;
  }
  return value;
};

const toAuditEventRecord = (row) => ({
  event_id: normalizeAuditStringOrNull(row?.event_id, 64) || '',
  domain: normalizeAuditDomain(row?.domain),
  tenant_id: normalizeAuditStringOrNull(row?.tenant_id, 64),
  request_id: normalizeAuditStringOrNull(row?.request_id, 128) || 'request_id_unset',
  traceparent: normalizeAuditTraceparentOrNull(row?.traceparent),
  event_type: normalizeAuditStringOrNull(row?.event_type, 128) || '',
  actor_user_id: normalizeAuditStringOrNull(row?.actor_user_id, 64),
  actor_session_id: normalizeAuditStringOrNull(row?.actor_session_id, 128),
  target_type: normalizeAuditStringOrNull(row?.target_type, 64) || '',
  target_id: normalizeAuditStringOrNull(row?.target_id, 128),
  result: normalizeAuditResult(row?.result) || 'failed',
  before_state: safeParseJsonValue(row?.before_state),
  after_state: safeParseJsonValue(row?.after_state),
  metadata: safeParseJsonValue(row?.metadata),
  occurred_at: row?.occurred_at instanceof Date
    ? row.occurred_at.toISOString()
    : normalizeAuditOccurredAt(row?.occurred_at)
});

module.exports = {
  toBoolean,
  normalizeAuditDomain,
  normalizeAuditResult,
  normalizeAuditStringOrNull,
  normalizeAuditTraceparentOrNull,
  parseMySqlAuditDateTimeAsUtc,
  resolveAuditOccurredAtDate,
  normalizeAuditOccurredAt,
  formatAuditDateTimeForMySql,
  safeParseJsonValue,
  resolvePlatformIntegrationNetworkErrorCodeFromSnapshot,
  isPlatformIntegrationRecoveryFailureRetryable,
  sanitizeAuditState,
  toAuditEventRecord
};

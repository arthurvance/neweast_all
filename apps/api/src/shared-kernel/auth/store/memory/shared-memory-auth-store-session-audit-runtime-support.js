'use strict';

const createSharedMemoryAuthStoreSessionAuditRuntimeSupport = ({
  AUDIT_EVENT_ALLOWED_DOMAINS,
  AUDIT_EVENT_ALLOWED_RESULTS,
  AUDIT_EVENT_REDACTION_COUNT_KEY_PATTERN,
  AUDIT_EVENT_REDACTION_KEY_PATTERN,
  auditEvents,
  isRetryableDeliveryFailure,
  normalizePlatformIntegrationOptionalText,
  normalizeTraceparent,
  randomUUID
} = {}) => {
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

  const normalizeAuditOccurredAt = (value) => {
    if (value === null || value === undefined) {
      return new Date().toISOString();
    }
    const dateValue = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(dateValue.getTime())) {
      return new Date().toISOString();
    }
    return dateValue.toISOString();
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

  const cloneJsonValue = (value) => {
    if (value === null || value === undefined) {
      return null;
    }
    try {
      return JSON.parse(JSON.stringify(value));
    } catch (_error) {
      return null;
    }
  };

  const toAuditEventRecord = (event = {}) => ({
    event_id: normalizeAuditStringOrNull(event.event_id, 64) || '',
    domain: normalizeAuditDomain(event.domain),
    tenant_id: normalizeAuditStringOrNull(event.tenant_id, 64),
    request_id: normalizeAuditStringOrNull(event.request_id, 128) || 'request_id_unset',
    traceparent: normalizeAuditTraceparentOrNull(event.traceparent),
    event_type: normalizeAuditStringOrNull(event.event_type, 128) || '',
    actor_user_id: normalizeAuditStringOrNull(event.actor_user_id, 64),
    actor_session_id: normalizeAuditStringOrNull(event.actor_session_id, 128),
    target_type: normalizeAuditStringOrNull(event.target_type, 64) || '',
    target_id: normalizeAuditStringOrNull(event.target_id, 128),
    result: normalizeAuditResult(event.result) || 'failed',
    before_state: safeParseJsonValue(cloneJsonValue(event.before_state)),
    after_state: safeParseJsonValue(cloneJsonValue(event.after_state)),
    metadata: safeParseJsonValue(cloneJsonValue(event.metadata)),
    occurred_at: normalizeAuditOccurredAt(event.occurred_at)
  });

  const restoreMapFromSnapshot = (targetMap, snapshotMap) => {
    targetMap.clear();
    for (const [key, value] of snapshotMap.entries()) {
      targetMap.set(key, value);
    }
  };

  const restoreSetFromSnapshot = (targetSet, snapshotSet) => {
    targetSet.clear();
    for (const value of snapshotSet.values()) {
      targetSet.add(value);
    }
  };

  const restoreAuditEventsFromSnapshot = (snapshotEvents = []) => {
    auditEvents.length = 0;
    for (const event of snapshotEvents) {
      auditEvents.push(event);
    }
  };

  const persistAuditEvent = ({
    eventId = null,
    domain,
    tenantId = null,
    requestId = 'request_id_unset',
    traceparent = null,
    eventType,
    actorUserId = null,
    actorSessionId = null,
    targetType,
    targetId = null,
    result = 'success',
    beforeState = null,
    afterState = null,
    metadata = null,
    occurredAt = null
  } = {}) => {
    const normalizedDomain = normalizeAuditDomain(domain);
    const normalizedResult = normalizeAuditResult(result);
    const normalizedEventType = normalizeAuditStringOrNull(eventType, 128);
    const normalizedTargetType = normalizeAuditStringOrNull(targetType, 64);
    if (
      !normalizedDomain
      || !normalizedResult
      || !normalizedEventType
      || !normalizedTargetType
    ) {
      throw new Error('recordAuditEvent requires valid domain, result, eventType and targetType');
    }
    const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
    if (normalizedDomain === 'tenant' && !normalizedTenantId) {
      throw new Error('recordAuditEvent tenant domain requires tenantId');
    }
    const eventRecord = toAuditEventRecord({
      event_id: normalizeAuditStringOrNull(eventId, 64) || randomUUID(),
      domain: normalizedDomain,
      tenant_id: normalizedTenantId,
      request_id: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
      traceparent: normalizeAuditTraceparentOrNull(traceparent),
      event_type: normalizedEventType,
      actor_user_id: normalizeAuditStringOrNull(actorUserId, 64),
      actor_session_id: normalizeAuditStringOrNull(actorSessionId, 128),
      target_type: normalizedTargetType,
      target_id: normalizeAuditStringOrNull(targetId, 128),
      result: normalizedResult,
      before_state: sanitizeAuditState(beforeState),
      after_state: sanitizeAuditState(afterState),
      metadata: sanitizeAuditState(metadata),
      occurred_at: normalizeAuditOccurredAt(occurredAt)
    });
    auditEvents.push(eventRecord);
    if (auditEvents.length > 5000) {
      auditEvents.splice(0, auditEvents.length - 5000);
    }
    return toAuditEventRecord(eventRecord);
  };

  return {
    cloneJsonValue,
    isPlatformIntegrationRecoveryFailureRetryable,
    normalizeAuditDomain,
    normalizeAuditOccurredAt,
    normalizeAuditResult,
    normalizeAuditStringOrNull,
    normalizeAuditTraceparentOrNull,
    persistAuditEvent,
    resolvePlatformIntegrationNetworkErrorCodeFromSnapshot,
    restoreAuditEventsFromSnapshot,
    restoreMapFromSnapshot,
    restoreSetFromSnapshot,
    safeParseJsonValue,
    sanitizeAuditState,
    toAuditEventRecord
  };
};

module.exports = {
  createSharedMemoryAuthStoreSessionAuditRuntimeSupport
};

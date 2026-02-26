'use strict';

const { AsyncLocalStorage } = require('node:async_hooks');
const { createHash } = require('node:crypto');

const createSharedAuthAuditObservabilityCapabilities = ({
  now,
  authStore,
  errors,
  log,
  normalizeAuditStringOrNull,
  normalizeAuditTraceparentOrNull,
  normalizeAuditDomain,
  normalizeAuditResult,
  sanitizeAuditState,
  parseAuditQueryTimestamp,
  MAX_AUTH_AUDIT_TRAIL_ENTRIES,
  MAX_AUDIT_QUERY_PAGE_SIZE
} = {}) => {
  const auditTrail = [];
  const requestTraceContextStorage = new AsyncLocalStorage();

  const normalizeAuditRequestIdOrNull = (value) =>
    normalizeAuditStringOrNull(value, 128);

  const bindRequestTraceparent = ({ requestId, traceparent } = {}) => {
    const normalizedRequestId = normalizeAuditRequestIdOrNull(requestId);
    const normalizedTraceparent = normalizeAuditTraceparentOrNull(traceparent);
    requestTraceContextStorage.enterWith({
      requestId: normalizedRequestId || 'request_id_unset',
      traceparent: normalizedTraceparent
    });
    return normalizedTraceparent;
  };

  const addAuditEvent = ({
    type,
    requestId,
    traceparent = undefined,
    userId = 'unknown',
    sessionId = 'unknown',
    detail = '',
    metadata = {}
  }) => {
    const normalizedRequestId =
      normalizeAuditRequestIdOrNull(requestId) || 'request_id_unset';
    const traceContext = requestTraceContextStorage.getStore();
    const inheritedTraceparent =
      traceContext && traceContext.requestId === normalizedRequestId
        ? traceContext.traceparent
        : null;
    const resolvedTraceparent =
      traceparent === undefined
        ? inheritedTraceparent
        : normalizeAuditTraceparentOrNull(traceparent);
    const event = {
      type,
      at: new Date(now()).toISOString(),
      request_id: normalizedRequestId,
      traceparent: resolvedTraceparent,
      user_id: userId,
      session_id: sessionId,
      detail,
      ...metadata
    };

    auditTrail.push(event);
    if (auditTrail.length > MAX_AUTH_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUTH_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Auth audit event', event);
  };

  const recordPersistentAuditEvent = async ({
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
      throw errors.auditDependencyUnavailable({
        reason: 'audit-payload-invalid'
      });
    }
    const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
    if (normalizedDomain === 'tenant' && !normalizedTenantId) {
      throw errors.auditDependencyUnavailable({
        reason: 'audit-tenant-id-missing'
      });
    }
    if (!authStore || typeof authStore.recordAuditEvent !== 'function') {
      throw errors.auditDependencyUnavailable({
        reason: 'audit-store-unsupported'
      });
    }
    try {
      const normalizedTraceparent = normalizeAuditTraceparentOrNull(traceparent);
      return await authStore.recordAuditEvent({
        domain: normalizedDomain,
        tenantId: normalizedTenantId,
        requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
        traceparent: normalizedTraceparent,
        eventType: normalizedEventType,
        actorUserId: normalizeAuditStringOrNull(actorUserId, 64),
        actorSessionId: normalizeAuditStringOrNull(actorSessionId, 128),
        targetType: normalizedTargetType,
        targetId: normalizeAuditStringOrNull(targetId, 128),
        result: normalizedResult,
        beforeState: sanitizeAuditState(beforeState),
        afterState: sanitizeAuditState(afterState),
        metadata: sanitizeAuditState(metadata),
        occurredAt: normalizeAuditOccurredAt(occurredAt)
      });
    } catch (error) {
      throw errors.auditDependencyUnavailable({
        reason: String(error?.code || error?.message || 'audit-write-failed').trim().toLowerCase()
      });
    }
  };

  const listAuditEvents = async ({
    domain,
    tenantId = null,
    page = 1,
    pageSize = 50,
    from = null,
    to = null,
    eventType = null,
    result = null,
    requestId = null,
    traceparent = null,
    actorUserId = null,
    targetType = null,
    targetId = null
  } = {}) => {
    const normalizedDomain = normalizeAuditDomain(domain);
    if (!normalizedDomain) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
    if (normalizedDomain === 'tenant' && !normalizedTenantId) {
      throw errors.invalidPayload();
    }
    const resolvedPage = Math.max(1, Math.floor(Number(page || 1)));
    const resolvedPageSize = Math.min(
      MAX_AUDIT_QUERY_PAGE_SIZE,
      Math.max(1, Math.floor(Number(pageSize || 50)))
    );
    const parsedFrom = parseAuditQueryTimestamp(from);
    const parsedTo = parseAuditQueryTimestamp(to);
    if (!parsedFrom.valid || !parsedTo.valid) {
      throw errors.invalidPayload();
    }
    if (
      parsedFrom.value
      && parsedTo.value
      && new Date(parsedFrom.value).getTime() > new Date(parsedTo.value).getTime()
    ) {
      throw errors.invalidPayload();
    }
    if (!authStore || typeof authStore.listAuditEvents !== 'function') {
      throw errors.auditDependencyUnavailable({
        reason: 'audit-store-query-unsupported'
      });
    }
    let normalizedTraceparentFilter = null;
    if (traceparent !== null && traceparent !== undefined) {
      normalizedTraceparentFilter = normalizeAuditTraceparentOrNull(traceparent);
      if (!normalizedTraceparentFilter) {
        throw errors.invalidPayload();
      }
    }
    try {
      return await authStore.listAuditEvents({
        domain: normalizedDomain,
        tenantId: normalizedTenantId,
        page: resolvedPage,
        pageSize: resolvedPageSize,
        from: parsedFrom.value,
        to: parsedTo.value,
        eventType: normalizeAuditStringOrNull(eventType, 128),
        result: normalizeAuditResult(result) || null,
        requestId: normalizeAuditStringOrNull(requestId, 128),
        traceparent: normalizedTraceparentFilter,
        actorUserId: normalizeAuditStringOrNull(actorUserId, 64),
        targetType: normalizeAuditStringOrNull(targetType, 64),
        targetId: normalizeAuditStringOrNull(targetId, 128)
      });
    } catch (error) {
      throw errors.auditDependencyUnavailable({
        reason: String(error?.code || error?.message || 'audit-query-failed').trim().toLowerCase()
      });
    }
  };

  const recordIdempotencyEvent = async ({
    requestId,
    traceparent = null,
    outcome = 'hit',
    routeKey = '',
    idempotencyKey = '',
    authorizationContext = null,
    metadata = {}
  } = {}) => {
    const requestedOutcome = String(outcome || 'hit').trim().toLowerCase();
    const outcomeDescriptorByCode = {
      hit: {
        eventType: 'auth.idempotency.hit',
        detail: 'idempotency replay served from prior result'
      },
      conflict: {
        eventType: 'auth.idempotency.conflict',
        detail: 'idempotency key reused with different request payload'
      },
      store_unavailable: {
        eventType: 'auth.idempotency.degraded',
        detail: 'idempotency store unavailable for this request'
      },
      pending_timeout: {
        eventType: 'auth.idempotency.degraded',
        detail: 'idempotency pending wait timeout'
      },
      unknown: {
        eventType: 'auth.idempotency.unknown',
        detail: 'idempotency outcome is unrecognized'
      }
    };
    const normalizedOutcome = Object.prototype.hasOwnProperty.call(
      outcomeDescriptorByCode,
      requestedOutcome
    )
      ? requestedOutcome
      : 'unknown';
    const selectedOutcomeDescriptor = outcomeDescriptorByCode[normalizedOutcome];
    const resolvedUserId = String(
      authorizationContext?.user_id
      || authorizationContext?.user?.id
      || 'unknown'
    ).trim() || 'unknown';
    const resolvedSessionId = String(
      authorizationContext?.session_id
      || authorizationContext?.session?.sessionId
      || authorizationContext?.session?.session_id
      || 'unknown'
    ).trim() || 'unknown';
    const idempotencyKeyFingerprint = createHash('sha256')
      .update(String(idempotencyKey || '').trim())
      .digest('hex');

    addAuditEvent({
      type: selectedOutcomeDescriptor.eventType,
      requestId,
      traceparent,
      userId: resolvedUserId,
      sessionId: resolvedSessionId,
      detail: selectedOutcomeDescriptor.detail,
      metadata: {
        route_key: String(routeKey || ''),
        idempotency_key_fingerprint: idempotencyKeyFingerprint,
        idempotency_outcome: normalizedOutcome,
        ...metadata
      }
    });
  };

  const addAccessInvalidAuditEvent = ({
    requestId,
    payload = null,
    userId = 'unknown',
    sessionId = 'unknown',
    dispositionReason = 'access-token-invalid'
  }) =>
    addAuditEvent({
      type: 'auth.access.invalid',
      requestId,
      userId,
      sessionId,
      detail: 'access token rejected',
      metadata: {
        session_id_hint: String(payload?.sid || sessionId || 'unknown'),
        disposition_reason: dispositionReason,
        disposition_action: 'reject-only'
      }
    });

  return {
    auditTrail,
    normalizeAuditRequestIdOrNull,
    bindRequestTraceparent,
    addAuditEvent,
    recordPersistentAuditEvent,
    listAuditEvents,
    recordIdempotencyEvent,
    addAccessInvalidAuditEvent
  };
};

const normalizeAuditOccurredAt = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed.toISOString();
};

module.exports = {
  createSharedAuthAuditObservabilityCapabilities
};

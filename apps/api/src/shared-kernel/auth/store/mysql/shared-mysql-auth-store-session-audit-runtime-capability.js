'use strict';

const createSharedMysqlAuthStoreSessionAuditRuntimeCapability = ({
  MAX_AUDIT_QUERY_PAGE_SIZE,
  dbClient,
  formatAuditDateTimeForMySql,
  normalizeAuditDomain,
  normalizeAuditOccurredAt,
  normalizeAuditResult,
  normalizeAuditStringOrNull,
  normalizeAuditTraceparentOrNull,
  randomUUID,
  sanitizeAuditState,
  toAuditEventRecord
} = {}) => {
  const recordAuditEventWithQueryClient = async ({
    queryClient,
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
    if (!queryClient || typeof queryClient.query !== 'function') {
      throw new Error('recordAuditEventWithQueryClient requires a query-capable client');
    }
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
      throw new Error('recordAuditEvent requires valid domain, result, eventType, and targetType');
    }
    const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
    if (normalizedDomain === 'tenant' && !normalizedTenantId) {
      throw new Error('recordAuditEvent tenant domain requires tenantId');
    }
    const normalizedEventId = normalizeAuditStringOrNull(eventId, 64) || randomUUID();
    const normalizedRequestId =
      normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset';
    const normalizedTraceparent = normalizeAuditTraceparentOrNull(traceparent);
    const normalizedActorUserId = normalizeAuditStringOrNull(actorUserId, 64);
    const normalizedActorSessionId = normalizeAuditStringOrNull(actorSessionId, 128);
    const normalizedTargetId = normalizeAuditStringOrNull(targetId, 128);
    const normalizedOccurredAt = normalizeAuditOccurredAt(occurredAt);
    const persistedOccurredAt = formatAuditDateTimeForMySql(normalizedOccurredAt);
    const sanitizedBeforeState = sanitizeAuditState(beforeState);
    const sanitizedAfterState = sanitizeAuditState(afterState);
    const sanitizedMetadata = sanitizeAuditState(metadata);

    await queryClient.query(
      `
        INSERT INTO audit_events (
          event_id,
          domain,
          tenant_id,
          request_id,
          traceparent,
          event_type,
          actor_user_id,
          actor_session_id,
          target_type,
          target_id,
          result,
          before_state,
          after_state,
          metadata,
          occurred_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        normalizedEventId,
        normalizedDomain,
        normalizedTenantId,
        normalizedRequestId,
        normalizedTraceparent,
        normalizedEventType,
        normalizedActorUserId,
        normalizedActorSessionId,
        normalizedTargetType,
        normalizedTargetId,
        normalizedResult,
        sanitizedBeforeState === null ? null : JSON.stringify(sanitizedBeforeState),
        sanitizedAfterState === null ? null : JSON.stringify(sanitizedAfterState),
        sanitizedMetadata === null ? null : JSON.stringify(sanitizedMetadata),
        persistedOccurredAt
      ]
    );
    return {
      event_id: normalizedEventId,
      domain: normalizedDomain,
      tenant_id: normalizedTenantId,
      request_id: normalizedRequestId,
      traceparent: normalizedTraceparent,
      event_type: normalizedEventType,
      actor_user_id: normalizedActorUserId,
      actor_session_id: normalizedActorSessionId,
      target_type: normalizedTargetType,
      target_id: normalizedTargetId,
      result: normalizedResult,
      before_state: sanitizedBeforeState,
      after_state: sanitizedAfterState,
      metadata: sanitizedMetadata,
      occurred_at: normalizedOccurredAt
    };
  };

  const recordAuditEvent = async (payload = {}) =>
    recordAuditEventWithQueryClient({
      queryClient: dbClient,
      ...payload
    });

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
      throw new Error('listAuditEvents requires a valid domain');
    }
    const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
    if (normalizedDomain === 'tenant' && !normalizedTenantId) {
      throw new Error('listAuditEvents tenant domain requires tenantId');
    }
    const resolvedPage = Math.max(1, Math.floor(Number(page || 1)));
    const resolvedPageSize = Math.min(
      MAX_AUDIT_QUERY_PAGE_SIZE,
      Math.max(1, Math.floor(Number(pageSize || 50)))
    );
    const offset = (resolvedPage - 1) * resolvedPageSize;

    const whereClauses = ['domain = ?'];
    const whereArgs = [normalizedDomain];
    if (normalizedTenantId) {
      whereClauses.push('tenant_id = ?');
      whereArgs.push(normalizedTenantId);
    }

    const normalizedEventType = normalizeAuditStringOrNull(eventType, 128);
    if (normalizedEventType) {
      whereClauses.push('event_type = ?');
      whereArgs.push(normalizedEventType);
    }
    const normalizedResult = normalizeAuditResult(result);
    if (normalizedResult) {
      whereClauses.push('result = ?');
      whereArgs.push(normalizedResult);
    }
    const normalizedRequestId = normalizeAuditStringOrNull(requestId, 128);
    if (normalizedRequestId) {
      whereClauses.push('request_id = ?');
      whereArgs.push(normalizedRequestId);
    }
    let normalizedTraceparent = null;
    if (traceparent !== null && traceparent !== undefined) {
      normalizedTraceparent = normalizeAuditTraceparentOrNull(traceparent);
      if (!normalizedTraceparent) {
        throw new Error('listAuditEvents requires valid traceparent');
      }
    }
    if (normalizedTraceparent) {
      whereClauses.push('traceparent = ?');
      whereArgs.push(normalizedTraceparent);
    }
    const normalizedActorUserId = normalizeAuditStringOrNull(actorUserId, 64);
    if (normalizedActorUserId) {
      whereClauses.push('actor_user_id = ?');
      whereArgs.push(normalizedActorUserId);
    }
    const normalizedTargetType = normalizeAuditStringOrNull(targetType, 64);
    if (normalizedTargetType) {
      whereClauses.push('target_type = ?');
      whereArgs.push(normalizedTargetType);
    }
    const normalizedTargetId = normalizeAuditStringOrNull(targetId, 128);
    if (normalizedTargetId) {
      whereClauses.push('target_id = ?');
      whereArgs.push(normalizedTargetId);
    }

    const fromDate = from ? new Date(from) : null;
    if (fromDate && !Number.isNaN(fromDate.getTime())) {
      whereClauses.push('occurred_at >= ?');
      whereArgs.push(formatAuditDateTimeForMySql(fromDate));
    }
    const toDate = to ? new Date(to) : null;
    if (toDate && !Number.isNaN(toDate.getTime())) {
      whereClauses.push('occurred_at <= ?');
      whereArgs.push(formatAuditDateTimeForMySql(toDate));
    }
    if (
      fromDate && toDate
      && !Number.isNaN(fromDate.getTime())
      && !Number.isNaN(toDate.getTime())
      && fromDate.getTime() > toDate.getTime()
    ) {
      throw new Error('listAuditEvents requires from <= to');
    }

    const whereSql = `WHERE ${whereClauses.join(' AND ')}`;
    const countRows = await dbClient.query(
      `
        SELECT COUNT(*) AS total
        FROM audit_events
        ${whereSql}
      `,
      whereArgs
    );
    const total = Number(countRows?.[0]?.total || 0);
    const rows = await dbClient.query(
      `
        SELECT event_id,
               domain,
               tenant_id,
               request_id,
               traceparent,
               event_type,
               actor_user_id,
               actor_session_id,
               target_type,
               target_id,
               result,
               before_state,
               after_state,
               metadata,
               occurred_at
        FROM audit_events
        ${whereSql}
        ORDER BY occurred_at DESC, event_id DESC
        LIMIT ? OFFSET ?
      `,
      [...whereArgs, resolvedPageSize, offset]
    );
    return {
      total,
      events: (Array.isArray(rows) ? rows : []).map((row) => toAuditEventRecord(row))
    };
  };

  return {
    listAuditEvents,
    recordAuditEvent,
    recordAuditEventWithQueryClient
  };
};

module.exports = {
  createSharedMysqlAuthStoreSessionAuditRuntimeCapability
};

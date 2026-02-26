'use strict';

const createSharedMemoryAuthStoreSessionAuditMethodComposition = ({
  MAX_AUDIT_QUERY_PAGE_SIZE,
  auditEvents,
  normalizeAuditDomain,
  normalizeAuditResult,
  normalizeAuditStringOrNull,
  normalizeAuditTraceparentOrNull,
  persistAuditEvent,
  repositoryMethods,
  toAuditEventRecord
} = {}) => ({
  findUserByPhone: repositoryMethods.findUserByPhone,
  findUserById: repositoryMethods.findUserById,
  updateUserPhone: repositoryMethods.updateUserPhone,

  recordAuditEvent: async (payload = {}) => persistAuditEvent(payload),

  listAuditEvents: async ({
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
      throw new Error('listAuditEvents requires valid domain');
    }
    const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
    if (normalizedDomain === 'tenant' && !normalizedTenantId) {
      throw new Error('listAuditEvents tenant domain requires tenantId');
    }
    const normalizedEventType = normalizeAuditStringOrNull(eventType, 128);
    const normalizedResult = normalizeAuditResult(result);
    const normalizedRequestId = normalizeAuditStringOrNull(requestId, 128);
    let normalizedTraceparent = null;
    if (traceparent !== null && traceparent !== undefined) {
      normalizedTraceparent = normalizeAuditTraceparentOrNull(traceparent);
      if (!normalizedTraceparent) {
        throw new Error('listAuditEvents requires valid traceparent');
      }
    }
    const normalizedActorUserId = normalizeAuditStringOrNull(actorUserId, 64);
    const normalizedTargetType = normalizeAuditStringOrNull(targetType, 64);
    const normalizedTargetId = normalizeAuditStringOrNull(targetId, 128);
    const fromDate = from ? new Date(from) : null;
    const toDate = to ? new Date(to) : null;
    if (
      fromDate && toDate
      && !Number.isNaN(fromDate.getTime())
      && !Number.isNaN(toDate.getTime())
      && fromDate.getTime() > toDate.getTime()
    ) {
      throw new Error('listAuditEvents requires from <= to');
    }

    const filtered = auditEvents.filter((event) => {
      if (normalizeAuditDomain(event.domain) !== normalizedDomain) {
        return false;
      }
      if (normalizedTenantId && normalizeAuditStringOrNull(event.tenant_id, 64) !== normalizedTenantId) {
        return false;
      }
      if (normalizedEventType && normalizeAuditStringOrNull(event.event_type, 128) !== normalizedEventType) {
        return false;
      }
      if (normalizedResult && normalizeAuditResult(event.result) !== normalizedResult) {
        return false;
      }
      if (normalizedRequestId && normalizeAuditStringOrNull(event.request_id, 128) !== normalizedRequestId) {
        return false;
      }
      if (
        normalizedTraceparent
        && normalizeAuditTraceparentOrNull(event.traceparent) !== normalizedTraceparent
      ) {
        return false;
      }
      if (normalizedActorUserId && normalizeAuditStringOrNull(event.actor_user_id, 64) !== normalizedActorUserId) {
        return false;
      }
      if (normalizedTargetType && normalizeAuditStringOrNull(event.target_type, 64) !== normalizedTargetType) {
        return false;
      }
      if (normalizedTargetId && normalizeAuditStringOrNull(event.target_id, 128) !== normalizedTargetId) {
        return false;
      }
      const occurredAt = new Date(event.occurred_at);
      if (fromDate && !Number.isNaN(fromDate.getTime()) && occurredAt < fromDate) {
        return false;
      }
      if (toDate && !Number.isNaN(toDate.getTime()) && occurredAt > toDate) {
        return false;
      }
      return true;
    });

    filtered.sort((left, right) => {
      const leftTime = new Date(left.occurred_at).getTime();
      const rightTime = new Date(right.occurred_at).getTime();
      if (rightTime !== leftTime) {
        return rightTime - leftTime;
      }
      return String(right.event_id || '').localeCompare(String(left.event_id || ''));
    });

    const total = filtered.length;
    const resolvedPage = Math.max(1, Math.floor(Number(page || 1)));
    const resolvedPageSize = Math.min(
      MAX_AUDIT_QUERY_PAGE_SIZE,
      Math.max(1, Math.floor(Number(pageSize || 50)))
    );
    const offset = (resolvedPage - 1) * resolvedPageSize;

    return {
      total,
      events: filtered
        .slice(offset, offset + resolvedPageSize)
        .map((event) => toAuditEventRecord(event))
    };
  },

  createSession: repositoryMethods.createSession,
  findSessionById: repositoryMethods.findSessionById,
  updateSessionContext: repositoryMethods.updateSessionContext,
  findDomainAccessByUserId: repositoryMethods.findDomainAccessByUserId,
  ensureDefaultDomainAccessForUser: repositoryMethods.ensureDefaultDomainAccessForUser,
  revokeSession: repositoryMethods.revokeSession,
  revokeAllUserSessions: repositoryMethods.revokeAllUserSessions,
  createRefreshToken: repositoryMethods.createRefreshToken,
  findRefreshTokenByHash: repositoryMethods.findRefreshTokenByHash,
  markRefreshTokenStatus: repositoryMethods.markRefreshTokenStatus,
  linkRefreshRotation: repositoryMethods.linkRefreshRotation,
  rotateRefreshToken: repositoryMethods.rotateRefreshToken,
  updateUserPasswordAndBumpSessionVersion:
    repositoryMethods.updateUserPasswordAndBumpSessionVersion,
  updateUserPasswordAndRevokeSessions:
    repositoryMethods.updateUserPasswordAndRevokeSessions
});

module.exports = {
  createSharedMemoryAuthStoreSessionAuditMethodComposition
};

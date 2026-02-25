const { log } = require('../../common/logger');
const { normalizeTraceparent } = require('../../common/trace-context');
const { AuthProblemError } = require('../../shared-kernel/auth/auth-problem-error');
const {
  resolveRoutePreauthorizedContext
} = require('../../shared-kernel/auth/route-authz');
const {
  PLATFORM_AUDIT_VIEW_PERMISSION_CODE,
  TENANT_AUDIT_VIEW_PERMISSION_CODE,
  PLATFORM_AUDIT_SCOPE,
  TENANT_AUDIT_SCOPE
} = require('./audit.constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const VALID_AUDIT_RESULT = new Set(['success', 'rejected', 'failed']);
const DEFAULT_AUDIT_PAGE = 1;
const DEFAULT_AUDIT_PAGE_SIZE = 50;
const MAX_AUDIT_PAGE_SIZE = 200;
const MAX_AUDIT_PAGE = 100000;

const PLATFORM_AUDIT_ALLOWED_QUERY_KEYS = new Set([
  'page',
  'page_size',
  'from',
  'to',
  'event_type',
  'result',
  'request_id',
  'traceparent',
  'actor_user_id',
  'target_type',
  'target_id',
  'tenant_id'
]);

const TENANT_AUDIT_ALLOWED_QUERY_KEYS = new Set([
  'page',
  'page_size',
  'from',
  'to',
  'event_type',
  'result',
  'request_id',
  'traceparent',
  'actor_user_id',
  'target_type',
  'target_id'
]);

const auditError = ({ status, title, detail, errorCode, extensions = {} }) =>
  new AuthProblemError({
    status,
    title,
    detail,
    errorCode,
    extensions
  });

const auditErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    auditError({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'AUTH-400-INVALID-PAYLOAD'
    }),

  noDomainAccess: () =>
    auditError({
      status: 403,
      title: 'Forbidden',
      detail: '当前入口无可用访问域权限',
      errorCode: 'AUTH-403-NO-DOMAIN'
    }),

  auditDependencyUnavailable: ({ reason = 'audit-dependency-unavailable' } = {}) =>
    auditError({
      status: 503,
      title: 'Service Unavailable',
      detail: '审计依赖暂不可用，请稍后重试',
      errorCode: 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: String(reason || 'audit-dependency-unavailable').trim()
      }
    })
};

const isPlainObject = (candidate) =>
  candidate !== null
  && typeof candidate === 'object'
  && !Array.isArray(candidate);

const normalizeRequiredString = (value) => {
  if (typeof value !== 'string') {
    return '';
  }
  return value.trim();
};

const normalizeOptionalStrictQueryString = ({
  query,
  key,
  maxLength = 128
} = {}) => {
  if (!Object.prototype.hasOwnProperty.call(query, key)) {
    return null;
  }
  const rawValue = query[key];
  if (rawValue === null || rawValue === undefined) {
    throw auditErrors.invalidPayload();
  }
  if (Array.isArray(rawValue) || typeof rawValue !== 'string') {
    throw auditErrors.invalidPayload();
  }
  const normalized = rawValue.trim();
  if (
    !normalized
    || rawValue !== normalized
    || normalized.length > maxLength
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    throw auditErrors.invalidPayload();
  }
  return normalized;
};

const normalizePositiveIntegerQuery = ({
  query,
  key,
  defaultValue,
  min = 1,
  max = Number.MAX_SAFE_INTEGER
} = {}) => {
  if (!Object.prototype.hasOwnProperty.call(query, key)) {
    return defaultValue;
  }
  const rawValue = query[key];
  if (Array.isArray(rawValue) || typeof rawValue !== 'string') {
    throw auditErrors.invalidPayload();
  }
  if (!/^\d+$/.test(rawValue)) {
    throw auditErrors.invalidPayload();
  }
  const parsed = Number(rawValue);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw auditErrors.invalidPayload();
  }
  return parsed;
};

const normalizeOptionalDateTimeQuery = ({ query, key } = {}) => {
  const value = normalizeOptionalStrictQueryString({
    query,
    key,
    maxLength: 64
  });
  if (value === null) {
    return null;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw auditErrors.invalidPayload();
  }
  return parsed.toISOString();
};

const normalizeOptionalAuditResultQuery = ({ query, key } = {}) => {
  const value = normalizeOptionalStrictQueryString({
    query,
    key,
    maxLength: 16
  });
  if (value === null) {
    return null;
  }
  const normalized = value.toLowerCase();
  if (!VALID_AUDIT_RESULT.has(normalized)) {
    throw auditErrors.invalidPayload();
  }
  return normalized;
};

const normalizeOptionalTraceparentQuery = ({ query, key } = {}) => {
  const value = normalizeOptionalStrictQueryString({
    query,
    key,
    maxLength: 128
  });
  if (value === null) {
    return null;
  }
  const normalizedTraceparent = normalizeTraceparent(value);
  if (!normalizedTraceparent) {
    throw auditErrors.invalidPayload();
  }
  return normalizedTraceparent;
};

const resolveActiveTenantId = (authorizationContext = null) =>
  normalizeRequiredString(
    authorizationContext?.active_tenant_id
      || authorizationContext?.activeTenantId
      || authorizationContext?.session_context?.active_tenant_id
      || authorizationContext?.session_context?.activeTenantId
      || authorizationContext?.sessionContext?.active_tenant_id
      || authorizationContext?.sessionContext?.activeTenantId
      || authorizationContext?.session?.sessionContext?.active_tenant_id
      || authorizationContext?.session?.sessionContext?.activeTenantId
      || authorizationContext?.session?.session_context?.active_tenant_id
      || authorizationContext?.session?.session_context?.activeTenantId
  );

const resolveAuthorizedIdentity = (authorizationContext = null) => {
  const userId = normalizeRequiredString(
    authorizationContext?.user_id
      || authorizationContext?.userId
      || authorizationContext?.user?.id
      || authorizationContext?.user?.user_id
      || authorizationContext?.user?.userId
  );
  const sessionId = normalizeRequiredString(
    authorizationContext?.session_id
      || authorizationContext?.sessionId
      || authorizationContext?.session?.sessionId
      || authorizationContext?.session?.session_id
  );
  return {
    userId,
    sessionId
  };
};

const throwAuditQueryResultInvalid = () => {
  throw auditErrors.auditDependencyUnavailable({
    reason: 'audit-query-result-invalid'
  });
};

const normalizeOptionalDependencyString = (value, maxLength) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    throwAuditQueryResultInvalid();
  }
  const normalized = value.trim();
  if (
    !normalized
    || normalized !== value
    || normalized.length > maxLength
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    throwAuditQueryResultInvalid();
  }
  return normalized;
};

const normalizeRequiredDependencyString = (value, maxLength) => {
  const normalized = normalizeOptionalDependencyString(value, maxLength);
  if (!normalized) {
    throwAuditQueryResultInvalid();
  }
  return normalized;
};

const normalizeOptionalDependencyTraceparent = (value) => {
  const normalized = normalizeOptionalDependencyString(value, 128);
  if (!normalized) {
    return null;
  }
  const normalizedTraceparent = normalizeTraceparent(normalized);
  if (!normalizedTraceparent) {
    throwAuditQueryResultInvalid();
  }
  return normalizedTraceparent;
};

const normalizeDependencyResult = (value) => {
  const normalized = normalizeRequiredDependencyString(value, 16).toLowerCase();
  if (!VALID_AUDIT_RESULT.has(normalized)) {
    throwAuditQueryResultInvalid();
  }
  return normalized;
};

const normalizeDependencyOccurredAt = (value) => {
  const normalized = normalizeRequiredDependencyString(value, 64);
  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime())) {
    throwAuditQueryResultInvalid();
  }
  return parsed.toISOString();
};

const cloneJsonCompatibleValue = (value) => {
  if (value === undefined) {
    return null;
  }
  if (value === null) {
    return null;
  }
  try {
    return JSON.parse(JSON.stringify(value));
  } catch (_error) {
    throwAuditQueryResultInvalid();
  }
};

const normalizeAuditEventFromDependency = ({
  event,
  expectedDomain,
  expectedTenantId = null,
  requestedTenantId = null
} = {}) => {
  if (!isPlainObject(event)) {
    throwAuditQueryResultInvalid();
  }
  const normalizedDomain = normalizeRequiredDependencyString(event.domain, 32).toLowerCase();
  if (normalizedDomain !== expectedDomain) {
    throwAuditQueryResultInvalid();
  }
  const normalizedTenantId = normalizeOptionalDependencyString(event.tenant_id, 64);
  if (
    expectedDomain === TENANT_AUDIT_SCOPE
    && normalizedTenantId !== expectedTenantId
  ) {
    throwAuditQueryResultInvalid();
  }
  if (
    expectedDomain === PLATFORM_AUDIT_SCOPE
    && requestedTenantId
    && normalizedTenantId !== requestedTenantId
  ) {
    throwAuditQueryResultInvalid();
  }
  return {
    event_id: normalizeRequiredDependencyString(event.event_id, 64),
    domain: normalizedDomain,
    tenant_id: normalizedTenantId,
    request_id: normalizeRequiredDependencyString(event.request_id, 128),
    traceparent: normalizeOptionalDependencyTraceparent(event.traceparent),
    event_type: normalizeRequiredDependencyString(event.event_type, 128),
    actor_user_id: normalizeOptionalDependencyString(event.actor_user_id, 64),
    actor_session_id: normalizeOptionalDependencyString(event.actor_session_id, 128),
    target_type: normalizeRequiredDependencyString(event.target_type, 64),
    target_id: normalizeOptionalDependencyString(event.target_id, 128),
    result: normalizeDependencyResult(event.result),
    before_state: cloneJsonCompatibleValue(event.before_state),
    after_state: cloneJsonCompatibleValue(event.after_state),
    metadata: cloneJsonCompatibleValue(event.metadata),
    occurred_at: normalizeDependencyOccurredAt(event.occurred_at)
  };
};

const normalizeAuditEventsPayload = ({
  events,
  expectedDomain,
  expectedTenantId = null,
  requestedTenantId = null
} = {}) => {
  if (!Array.isArray(events)) {
    throwAuditQueryResultInvalid();
  }
  return events.map((event) =>
    normalizeAuditEventFromDependency({
      event,
      expectedDomain,
      expectedTenantId,
      requestedTenantId
    }));
};

const normalizeNonNegativeInteger = (value = 0) => {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw auditErrors.auditDependencyUnavailable({
      reason: 'audit-query-result-invalid'
    });
  }
  return parsed;
};

const parseAuditQuery = ({
  query,
  allowedKeys
} = {}) => {
  if (!isPlainObject(query)) {
    throw auditErrors.invalidPayload();
  }
  for (const key of Object.keys(query)) {
    if (!allowedKeys.has(key)) {
      throw auditErrors.invalidPayload();
    }
  }

  const page = normalizePositiveIntegerQuery({
    query,
    key: 'page',
    defaultValue: DEFAULT_AUDIT_PAGE,
    min: 1,
    max: MAX_AUDIT_PAGE
  });
  const pageSize = normalizePositiveIntegerQuery({
    query,
    key: 'page_size',
    defaultValue: DEFAULT_AUDIT_PAGE_SIZE,
    min: 1,
    max: MAX_AUDIT_PAGE_SIZE
  });
  const from = normalizeOptionalDateTimeQuery({ query, key: 'from' });
  const to = normalizeOptionalDateTimeQuery({ query, key: 'to' });
  if (from && to && new Date(from).getTime() > new Date(to).getTime()) {
    throw auditErrors.invalidPayload();
  }

  return {
    page,
    pageSize,
    from,
    to,
    eventType: normalizeOptionalStrictQueryString({
      query,
      key: 'event_type',
      maxLength: 128
    }),
    result: normalizeOptionalAuditResultQuery({ query, key: 'result' }),
    requestId: normalizeOptionalStrictQueryString({
      query,
      key: 'request_id',
      maxLength: 128
    }),
    traceparent: normalizeOptionalTraceparentQuery({
      query,
      key: 'traceparent'
    }),
    actorUserId: normalizeOptionalStrictQueryString({
      query,
      key: 'actor_user_id',
      maxLength: 64
    }),
    targetType: normalizeOptionalStrictQueryString({
      query,
      key: 'target_type',
      maxLength: 64
    }),
    targetId: normalizeOptionalStrictQueryString({
      query,
      key: 'target_id',
      maxLength: 128
    }),
    tenantId: normalizeOptionalStrictQueryString({
      query,
      key: 'tenant_id',
      maxLength: 64
    })
  };
};

const createAuditService = ({ authService } = {}) => {
  if (!authService || typeof authService !== 'object') {
    throw new TypeError('createAuditService requires authService');
  }
  if (typeof authService.listAuditEvents !== 'function') {
    throw new TypeError('createAuditService requires authService.listAuditEvents');
  }

  const resolveOperatorContext = async ({
    requestId,
    accessToken,
    authorizationContext = null,
    permissionCode,
    scope,
    entryDomain
  }) => {
    const preauthorizedContext = resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode: permissionCode,
      expectedScope: scope,
      expectedEntryDomain: entryDomain
    });
    if (preauthorizedContext) {
      return {
        operatorUserId: preauthorizedContext.userId,
        operatorSessionId: preauthorizedContext.sessionId,
        activeTenantId: resolveActiveTenantId(authorizationContext)
      };
    }

    if (typeof authService.authorizeRoute !== 'function') {
      throw auditErrors.auditDependencyUnavailable({
        reason: 'authorize-route-unsupported'
      });
    }

    const authorizationResult = await authService.authorizeRoute({
      requestId,
      accessToken,
      permissionCode,
      scope
    });
    const {
      userId,
      sessionId
    } = resolveAuthorizedIdentity(authorizationResult);
    if (!userId || !sessionId) {
      throw auditErrors.auditDependencyUnavailable({
        reason: 'authorization-context-invalid'
      });
    }

    return {
      operatorUserId: userId,
      operatorSessionId: sessionId,
      activeTenantId:
        resolveActiveTenantId(authorizationResult)
        || resolveActiveTenantId(authorizationContext)
    };
  };

  const listPlatformAuditEvents = async ({
    requestId,
    accessToken,
    query = {},
    authorizationContext = null
  } = {}) => {
    const resolvedRequestId = normalizeRequiredString(requestId) || 'request_id_unset';
    await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_AUDIT_VIEW_PERMISSION_CODE,
      scope: PLATFORM_AUDIT_SCOPE,
      entryDomain: PLATFORM_AUDIT_SCOPE
    });

    const parsedQuery = parseAuditQuery({
      query,
      allowedKeys: PLATFORM_AUDIT_ALLOWED_QUERY_KEYS
    });

    let auditListResult;
    try {
      auditListResult = await authService.listAuditEvents({
        domain: PLATFORM_AUDIT_SCOPE,
        tenantId: parsedQuery.tenantId,
        page: parsedQuery.page,
        pageSize: parsedQuery.pageSize,
        from: parsedQuery.from,
        to: parsedQuery.to,
        eventType: parsedQuery.eventType,
        result: parsedQuery.result,
        requestId: parsedQuery.requestId,
        traceparent: parsedQuery.traceparent,
        actorUserId: parsedQuery.actorUserId,
        targetType: parsedQuery.targetType,
        targetId: parsedQuery.targetId
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      log('warn', 'Platform audit events query failed', {
        request_id: resolvedRequestId,
        detail: String(error?.message || 'unknown')
      });
      throw auditErrors.auditDependencyUnavailable({
        reason: 'audit-query-failed'
      });
    }

    return {
      domain: PLATFORM_AUDIT_SCOPE,
      page: parsedQuery.page,
      page_size: parsedQuery.pageSize,
      total: normalizeNonNegativeInteger(auditListResult?.total || 0),
      events: normalizeAuditEventsPayload({
        events: auditListResult?.events,
        expectedDomain: PLATFORM_AUDIT_SCOPE,
        requestedTenantId: parsedQuery.tenantId
      }),
      request_id: resolvedRequestId
    };
  };

  const listTenantAuditEvents = async ({
    requestId,
    accessToken,
    query = {},
    authorizationContext = null
  } = {}) => {
    const resolvedRequestId = normalizeRequiredString(requestId) || 'request_id_unset';
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_AUDIT_VIEW_PERMISSION_CODE,
      scope: TENANT_AUDIT_SCOPE,
      entryDomain: TENANT_AUDIT_SCOPE
    });
    const activeTenantId = normalizeRequiredString(operatorContext.activeTenantId);
    if (!activeTenantId) {
      throw auditErrors.noDomainAccess();
    }

    const parsedQuery = parseAuditQuery({
      query,
      allowedKeys: TENANT_AUDIT_ALLOWED_QUERY_KEYS
    });

    let auditListResult;
    try {
      auditListResult = await authService.listAuditEvents({
        domain: TENANT_AUDIT_SCOPE,
        tenantId: activeTenantId,
        page: parsedQuery.page,
        pageSize: parsedQuery.pageSize,
        from: parsedQuery.from,
        to: parsedQuery.to,
        eventType: parsedQuery.eventType,
        result: parsedQuery.result,
        requestId: parsedQuery.requestId,
        traceparent: parsedQuery.traceparent,
        actorUserId: parsedQuery.actorUserId,
        targetType: parsedQuery.targetType,
        targetId: parsedQuery.targetId
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      log('warn', 'Tenant audit events query failed', {
        request_id: resolvedRequestId,
        tenant_id: activeTenantId,
        detail: String(error?.message || 'unknown')
      });
      throw auditErrors.auditDependencyUnavailable({
        reason: 'audit-query-failed'
      });
    }

    return {
      domain: TENANT_AUDIT_SCOPE,
      page: parsedQuery.page,
      page_size: parsedQuery.pageSize,
      total: normalizeNonNegativeInteger(auditListResult?.total || 0),
      events: normalizeAuditEventsPayload({
        events: auditListResult?.events,
        expectedDomain: TENANT_AUDIT_SCOPE,
        expectedTenantId: activeTenantId
      }),
      request_id: resolvedRequestId
    };
  };

  return {
    listPlatformAuditEvents,
    listTenantAuditEvents,
    _internals: {
      authService
    }
  };
};

module.exports = { createAuditService };

const http = require('node:http');
const { randomUUID, createHash } = require('node:crypto');
const { readConfig } = require('./config/env');
const { createRouteHandlers } = require('./http-routes');
const { checkDependencies } = require('./infrastructure/connectivity');
const { buildProblemDetails } = require('./common/problem-details');
const { AuthProblemError } = require('./modules/auth/auth.routes');
const {
  markRoutePreauthorizedContext
} = require('./modules/auth/route-preauthorization');
const {
  PLATFORM_ORG_CREATE_ROUTE_KEY,
  PLATFORM_ORG_STATUS_ROUTE_KEY,
  PLATFORM_ORG_OWNER_TRANSFER_ROUTE_KEY,
  PLATFORM_ORG_OWNER_TRANSFER_PATH
} = require('./modules/platform/org.constants');
const {
  PLATFORM_ROLE_LIST_ROUTE_KEY,
  PLATFORM_ROLE_CREATE_ROUTE_KEY,
  PLATFORM_ROLE_UPDATE_ROUTE_KEY,
  PLATFORM_ROLE_DELETE_ROUTE_KEY,
  PLATFORM_ROLE_PERMISSION_GET_ROUTE_KEY,
  PLATFORM_ROLE_PERMISSION_PUT_ROUTE_KEY
} = require('./modules/platform/role.constants');
const {
  PLATFORM_USER_CREATE_ROUTE_KEY,
  PLATFORM_USER_STATUS_ROUTE_KEY
} = require('./modules/platform/user.constants');
const {
  TENANT_MEMBER_LIST_ROUTE_KEY,
  TENANT_MEMBER_CREATE_ROUTE_KEY,
  TENANT_MEMBER_DETAIL_ROUTE_KEY,
  TENANT_MEMBER_STATUS_ROUTE_KEY,
  TENANT_MEMBER_PROFILE_ROUTE_KEY,
  TENANT_MEMBER_ROLE_BINDING_GET_ROUTE_KEY,
  TENANT_MEMBER_ROLE_BINDING_PUT_ROUTE_KEY
} = require('./modules/tenant/member.constants');
const {
  TENANT_ROLE_LIST_ROUTE_KEY,
  TENANT_ROLE_CREATE_ROUTE_KEY,
  TENANT_ROLE_UPDATE_ROUTE_KEY,
  TENANT_ROLE_DELETE_ROUTE_KEY,
  TENANT_ROLE_PERMISSION_GET_ROUTE_KEY,
  TENANT_ROLE_PERMISSION_PUT_ROUTE_KEY
} = require('./modules/tenant/role.constants');
const {
  listSupportedRoutePermissionCodes,
  listSupportedRoutePermissionScopes
} = require('./modules/auth/auth.service');
const {
  ROUTE_DEFINITIONS,
  toRouteDefinitionsSnapshot,
  createRouteDefinitionMap,
  listDeclaredRoutePaths,
  findRouteDefinitionInMap,
  isRoutePathMatch,
  extractRoutePathParams,
  ensureRoutePermissionDeclarationsOrThrow
} = require('./route-permissions');
const ROUTE_DECLARATION_LOOKUP_CACHE = new WeakMap();
const AUTHORIZE_ROUTE_PREFLIGHT_CACHE = new WeakMap();
const ROUTE_DECLARATION_LOOKUP_TOKEN = Symbol('routeDeclarationLookup');

const asMethod = (method) => String(method || 'GET').toUpperCase();

const normalizePathname = (pathname) => {
  if (!pathname || pathname === '/') {
    return '/';
  }
  return pathname.replace(/\/+$/, '') || '/';
};
const hasNonCanonicalRoutePathSlashes = (pathname) => {
  const raw = String(pathname || '');
  if (raw.length === 0 || raw === '/') {
    return false;
  }
  return raw.includes('//') || raw.endsWith('/');
};

const parseRequestPath = (inputPath) => {
  const raw = typeof inputPath === 'string' && inputPath.length > 0 ? inputPath : '/';
  try {
    const parsed = new URL(raw, 'http://localhost');
    return {
      rawPathname: parsed.pathname || '/',
      pathname: normalizePathname(parsed.pathname),
      search: parsed.search || ''
    };
  } catch (_error) {
    const [pathnameOnly, ...queryParts] = raw.split('?');
    return {
      rawPathname: pathnameOnly || '/',
      pathname: normalizePathname(pathnameOnly),
      search: queryParts.length > 0 ? `?${queryParts.join('?')}` : ''
    };
  }
};

const parseRequestQuery = (search = '') => {
  const rawSearch = String(search || '');
  if (!rawSearch || rawSearch === '?') {
    return {};
  }
  const searchValue = rawSearch.startsWith('?') ? rawSearch.slice(1) : rawSearch;
  const searchParams = new URLSearchParams(searchValue);
  const query = Object.create(null);
  for (const [key, value] of searchParams.entries()) {
    if (!Object.prototype.hasOwnProperty.call(query, key)) {
      query[key] = value;
      continue;
    }
    if (Array.isArray(query[key])) {
      query[key].push(value);
    } else {
      query[key] = [query[key], value];
    }
  }
  return query;
};

const DEFAULT_JSON_BODY_LIMIT_BYTES = 1024 * 1024;
const MAX_REQUEST_ID_LENGTH = 128;
const MAX_IDEMPOTENCY_KEY_LENGTH = 128;
const OWNER_TRANSFER_ORG_ID_MAX_LENGTH = 64;
const DEFAULT_IDEMPOTENCY_REPLAY_TTL_MS = 10 * 60 * 1000;
const DEFAULT_IDEMPOTENCY_PENDING_TTL_MS = 30 * 1000;
const DEFAULT_IDEMPOTENCY_WAIT_TIMEOUT_MS = 5000;
const DEFAULT_IDEMPOTENCY_WAIT_POLL_INTERVAL_MS = 40;
const DEFAULT_IN_MEMORY_IDEMPOTENCY_MAX_ENTRIES = 5000;
const IDEMPOTENCY_REQUEST_HASH_PATTERN = /^[0-9a-f]{64}$/i;
const IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES = new Set([
  400,
  401,
  403,
  404,
  413,
  415,
  422,
  429
]);
const IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES_WITH_CONFLICT = new Set([
  ...IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES,
  409
]);
const IDEMPOTENCY_PROTECTED_ROUTE_KEYS = new Set([
  'POST /auth/tenant/member-admin/provision-user',
  'POST /auth/platform/member-admin/provision-user',
  TENANT_MEMBER_CREATE_ROUTE_KEY,
  TENANT_MEMBER_PROFILE_ROUTE_KEY,
  TENANT_MEMBER_STATUS_ROUTE_KEY,
  TENANT_MEMBER_ROLE_BINDING_PUT_ROUTE_KEY,
  TENANT_ROLE_CREATE_ROUTE_KEY,
  TENANT_ROLE_UPDATE_ROUTE_KEY,
  TENANT_ROLE_DELETE_ROUTE_KEY,
  TENANT_ROLE_PERMISSION_PUT_ROUTE_KEY,
  'POST /auth/platform/role-facts/replace',
  PLATFORM_ORG_CREATE_ROUTE_KEY,
  PLATFORM_ORG_STATUS_ROUTE_KEY,
  PLATFORM_ORG_OWNER_TRANSFER_ROUTE_KEY,
  PLATFORM_ROLE_CREATE_ROUTE_KEY,
  PLATFORM_ROLE_UPDATE_ROUTE_KEY,
  PLATFORM_ROLE_DELETE_ROUTE_KEY,
  PLATFORM_ROLE_PERMISSION_PUT_ROUTE_KEY,
  PLATFORM_USER_CREATE_ROUTE_KEY,
  PLATFORM_USER_STATUS_ROUTE_KEY
]);
const IDEMPOTENCY_USER_SCOPED_ROUTE_KEYS = new Set([
  TENANT_MEMBER_CREATE_ROUTE_KEY,
  TENANT_MEMBER_PROFILE_ROUTE_KEY,
  TENANT_MEMBER_STATUS_ROUTE_KEY,
  TENANT_MEMBER_ROLE_BINDING_PUT_ROUTE_KEY,
  TENANT_ROLE_CREATE_ROUTE_KEY,
  TENANT_ROLE_UPDATE_ROUTE_KEY,
  TENANT_ROLE_DELETE_ROUTE_KEY,
  TENANT_ROLE_PERMISSION_PUT_ROUTE_KEY,
  PLATFORM_ORG_CREATE_ROUTE_KEY,
  PLATFORM_ORG_STATUS_ROUTE_KEY,
  PLATFORM_ORG_OWNER_TRANSFER_ROUTE_KEY,
  PLATFORM_ROLE_CREATE_ROUTE_KEY,
  PLATFORM_ROLE_UPDATE_ROUTE_KEY,
  PLATFORM_ROLE_DELETE_ROUTE_KEY,
  PLATFORM_ROLE_PERMISSION_PUT_ROUTE_KEY,
  PLATFORM_USER_CREATE_ROUTE_KEY,
  PLATFORM_USER_STATUS_ROUTE_KEY
]);
const IDEMPOTENCY_USER_SCOPED_ROUTE_KEYS_IGNORE_TENANT = new Set([
  PLATFORM_ORG_CREATE_ROUTE_KEY,
  PLATFORM_ORG_STATUS_ROUTE_KEY,
  PLATFORM_ORG_OWNER_TRANSFER_ROUTE_KEY,
  PLATFORM_ROLE_CREATE_ROUTE_KEY,
  PLATFORM_ROLE_UPDATE_ROUTE_KEY,
  PLATFORM_ROLE_DELETE_ROUTE_KEY,
  PLATFORM_ROLE_PERMISSION_PUT_ROUTE_KEY,
  PLATFORM_USER_CREATE_ROUTE_KEY,
  PLATFORM_USER_STATUS_ROUTE_KEY
]);
const IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES_BY_ROUTE = new Map([
  [TENANT_MEMBER_CREATE_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES_WITH_CONFLICT],
  [TENANT_MEMBER_PROFILE_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES_WITH_CONFLICT],
  [TENANT_MEMBER_STATUS_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES_WITH_CONFLICT],
  [TENANT_MEMBER_ROLE_BINDING_PUT_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES],
  [TENANT_ROLE_CREATE_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES],
  [TENANT_ROLE_UPDATE_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES],
  [TENANT_ROLE_DELETE_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES],
  [TENANT_ROLE_PERMISSION_PUT_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES],
  [PLATFORM_ORG_CREATE_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES],
  [PLATFORM_ORG_STATUS_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES],
  [
    PLATFORM_ORG_OWNER_TRANSFER_ROUTE_KEY,
    IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES_WITH_CONFLICT
  ],
  [PLATFORM_ROLE_CREATE_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES],
  [PLATFORM_ROLE_UPDATE_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES],
  [PLATFORM_ROLE_DELETE_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES],
  [PLATFORM_ROLE_PERMISSION_PUT_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES],
  [PLATFORM_USER_CREATE_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES],
  [PLATFORM_USER_STATUS_ROUTE_KEY, IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES]
]);
const IDEMPOTENCY_REQUEST_HASH_IGNORES_BODY_ROUTE_KEYS = new Set([
  TENANT_ROLE_DELETE_ROUTE_KEY,
  PLATFORM_ROLE_DELETE_ROUTE_KEY
]);

const resolveJsonBodyLimitBytes = (value) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_JSON_BODY_LIMIT_BYTES;
  }
  return Math.floor(parsed);
};

const CORS_WILDCARD_ORIGIN = '*';
const CORS_ALLOW_HEADERS = 'Authorization, Content-Type, X-Request-Id, Idempotency-Key';
const CORS_MAX_AGE_SECONDS = '600';
const DEFAULT_CORS_ALLOWED_ORIGINS = Object.freeze([
  'http://localhost:4173',
  'http://127.0.0.1:4173'
]);
const CORS_METHOD_ORDER = Object.freeze([
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS'
]);
const CORS_METHOD_ORDER_INDEX = new Map(
  CORS_METHOD_ORDER.map((method, index) => [method, index])
);
const REQUEST_ID_CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]+/g;
const OWNER_TRANSFER_CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const OWNER_TRANSFER_WHITESPACE_PATTERN = /\s/;

const parseCorsAllowedOrigins = (rawOrigins, nodeEnv = 'development') => {
  const hasExplicitOrigins =
    rawOrigins !== undefined
    && rawOrigins !== null
    && String(rawOrigins).trim().length > 0;
  if (!hasExplicitOrigins) {
    return nodeEnv === 'production' ? [] : [...DEFAULT_CORS_ALLOWED_ORIGINS];
  }
  return String(rawOrigins)
    .split(',')
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);
};

const createCorsPolicy = (config = {}) => {
  const allowedOrigins = parseCorsAllowedOrigins(
    config.API_CORS_ALLOWED_ORIGINS,
    config.NODE_ENV
  );
  if (allowedOrigins.includes(CORS_WILDCARD_ORIGIN)) {
    return Object.freeze({
      allowAnyOrigin: true,
      allowedOrigins: Object.freeze([CORS_WILDCARD_ORIGIN]),
      allowedOriginSet: new Set(),
      fallbackOrigin: CORS_WILDCARD_ORIGIN
    });
  }
  const uniqueAllowedOrigins = [...new Set(allowedOrigins)];
  return Object.freeze({
    allowAnyOrigin: false,
    allowedOrigins: Object.freeze(uniqueAllowedOrigins),
    allowedOriginSet: new Set(uniqueAllowedOrigins),
    fallbackOrigin: uniqueAllowedOrigins[0] || ''
  });
};

const DEFAULT_CORS_POLICY = createCorsPolicy({
  API_CORS_ALLOWED_ORIGINS: CORS_WILDCARD_ORIGIN,
  NODE_ENV: 'development'
});

const mergeVaryHeader = (existingVary, nextToken) => {
  const normalizedToken = String(nextToken || '').trim();
  if (normalizedToken.length === 0) {
    return String(existingVary || '').trim();
  }
  const values = String(existingVary || '')
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
  if (!values.includes(normalizedToken)) {
    values.push(normalizedToken);
  }
  return values.join(', ');
};

const resolveCorsAllowOrigin = ({
  corsPolicy = DEFAULT_CORS_POLICY,
  requestOrigin = ''
} = {}) => {
  if (corsPolicy.allowAnyOrigin) {
    return CORS_WILDCARD_ORIGIN;
  }
  const normalizedRequestOrigin = String(requestOrigin || '').trim();
  if (
    normalizedRequestOrigin.length > 0
    && corsPolicy.allowedOriginSet.has(normalizedRequestOrigin)
  ) {
    return normalizedRequestOrigin;
  }
  return '';
};

const applyCorsPolicyToHeaders = (
  headers = {},
  corsPolicy = DEFAULT_CORS_POLICY,
  requestOrigin = ''
) => {
  const nextHeaders = {
    ...headers
  };
  const allowOrigin = resolveCorsAllowOrigin({
    corsPolicy,
    requestOrigin
  });
  if (allowOrigin) {
    nextHeaders['access-control-allow-origin'] = allowOrigin;
  } else {
    delete nextHeaders['access-control-allow-origin'];
  }
  if (!corsPolicy.allowAnyOrigin) {
    nextHeaders.vary = mergeVaryHeader(nextHeaders.vary, 'Origin');
  }
  return nextHeaders;
};

const withCorsHeaders = (headers = {}, options = {}) =>
  applyCorsPolicyToHeaders(
    headers,
    options.corsPolicy || DEFAULT_CORS_POLICY,
    options.requestOrigin || ''
  );

const toCorsAllowMethods = (methods = []) => {
  const normalizedMethods = new Set();
  for (const method of methods) {
    const normalizedMethod = asMethod(method);
    if (normalizedMethod.length > 0) {
      normalizedMethods.add(normalizedMethod);
    }
  }
  normalizedMethods.add('OPTIONS');
  return [...normalizedMethods]
    .sort((left, right) => {
      const leftIndex = CORS_METHOD_ORDER_INDEX.has(left)
        ? CORS_METHOD_ORDER_INDEX.get(left)
        : Number.MAX_SAFE_INTEGER;
      const rightIndex = CORS_METHOD_ORDER_INDEX.has(right)
        ? CORS_METHOD_ORDER_INDEX.get(right)
        : Number.MAX_SAFE_INTEGER;
      if (leftIndex !== rightIndex) {
        return leftIndex - rightIndex;
      }
      return left.localeCompare(right);
    })
    .join(',');
};

const preflightCorsHeaders = (allowMethods = [], options = {}) =>
  withCorsHeaders({
    'access-control-allow-methods': toCorsAllowMethods(allowMethods),
    'access-control-allow-headers': CORS_ALLOW_HEADERS,
    'access-control-max-age': CORS_MAX_AGE_SECONDS,
    vary: 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers'
  }, options);

const responseJson = (
  status,
  payload,
  contentType = 'application/json',
  options = {}
) => ({
  status,
  headers: withCorsHeaders({ 'content-type': contentType }, options),
  body: JSON.stringify(payload)
});

const responseNoContent = (status, headers = {}, options = {}) => ({
  status,
  headers: withCorsHeaders({
    ...headers,
    'content-length': '0'
  }, options),
  body: ''
});

const asPositiveInteger = (value) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return null;
  }
  return Math.ceil(parsed);
};

const readHeaderValue = (headers = {}, headerName) => {
  const normalizedHeaderName = String(headerName || '').trim().toLowerCase();
  if (!normalizedHeaderName) {
    return { present: false, value: '', values: [] };
  }
  const collectedValues = [];
  for (const [key, value] of Object.entries(headers || {})) {
    if (String(key || '').trim().toLowerCase() !== normalizedHeaderName) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        collectedValues.push(String(item ?? ''));
      }
    } else {
      collectedValues.push(String(value ?? ''));
    }
  }
  if (collectedValues.length === 0) {
    return { present: false, value: '', values: [] };
  }
  return { present: true, value: collectedValues[0], values: collectedValues };
};

const isHeaderSafeValue = (headerName, value) => {
  try {
    http.validateHeaderValue(headerName, value);
    return true;
  } catch (_error) {
    return false;
  }
};

const normalizeRequestIdCandidate = (value) => {
  const normalized = String(value ?? '')
    .replace(REQUEST_ID_CONTROL_CHAR_PATTERN, ' ')
    .trim();
  if (!normalized) {
    return '';
  }
  try {
    http.validateHeaderValue('x-request-id', normalized);
  } catch (_error) {
    return '';
  }
  const bounded =
    normalized.length <= MAX_REQUEST_ID_LENGTH
      ? normalized
      : normalized.slice(0, MAX_REQUEST_ID_LENGTH);
  try {
    http.validateHeaderValue('x-request-id', bounded);
  } catch (_error) {
    return '';
  }
  return bounded;
};

const resolveRequestIdFromHeaders = (headers = {}) => {
  const rawRequestIdHeader = readHeaderValue(headers, 'x-request-id');
  const normalizedValues = rawRequestIdHeader.values
    .map((value) => normalizeRequestIdCandidate(value))
    .filter((value) => value.length > 0);
  const hasAmbiguousMultiValueHeader = rawRequestIdHeader.values.length > 1;
  const hasAmbiguousCommaSeparatedValue = normalizedValues.some((value) =>
    value.includes(',')
  );
  if (
    hasAmbiguousMultiValueHeader
    || hasAmbiguousCommaSeparatedValue
    || normalizedValues.length !== 1
  ) {
    return randomUUID();
  }
  return normalizedValues[0];
};

const resolveRequestId = ({ requestId, headers = {} } = {}) => {
  const normalizedRequestId = normalizeRequestIdCandidate(requestId);
  if (normalizedRequestId && !normalizedRequestId.includes(',')) {
    return normalizedRequestId;
  }
  return resolveRequestIdFromHeaders(headers);
};

const requestIdFrom = (req) =>
  resolveRequestIdFromHeaders(req?.headers || {});

const normalizeIdempotencyKey = (headers = {}) => {
  const rawIdempotencyKey = readHeaderValue(headers, 'idempotency-key');
  let hasInvalidHeaderValue = false;
  const normalizedValues = rawIdempotencyKey.values
    .map((value) => String(value || '').trim())
    .map((value) => {
      if (value.length === 0) {
        return '';
      }
      if (!isHeaderSafeValue('idempotency-key', value)) {
        hasInvalidHeaderValue = true;
        return '';
      }
      return value;
    })
    .filter((value) => value.length > 0);
  const hasAmbiguousMultiValueHeader = rawIdempotencyKey.values.length > 1;
  const hasAmbiguousCommaSeparatedValue = normalizedValues.some((value) =>
    value.includes(',')
  );
  return {
    present: rawIdempotencyKey.present,
    invalid:
      hasInvalidHeaderValue
      || hasAmbiguousMultiValueHeader
      || hasAmbiguousCommaSeparatedValue,
    value: normalizedValues.length === 1 ? normalizedValues[0] : ''
  };
};

const normalizeAuthorizationHeader = (headers = {}) => {
  const rawAuthorization = readHeaderValue(headers, 'authorization');
  let hasInvalidHeaderValue = false;
  const normalizedValues = rawAuthorization.values
    .map((value) => String(value || '').trim())
    .map((value) => {
      if (value.length === 0) {
        return '';
      }
      if (!isHeaderSafeValue('authorization', value)) {
        hasInvalidHeaderValue = true;
        return '';
      }
      return value;
    })
    .filter((value) => value.length > 0);
  const hasAmbiguousMultiValueHeader = rawAuthorization.values.length > 1;
  const hasAmbiguousCommaSeparatedValue = normalizedValues.some((value) =>
    value.includes(',')
  );
  return {
    present: rawAuthorization.present,
    invalid:
      hasInvalidHeaderValue
      || hasAmbiguousMultiValueHeader
      || hasAmbiguousCommaSeparatedValue,
    value: normalizedValues.length === 1 ? normalizedValues[0] : ''
  };
};

const hashFingerprint = (value) =>
  createHash('sha256').update(String(value || '')).digest('hex');

const canonicalizeForHash = (value) => {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeForHash(item));
  }
  if (!value || typeof value !== 'object') {
    return value;
  }
  const normalized = {};
  for (const key of Object.keys(value).sort()) {
    const normalizedValue = canonicalizeForHash(value[key]);
    if (normalizedValue === undefined) {
      continue;
    }
    normalized[key] = normalizedValue;
  }
  return normalized;
};

const toIdempotencyRequestHash = (payload = {}) =>
  hashFingerprint(JSON.stringify(canonicalizeForHash(payload || {})));

const toIdempotencyRouteVariant = (routeParams = {}) =>
  JSON.stringify(canonicalizeForHash(routeParams || {}));

const normalizeRouteParamsForRoute = ({
  routeKey = '',
  routeParams = {}
} = {}) => {
  const normalizedRouteParams = {
    ...(routeParams && typeof routeParams === 'object' && !Array.isArray(routeParams)
      ? routeParams
      : {})
  };
  if (
    routeKey === TENANT_ROLE_UPDATE_ROUTE_KEY
    || routeKey === TENANT_ROLE_DELETE_ROUTE_KEY
    || routeKey === TENANT_ROLE_PERMISSION_PUT_ROUTE_KEY
  ) {
    normalizedRouteParams.role_id = String(
      normalizedRouteParams.role_id || ''
    ).trim().toLowerCase();
  }
  if (
    routeKey === PLATFORM_ROLE_UPDATE_ROUTE_KEY
    || routeKey === PLATFORM_ROLE_DELETE_ROUTE_KEY
    || routeKey === PLATFORM_ROLE_PERMISSION_PUT_ROUTE_KEY
  ) {
    normalizedRouteParams.role_id = String(
      normalizedRouteParams.role_id || ''
    ).trim().toLowerCase();
  }
  return normalizedRouteParams;
};

const normalizeRouteParamsForIdempotency = ({
  routeKey = '',
  routeParams = {}
} = {}) => {
  const normalizedRouteParams = normalizeRouteParamsForRoute({
    routeKey,
    routeParams
  });
  if (
    routeKey === TENANT_MEMBER_STATUS_ROUTE_KEY
    || routeKey === TENANT_MEMBER_PROFILE_ROUTE_KEY
    || routeKey === TENANT_MEMBER_ROLE_BINDING_PUT_ROUTE_KEY
  ) {
    normalizedRouteParams.membership_id = String(
      normalizedRouteParams.membership_id || ''
    ).trim().toLowerCase();
  }
  return normalizedRouteParams;
};

const normalizeIdempotencyRequestHash = (requestHash) =>
  String(requestHash || '').trim().toLowerCase();

const isValidIdempotencyRequestHash = (requestHash) =>
  IDEMPOTENCY_REQUEST_HASH_PATTERN.test(
    normalizeIdempotencyRequestHash(requestHash)
  );

const resolveIdempotencyActorScope = ({
  routeKey = '',
  authorizationContext = null,
  authorization = ''
} = {}) => {
  const normalizedRouteKey = String(routeKey || '').trim();
  const preferUserScope = IDEMPOTENCY_USER_SCOPED_ROUTE_KEYS.has(normalizedRouteKey);
  const ignoreTenantInScope =
    preferUserScope
    && IDEMPOTENCY_USER_SCOPED_ROUTE_KEYS_IGNORE_TENANT.has(normalizedRouteKey);
  const resolvedSessionId = String(
    authorizationContext?.session_id
    || authorizationContext?.sessionId
    || authorizationContext?.session?.sessionId
    || authorizationContext?.session?.session_id
    || ''
  ).trim();
  const resolvedUserId = String(
    authorizationContext?.user_id
    || authorizationContext?.userId
    || authorizationContext?.user?.id
    || authorizationContext?.user?.user_id
    || ''
  ).trim();
  const resolvedTenantId = String(
    authorizationContext?.active_tenant_id
    || authorizationContext?.activeTenantId
    || authorizationContext?.session_context?.active_tenant_id
    || authorizationContext?.session_context?.activeTenantId
    || authorizationContext?.session?.sessionContext?.active_tenant_id
    || authorizationContext?.session?.sessionContext?.activeTenantId
    || authorizationContext?.session?.session_context?.active_tenant_id
    || authorizationContext?.session?.session_context?.activeTenantId
    || ''
  ).trim();
  const tenantScopeSuffix = ignoreTenantInScope
    ? ''
    : `:tenant:${resolvedTenantId || '-'}`;
  if (preferUserScope) {
    if (resolvedUserId) {
      return `user:${resolvedUserId}${tenantScopeSuffix}`;
    }
    if (resolvedSessionId) {
      return `session:${resolvedSessionId}${tenantScopeSuffix}`;
    }
    return `authorization:${String(authorization || '').trim()}`;
  }
  if (resolvedSessionId) {
    return `session:${resolvedSessionId}:tenant:${resolvedTenantId || '-'}`;
  }
  if (resolvedUserId) {
    return `user:${resolvedUserId}:tenant:${resolvedTenantId || '-'}`;
  }
  return `authorization:${String(authorization || '').trim()}`;
};

const toIdempotencyScopeKey = ({
  routeKey,
  idempotencyKey,
  actorScope,
  routeVariant = ''
}) =>
  `${String(routeKey || '')}:${hashFingerprint(actorScope || '')}:${hashFingerprint(routeVariant || '')}:${hashFingerprint(idempotencyKey || '')}`;

const toIdempotencyScopeWindowKey = ({
  routeKey,
  actorScope,
  routeVariant = ''
}) =>
  `${String(routeKey || '')}:${hashFingerprint(actorScope || '')}:${hashFingerprint(routeVariant || '')}`;

const parseProblemErrorCodeFromResponse = (response = {}) => {
  if (!response || typeof response !== 'object') {
    return '';
  }
  if (typeof response.body !== 'string') {
    return '';
  }
  try {
    const parsed = JSON.parse(response.body);
    if (
      !parsed
      || typeof parsed !== 'object'
      || Array.isArray(parsed)
    ) {
      return '';
    }
    return String(parsed.error_code || '').trim();
  } catch (_error) {
    return '';
  }
};

const parseProblemRetryableFromResponse = (response = {}) => {
  if (!response || typeof response !== 'object') {
    return null;
  }
  if (typeof response.body !== 'string') {
    return null;
  }
  try {
    const parsed = JSON.parse(response.body);
    if (
      !parsed
      || typeof parsed !== 'object'
      || Array.isArray(parsed)
    ) {
      return null;
    }
    if (typeof parsed.retryable !== 'boolean') {
      return null;
    }
    return parsed.retryable;
  } catch (_error) {
    return null;
  }
};

const shouldPersistIdempotencyResponse = ({
  routeKey,
  statusCode,
  response = null
}) => {
  const resolvedStatusCode = Number(statusCode);
  if (!Number.isFinite(resolvedStatusCode) || resolvedStatusCode >= 500) {
    return false;
  }
  if (
    resolvedStatusCode === 409
    && parseProblemRetryableFromResponse(response) === true
  ) {
    return false;
  }
  const nonCacheableStatuses = IDEMPOTENCY_NON_CACHEABLE_STATUS_CODES_BY_ROUTE.get(
    String(routeKey || '').trim()
  );
  const normalizedRouteKey = String(routeKey || '').trim();
  if (
    (normalizedRouteKey === TENANT_MEMBER_CREATE_ROUTE_KEY
      || normalizedRouteKey === TENANT_MEMBER_PROFILE_ROUTE_KEY
      || normalizedRouteKey === TENANT_MEMBER_STATUS_ROUTE_KEY)
    && resolvedStatusCode === 409
  ) {
    return parseProblemRetryableFromResponse(response) !== true;
  }
  if (!(nonCacheableStatuses instanceof Set)) {
    return true;
  }
  if (
    normalizedRouteKey === PLATFORM_ORG_OWNER_TRANSFER_ROUTE_KEY
    && resolvedStatusCode === 409
  ) {
    const errorCode = parseProblemErrorCodeFromResponse(response);
    return errorCode !== 'ORG-409-OWNER-TRANSFER-CONFLICT';
  }
  return !nonCacheableStatuses.has(resolvedStatusCode);
};

const cloneIdempotencyEntryResponse = (response = {}) => ({
  status: Number(response.status),
  headers:
    response.headers && typeof response.headers === 'object' && !Array.isArray(response.headers)
      ? { ...response.headers }
      : {},
  body: String(response.body ?? '')
});

const cloneIdempotencyEntry = (entry = null) => {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    return null;
  }
  if (entry.state === 'pending') {
    return {
      state: 'pending',
      requestHash: String(entry.requestHash || ''),
      pendingToken: String(entry.pendingToken || '')
    };
  }
  if (entry.state === 'resolved') {
    return {
      state: 'resolved',
      requestHash: String(entry.requestHash || ''),
      response: cloneIdempotencyEntryResponse(entry.response)
    };
  }
  return null;
};

const createInMemoryAuthIdempotencyStore = ({
  replayTtlMs = DEFAULT_IDEMPOTENCY_REPLAY_TTL_MS,
  pendingTtlMs = DEFAULT_IDEMPOTENCY_PENDING_TTL_MS,
  maxEntries = DEFAULT_IN_MEMORY_IDEMPOTENCY_MAX_ENTRIES
} = {}) => {
  const resolvedReplayTtlMs = Math.max(1000, Number(replayTtlMs) || DEFAULT_IDEMPOTENCY_REPLAY_TTL_MS);
  const resolvedPendingTtlMs = Math.max(
    1000,
    Math.min(resolvedReplayTtlMs, Number(pendingTtlMs) || DEFAULT_IDEMPOTENCY_PENDING_TTL_MS)
  );
  const resolvedMaxEntries = Math.max(1, Number(maxEntries) || DEFAULT_IN_MEMORY_IDEMPOTENCY_MAX_ENTRIES);
  const entries = new Map();

  const pruneExpiredEntries = (nowMs) => {
    for (const [scopeKey, entry] of entries.entries()) {
      if (Number(entry?.expiresAt || 0) <= nowMs) {
        entries.delete(scopeKey);
      }
    }
  };

  const evictOldestEntries = () => {
    if (entries.size < resolvedMaxEntries) {
      return;
    }
    const overBy = entries.size - resolvedMaxEntries + 1;
    const victims = [...entries.entries()]
      .sort((left, right) => Number(left[1]?.updatedAt || 0) - Number(right[1]?.updatedAt || 0))
      .slice(0, Math.max(1, overBy));
    for (const [victimScopeKey] of victims) {
      entries.delete(victimScopeKey);
    }
  };

  return {
    claimOrRead: async ({
      scopeKey,
      requestHash,
      pendingToken,
      nowMs = Date.now()
    }) => {
      pruneExpiredEntries(nowMs);
      const existing = entries.get(scopeKey);
      if (existing) {
        existing.updatedAt = nowMs;
        return { action: 'existing', entry: cloneIdempotencyEntry(existing) };
      }

      evictOldestEntries();
      entries.set(scopeKey, {
        state: 'pending',
        requestHash: String(requestHash || ''),
        pendingToken: String(pendingToken || ''),
        expiresAt: nowMs + resolvedPendingTtlMs,
        updatedAt: nowMs
      });
      return { action: 'claimed' };
    },

    read: async ({ scopeKey, nowMs = Date.now() }) => {
      pruneExpiredEntries(nowMs);
      const existing = entries.get(scopeKey);
      if (!existing) {
        return null;
      }
      existing.updatedAt = nowMs;
      return cloneIdempotencyEntry(existing);
    },

    resolve: async ({
      scopeKey,
      pendingToken,
      requestHash,
      response,
      nowMs = Date.now()
    }) => {
      pruneExpiredEntries(nowMs);
      const existing = entries.get(scopeKey);
      if (!existing) {
        return false;
      }
      if (
        existing.state !== 'pending'
        || existing.pendingToken !== String(pendingToken || '')
        || existing.requestHash !== String(requestHash || '')
      ) {
        return false;
      }
      entries.set(scopeKey, {
        state: 'resolved',
        requestHash: String(requestHash || ''),
        response: cloneIdempotencyEntryResponse(response),
        expiresAt: nowMs + resolvedReplayTtlMs,
        updatedAt: nowMs
      });
      return true;
    },

    releasePending: async ({
      scopeKey,
      pendingToken,
      requestHash
    }) => {
      const existing = entries.get(scopeKey);
      if (!existing) {
        return true;
      }
      if (
        existing.state === 'pending'
        && existing.pendingToken === String(pendingToken || '')
        && existing.requestHash === String(requestHash || '')
      ) {
        entries.delete(scopeKey);
        return true;
      }
      return false;
    }
  };
};

const DEFAULT_AUTH_IDEMPOTENCY_STORE_BY_HANDLERS = new WeakMap();
let fallbackDefaultAuthIdempotencyStore = null;

const resolveDefaultAuthIdempotencyStore = (handlers = null) => {
  const storeOwner =
    handlers?._internals?.authService
    && typeof handlers._internals.authService === 'object'
      ? handlers._internals.authService
      : handlers;
  if (storeOwner && typeof storeOwner === 'object') {
    const existingStore = DEFAULT_AUTH_IDEMPOTENCY_STORE_BY_HANDLERS.get(storeOwner);
    if (existingStore) {
      return existingStore;
    }
    const createdStore = createInMemoryAuthIdempotencyStore();
    DEFAULT_AUTH_IDEMPOTENCY_STORE_BY_HANDLERS.set(storeOwner, createdStore);
    return createdStore;
  }
  if (!fallbackDefaultAuthIdempotencyStore) {
    fallbackDefaultAuthIdempotencyStore = createInMemoryAuthIdempotencyStore();
  }
  return fallbackDefaultAuthIdempotencyStore;
};

const cloneRouteResponse = (routeResponse = {}) => ({
  status: Number(routeResponse.status),
  headers: {
    ...(routeResponse.headers || {})
  },
  body: String(routeResponse.body ?? '')
});

const isValidRouteResponse = (routeResponse = {}) => {
  if (
    !routeResponse
    || typeof routeResponse !== 'object'
    || Array.isArray(routeResponse)
  ) {
    return false;
  }
  const status = Number(routeResponse.status);
  if (!Number.isInteger(status) || status < 100 || status > 599) {
    return false;
  }
  if (
    routeResponse.headers === null
    || typeof routeResponse.headers !== 'object'
    || Array.isArray(routeResponse.headers)
  ) {
    return false;
  }
  return typeof routeResponse.body === 'string';
};

const withPatchedResponseRequestId = (routeResponse = {}, requestId = '') => {
  const normalizedRequestId = String(requestId || '').trim();
  const clonedResponse = cloneRouteResponse(routeResponse);
  if (!normalizedRequestId || !clonedResponse.body) {
    return clonedResponse;
  }
  const contentType = String(
    clonedResponse.headers?.['content-type']
    || clonedResponse.headers?.['Content-Type']
    || ''
  ).toLowerCase();
  if (!contentType.includes('json')) {
    return clonedResponse;
  }
  try {
    const parsedBody = JSON.parse(clonedResponse.body);
    if (
      parsedBody
      && typeof parsedBody === 'object'
      && !Array.isArray(parsedBody)
      && Object.prototype.hasOwnProperty.call(parsedBody, 'request_id')
    ) {
      parsedBody.request_id = normalizedRequestId;
      clonedResponse.body = JSON.stringify(parsedBody);
    }
  } catch (_error) {
  }
  return clonedResponse;
};

const createIdempotencyConflictProblem = () =>
  new AuthProblemError({
    status: 409,
    title: 'Conflict',
    detail: '幂等键与请求载荷不一致，请更换 Idempotency-Key 后重试',
    errorCode: 'AUTH-409-IDEMPOTENCY-CONFLICT'
  });

const createInvalidIdempotencyKeyProblem = () =>
  new AuthProblemError({
    status: 400,
    title: 'Bad Request',
    detail: 'Idempotency-Key 必须为 1 到 128 个非空字符',
    errorCode: 'AUTH-400-IDEMPOTENCY-KEY-INVALID'
  });

const createIdempotencyStoreUnavailableProblem = () =>
  new AuthProblemError({
    status: 503,
    title: 'Service Unavailable',
    detail: '幂等服务暂时不可用，请稍后重试',
    errorCode: 'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE',
    extensions: {
      retryable: true,
      degradation_reason: 'idempotency-store-unavailable'
    }
  });

const createIdempotencyPendingTimeoutProblem = () =>
  new AuthProblemError({
    status: 503,
    title: 'Service Unavailable',
    detail: '幂等请求处理中，请稍后重试',
    errorCode: 'AUTH-503-IDEMPOTENCY-PENDING-TIMEOUT',
    extensions: {
      retryable: true,
      degradation_reason: 'idempotency-pending-timeout'
    }
  });

const normalizeOwnerTransferOrgIdFromBody = (payloadBody = {}) => {
  if (
    !payloadBody
    || typeof payloadBody !== 'object'
    || Array.isArray(payloadBody)
    || !Object.prototype.hasOwnProperty.call(payloadBody, 'org_id')
  ) {
    return null;
  }
  if (typeof payloadBody.org_id !== 'string') {
    return null;
  }
  const orgIdRaw = payloadBody.org_id;
  const normalizedOrgId = orgIdRaw.trim();
  if (
    !normalizedOrgId
    || normalizedOrgId !== orgIdRaw
    || normalizedOrgId.length > OWNER_TRANSFER_ORG_ID_MAX_LENGTH
    || OWNER_TRANSFER_WHITESPACE_PATTERN.test(normalizedOrgId)
    || OWNER_TRANSFER_CONTROL_CHAR_PATTERN.test(normalizedOrgId)
  ) {
    return null;
  }
  return normalizedOrgId;
};

const withOwnerTransferIdempotencyProblemContract = ({
  problem,
  body = {},
  outcome = ''
} = {}) => {
  if (!(problem instanceof AuthProblemError)) {
    return problem;
  }
  const baseExtensions =
    problem.extensions
    && typeof problem.extensions === 'object'
    && !Array.isArray(problem.extensions)
      ? problem.extensions
      : {};
  const normalizedOutcome = String(outcome || '').trim().toLowerCase();
  return new AuthProblemError({
    status: problem.status,
    title: problem.title,
    detail: problem.detail,
    errorCode: problem.errorCode,
    extensions: {
      ...baseExtensions,
      org_id: normalizeOwnerTransferOrgIdFromBody(body),
      old_owner_user_id: null,
      new_owner_user_id: null,
      result_status: normalizedOutcome === 'conflict' ? 'conflict' : 'rejected',
      retryable: baseExtensions.retryable === true
    }
  });
};

const toRouteSpecificIdempotencyProblem = ({
  routeKey,
  problem,
  body = {},
  outcome = ''
} = {}) => {
  if (routeKey === PLATFORM_ORG_OWNER_TRANSFER_ROUTE_KEY) {
    return withOwnerTransferIdempotencyProblemContract({
      problem,
      body,
      outcome
    });
  }
  return problem;
};

const isOwnerTransferPath = (routePath = '') =>
  normalizePathname(String(routePath || '')) === PLATFORM_ORG_OWNER_TRANSFER_PATH;

const withOwnerTransferParseProblemContract = ({
  problemResponse,
  routePath = ''
} = {}) => {
  if (!isOwnerTransferPath(routePath)) {
    return problemResponse;
  }
  if (
    !problemResponse
    || typeof problemResponse !== 'object'
    || typeof problemResponse.body !== 'string'
  ) {
    return problemResponse;
  }
  let parsedProblemBody;
  try {
    parsedProblemBody = JSON.parse(problemResponse.body);
  } catch (_error) {
    return problemResponse;
  }
  if (
    !parsedProblemBody
    || typeof parsedProblemBody !== 'object'
    || Array.isArray(parsedProblemBody)
  ) {
    return problemResponse;
  }

  const patchedProblemBody = {
    ...parsedProblemBody,
    org_id: Object.prototype.hasOwnProperty.call(parsedProblemBody, 'org_id')
      ? parsedProblemBody.org_id
      : null,
    old_owner_user_id: Object.prototype.hasOwnProperty.call(
      parsedProblemBody,
      'old_owner_user_id'
    )
      ? parsedProblemBody.old_owner_user_id
      : null,
    new_owner_user_id: Object.prototype.hasOwnProperty.call(
      parsedProblemBody,
      'new_owner_user_id'
    )
      ? parsedProblemBody.new_owner_user_id
      : null,
    result_status:
      parsedProblemBody.result_status === 'conflict' ? 'conflict' : 'rejected',
    retryable: parsedProblemBody.retryable === true
  };

  return {
    ...problemResponse,
    body: JSON.stringify(patchedProblemBody)
  };
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const waitForResolvedIdempotencyEntry = async ({
  idempotencyStore,
  scopeKey,
  requestHash,
  timeoutMs = DEFAULT_IDEMPOTENCY_WAIT_TIMEOUT_MS,
  pollIntervalMs = DEFAULT_IDEMPOTENCY_WAIT_POLL_INTERVAL_MS
}) => {
  const resolvedTimeoutMs = Math.max(1, Number(timeoutMs) || DEFAULT_IDEMPOTENCY_WAIT_TIMEOUT_MS);
  const resolvedPollIntervalMs = Math.max(
    1,
    Number(pollIntervalMs) || DEFAULT_IDEMPOTENCY_WAIT_POLL_INTERVAL_MS
  );
  const normalizedRequestHash = normalizeIdempotencyRequestHash(requestHash);
  const deadline = Date.now() + resolvedTimeoutMs;

  while (Date.now() <= deadline) {
    const existing = await idempotencyStore.read({ scopeKey });
    if (!existing) {
      return { state: 'missing' };
    }
    const existingRequestHash = normalizeIdempotencyRequestHash(
      existing.requestHash
    );
    if (!isValidIdempotencyRequestHash(existingRequestHash)) {
      return { state: 'corrupted' };
    }
    if (existingRequestHash !== normalizedRequestHash) {
      return { state: 'conflict' };
    }
    if (existing.state === 'resolved') {
      return { state: 'resolved', entry: existing };
    }
    if (existing.state !== 'pending') {
      return { state: 'corrupted' };
    }
    await sleep(resolvedPollIntervalMs);
  }
  return { state: 'timeout' };
};

const emitAuthIdempotencyAuditEvent = async ({
  handlers,
  requestId,
  routeKey,
  idempotencyKey,
  outcome,
  authorizationContext = null,
  metadata = {}
}) => {
  if (typeof handlers?.recordAuthIdempotencyEvent !== 'function') {
    return;
  }
  try {
    await handlers.recordAuthIdempotencyEvent({
      requestId,
      routeKey,
      idempotencyKey,
      outcome,
      authorizationContext,
      metadata
    });
  } catch (_error) {
  }
};

const summarizeErrorForLog = (error) => {
  if (error instanceof Error) {
    return `${error.name}: ${error.message}`;
  }
  return String(error || 'Unknown error');
};

const authProblemResponse = (error, requestId) => {
  const response = responseJson(
    error.status,
    buildProblemDetails({
      status: error.status,
      title: error.title,
      detail: error.detail,
      requestId,
      extensions: {
        error_code: error.errorCode,
        ...(error.extensions || {})
      }
    }),
    'application/problem+json'
  );

  if (error.status === 429) {
    const retryAfter = asPositiveInteger(error.extensions?.retry_after_seconds);
    const rateLimitLimit = asPositiveInteger(error.extensions?.rate_limit_limit);
    const rateLimitWindowSeconds = asPositiveInteger(
      error.extensions?.rate_limit_window_seconds
    );

    if (retryAfter !== null) {
      response.headers['retry-after'] = String(retryAfter);
      response.headers['x-ratelimit-reset'] = String(retryAfter);
    }
    if (rateLimitLimit !== null) {
      response.headers['x-ratelimit-limit'] = String(rateLimitLimit);
    }
    response.headers['x-ratelimit-remaining'] = '0';
    if (rateLimitLimit !== null && rateLimitWindowSeconds !== null) {
      response.headers['x-ratelimit-policy'] = `${rateLimitLimit};w=${rateLimitWindowSeconds}`;
    }
  }

  return response;
};

const runAuthRoute = async (handler, requestId) => {
  try {
    const payload = await handler();
    return responseJson(200, payload);
  } catch (error) {
    if (error instanceof AuthProblemError) {
      return authProblemResponse(error, requestId);
    }
    throw error;
  }
};

const buildMalformedPayloadProblem = (requestId) =>
  responseJson(
    400,
    buildProblemDetails({
      status: 400,
      title: 'Bad Request',
      detail: 'Malformed JSON payload',
      requestId,
      extensions: { error_code: 'AUTH-400-INVALID-PAYLOAD' }
    }),
    'application/problem+json'
  );

const buildPayloadTooLargeProblem = (requestId, maxBytes) =>
  (() => {
    const response = responseJson(
    413,
    buildProblemDetails({
      status: 413,
      title: 'Payload Too Large',
      detail: 'JSON payload exceeds allowed size',
      requestId,
      extensions: { error_code: 'AUTH-413-PAYLOAD-TOO-LARGE' }
    }),
    'application/problem+json'
    );
    response.headers.connection = 'close';
    return response;
  })();

const buildInternalServerProblem = (requestId) =>
  responseJson(
    500,
    buildProblemDetails({
      status: 500,
      title: 'Internal Server Error',
      detail: 'Unexpected server error',
      requestId,
      extensions: { error_code: 'AUTH-500-INTERNAL' }
    }),
    'application/problem+json'
  );

const shouldParseJsonBody = (req) => {
  const method = asMethod(req.method);
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return false;
  }
  const contentType = String(req.headers['content-type'] || '').toLowerCase();
  return contentType.includes('application/json');
};

const readJsonBody = async (req, maxBytes) => {
  if (!shouldParseJsonBody(req)) {
    return { body: {} };
  }

  const requestId = requestIdFrom(req);
  const contentLength = Number(req.headers['content-length']);
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    return { error: buildPayloadTooLargeProblem(requestId, maxBytes) };
  }

  const chunks = [];
  let bytesRead = 0;
  for await (const chunk of req) {
    const bufferChunk = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytesRead += bufferChunk.length;

    if (bytesRead > maxBytes) {
      return { error: buildPayloadTooLargeProblem(requestId, maxBytes) };
    }

    chunks.push(bufferChunk);
  }

  const raw = chunks.length > 0 ? Buffer.concat(chunks).toString('utf8') : '';
  if (raw.length === 0) {
    return { body: {} };
  }

  try {
    return { body: JSON.parse(raw) };
  } catch (_error) {
    return { error: buildMalformedPayloadProblem(requestId) };
  }
};

const createRouteTable = ({
  handlers,
  requestId,
  headers,
  body,
  getAuthorizationContext = () => null,
  getRouteParams = () => ({}),
  getRouteQuery = () => ({})
}) => {
  const idempotencyStore =
    handlers?.authIdempotencyStore
    && typeof handlers.authIdempotencyStore.claimOrRead === 'function'
    && typeof handlers.authIdempotencyStore.read === 'function'
    && typeof handlers.authIdempotencyStore.resolve === 'function'
    && typeof handlers.authIdempotencyStore.releasePending === 'function'
      ? handlers.authIdempotencyStore
      : resolveDefaultAuthIdempotencyStore(handlers);

  const executeIdempotentAuthRoute = async ({
    routeKey,
    execute
  }) => {
    if (!IDEMPOTENCY_PROTECTED_ROUTE_KEYS.has(routeKey)) {
      return execute();
    }
    const normalizedIdempotencyKey = normalizeIdempotencyKey(headers);
    if (normalizedIdempotencyKey.invalid) {
      return authProblemResponse(
        toRouteSpecificIdempotencyProblem({
          routeKey,
          problem: createInvalidIdempotencyKeyProblem(),
          body,
          outcome: 'invalid_key'
        }),
        requestId
      );
    }
    if (!normalizedIdempotencyKey.present) {
      return execute();
    }
    const idempotencyKey = normalizedIdempotencyKey.value;
    if (
      !idempotencyKey
      || idempotencyKey.length > MAX_IDEMPOTENCY_KEY_LENGTH
    ) {
      return authProblemResponse(
        toRouteSpecificIdempotencyProblem({
          routeKey,
          problem: createInvalidIdempotencyKeyProblem(),
          body,
          outcome: 'invalid_key'
        }),
        requestId
      );
    }

    const authorizationContext = getAuthorizationContext() || null;
    const actorScope = resolveIdempotencyActorScope({
      routeKey,
      authorizationContext,
      authorization: headers.authorization
    });
    const routeParams = getRouteParams() || {};
    const idempotencyRouteParams = normalizeRouteParamsForIdempotency({
      routeKey,
      routeParams
    });
    const routeVariant = toIdempotencyRouteVariant(idempotencyRouteParams);
    const shouldIgnoreRequestBodyInHash =
      IDEMPOTENCY_REQUEST_HASH_IGNORES_BODY_ROUTE_KEYS.has(routeKey);
    const requestHash = normalizeIdempotencyRequestHash(
      toIdempotencyRequestHash(
        shouldIgnoreRequestBodyInHash
          ? {
            route_params: idempotencyRouteParams
          }
          : {
            body: body || {},
            route_params: idempotencyRouteParams
          }
      )
    );
    const scopeKey = toIdempotencyScopeKey({
      routeKey,
      idempotencyKey,
      actorScope,
      routeVariant
    });
    const scopeWindowKey = toIdempotencyScopeWindowKey({
      routeKey,
      actorScope,
      routeVariant
    });
    const respondWithAuditedIdempotencyProblem = async ({
      problem,
      outcome,
      metadata = {}
    }) => {
      await emitAuthIdempotencyAuditEvent({
        handlers,
        requestId,
        routeKey,
        idempotencyKey,
        outcome,
        authorizationContext,
        metadata
      });
      return authProblemResponse(
        toRouteSpecificIdempotencyProblem({
          routeKey,
          problem,
          body,
          outcome
        }),
        requestId
      );
    };
    const maxAcquireAttempts = 2;

    for (let attempt = 0; attempt < maxAcquireAttempts; attempt += 1) {
      const pendingToken = randomUUID();
      let claimResult;
      try {
        claimResult = await idempotencyStore.claimOrRead({
          scopeKey,
          scopeWindowKey,
          requestHash,
          pendingToken
        });
      } catch (_error) {
        return respondWithAuditedIdempotencyProblem({
          problem: createIdempotencyStoreUnavailableProblem(),
          outcome: 'store_unavailable',
          metadata: {
            degradation_reason: 'idempotency-store-unavailable'
          }
        });
      }

      if (claimResult?.action === 'claimed') {
        try {
          const executedResponse = await execute();
          const responseSnapshot = cloneRouteResponse(executedResponse);
          const resolvedStatus = Number(responseSnapshot.status);
          if (
            shouldPersistIdempotencyResponse({
              routeKey,
              statusCode: resolvedStatus,
              response: responseSnapshot
            })
          ) {
            try {
              const resolveResult = await idempotencyStore.resolve({
                scopeKey,
                scopeWindowKey,
                pendingToken,
                requestHash,
                response: responseSnapshot
              });
              if (resolveResult === false) {
                try {
                  await idempotencyStore.releasePending({
                    scopeKey,
                    scopeWindowKey,
                    pendingToken,
                    requestHash
                  });
                } catch (_error) {
                }
                await emitAuthIdempotencyAuditEvent({
                  handlers,
                  requestId,
                  routeKey,
                  idempotencyKey,
                  outcome: 'store_unavailable',
                  authorizationContext,
                  metadata: {
                    degradation_reason: 'idempotency-store-unavailable',
                    idempotency_stage: 'resolve'
                  }
                });
              }
            } catch (_error) {
              try {
                await idempotencyStore.releasePending({
                  scopeKey,
                  scopeWindowKey,
                  pendingToken,
                  requestHash
                });
              } catch (_nestedError) {
              }
              await emitAuthIdempotencyAuditEvent({
                handlers,
                requestId,
                routeKey,
                idempotencyKey,
                outcome: 'store_unavailable',
                authorizationContext,
                metadata: {
                  degradation_reason: 'idempotency-store-unavailable',
                  idempotency_stage: 'resolve'
                }
              });
            }
          } else {
            try {
              const releaseResult = await idempotencyStore.releasePending({
                scopeKey,
                scopeWindowKey,
                pendingToken,
                requestHash
              });
              if (releaseResult === false) {
                await emitAuthIdempotencyAuditEvent({
                  handlers,
                  requestId,
                  routeKey,
                  idempotencyKey,
                  outcome: 'store_unavailable',
                  authorizationContext,
                  metadata: {
                    degradation_reason: 'idempotency-store-unavailable',
                    idempotency_stage: 'release-pending'
                  }
                });
              }
            } catch (_error) {
              await emitAuthIdempotencyAuditEvent({
                handlers,
                requestId,
                routeKey,
                idempotencyKey,
                outcome: 'store_unavailable',
                authorizationContext,
                metadata: {
                  degradation_reason: 'idempotency-store-unavailable',
                  idempotency_stage: 'release-pending'
                }
              });
            }
          }
          return cloneRouteResponse(responseSnapshot);
        } catch (error) {
          try {
            await idempotencyStore.releasePending({
              scopeKey,
              scopeWindowKey,
              pendingToken,
              requestHash
            });
          } catch (_error) {
          }
          throw error;
        }
      }

      if (claimResult?.action === 'retry') {
        continue;
      }

      const existingEntry = claimResult?.entry;
      if (!existingEntry) {
        return respondWithAuditedIdempotencyProblem({
          problem: createIdempotencyStoreUnavailableProblem(),
          outcome: 'store_unavailable',
          metadata: {
            degradation_reason: 'idempotency-store-corrupted-entry',
            idempotency_stage: 'claim-or-read'
          }
        });
      }

      const existingRequestHash = normalizeIdempotencyRequestHash(
        existingEntry.requestHash
      );
      if (!isValidIdempotencyRequestHash(existingRequestHash)) {
        return respondWithAuditedIdempotencyProblem({
          problem: createIdempotencyStoreUnavailableProblem(),
          outcome: 'store_unavailable',
          metadata: {
            degradation_reason: 'idempotency-store-corrupted-entry',
            idempotency_stage: 'claim-or-read'
          }
        });
      }
      if (existingRequestHash !== requestHash) {
        await emitAuthIdempotencyAuditEvent({
          handlers,
          requestId,
          routeKey,
          idempotencyKey,
          outcome: 'conflict',
          authorizationContext
        });
        return authProblemResponse(
          toRouteSpecificIdempotencyProblem({
            routeKey,
            problem: createIdempotencyConflictProblem(),
            body,
            outcome: 'conflict'
          }),
          requestId
        );
      }

      if (existingEntry.state === 'resolved') {
        const replayResponse = withPatchedResponseRequestId(
          existingEntry.response,
          requestId
        );
        if (!isValidRouteResponse(replayResponse)) {
          return respondWithAuditedIdempotencyProblem({
            problem: createIdempotencyStoreUnavailableProblem(),
            outcome: 'store_unavailable',
            metadata: {
              degradation_reason: 'idempotency-store-corrupted-response',
              idempotency_stage: 'replay'
            }
          });
        }
        await emitAuthIdempotencyAuditEvent({
          handlers,
          requestId,
          routeKey,
          idempotencyKey,
          outcome: 'hit',
          authorizationContext
        });
        return replayResponse;
      }

      if (existingEntry.state !== 'pending') {
        return respondWithAuditedIdempotencyProblem({
          problem: createIdempotencyStoreUnavailableProblem(),
          outcome: 'store_unavailable',
          metadata: {
            degradation_reason: 'idempotency-store-corrupted-entry',
            idempotency_stage: 'claim-or-read'
          }
        });
      }

      let waitResult;
      try {
        waitResult = await waitForResolvedIdempotencyEntry({
          idempotencyStore,
          scopeKey,
          requestHash
        });
      } catch (_error) {
        return respondWithAuditedIdempotencyProblem({
          problem: createIdempotencyStoreUnavailableProblem(),
          outcome: 'store_unavailable',
          metadata: {
            degradation_reason: 'idempotency-store-unavailable'
          }
        });
      }

      if (waitResult.state === 'conflict') {
        await emitAuthIdempotencyAuditEvent({
          handlers,
          requestId,
          routeKey,
          idempotencyKey,
          outcome: 'conflict',
          authorizationContext
        });
        return authProblemResponse(
          toRouteSpecificIdempotencyProblem({
            routeKey,
            problem: createIdempotencyConflictProblem(),
            body,
            outcome: 'conflict'
          }),
          requestId
        );
      }
      if (waitResult.state === 'resolved') {
        const replayResponse = withPatchedResponseRequestId(
          waitResult.entry.response,
          requestId
        );
        if (!isValidRouteResponse(replayResponse)) {
          return respondWithAuditedIdempotencyProblem({
            problem: createIdempotencyStoreUnavailableProblem(),
            outcome: 'store_unavailable',
            metadata: {
              degradation_reason: 'idempotency-store-corrupted-response',
              idempotency_stage: 'replay-after-wait'
            }
          });
        }
        await emitAuthIdempotencyAuditEvent({
          handlers,
          requestId,
          routeKey,
          idempotencyKey,
          outcome: 'hit',
          authorizationContext
        });
        return replayResponse;
      }
      if (waitResult.state === 'corrupted') {
        return respondWithAuditedIdempotencyProblem({
          problem: createIdempotencyStoreUnavailableProblem(),
          outcome: 'store_unavailable',
          metadata: {
            degradation_reason: 'idempotency-store-corrupted-entry',
            idempotency_stage: 'wait-for-resolved'
          }
        });
      }
      if (waitResult.state === 'missing') {
        return respondWithAuditedIdempotencyProblem({
          problem: createIdempotencyStoreUnavailableProblem(),
          outcome: 'store_unavailable',
          metadata: {
            degradation_reason: 'idempotency-store-entry-missing',
            idempotency_stage: 'wait-for-resolved'
          }
        });
      }
      if (waitResult.state === 'timeout') {
        return respondWithAuditedIdempotencyProblem({
          problem: createIdempotencyPendingTimeoutProblem(),
          outcome: 'pending_timeout',
          metadata: {
            degradation_reason: 'idempotency-pending-timeout'
          }
        });
      }
    }

    return respondWithAuditedIdempotencyProblem({
      problem: createIdempotencyPendingTimeoutProblem(),
      outcome: 'pending_timeout',
      metadata: {
        degradation_reason: 'idempotency-pending-timeout'
      }
    });
  };

  return {
    'GET /health': async () => {
      const payload = await handlers.health(requestId);
      return responseJson(payload.ok ? 200 : 503, payload);
    },
    'GET /openapi.json': async () => responseJson(200, handlers.openapi(requestId)),
    'GET /auth/ping': async () => responseJson(200, handlers.authPing(requestId)),
    'POST /auth/login': async () =>
      runAuthRoute(() => handlers.authLogin(requestId, body || {}), requestId),
    'POST /auth/otp/send': async () =>
      runAuthRoute(() => handlers.authOtpSend(requestId, body || {}), requestId),
    'POST /auth/otp/login': async () =>
      runAuthRoute(() => handlers.authOtpLogin(requestId, body || {}), requestId),
    'GET /auth/tenant/options': async () =>
      runAuthRoute(
        () =>
          handlers.authTenantOptions(
            requestId,
            headers.authorization,
            getAuthorizationContext()
          ),
        requestId
      ),
    'POST /auth/tenant/select': async () =>
      runAuthRoute(
        () =>
          handlers.authTenantSelect(
            requestId,
            headers.authorization,
            body || {},
            getAuthorizationContext()
          ),
        requestId
      ),
    'POST /auth/tenant/switch': async () =>
      runAuthRoute(
        () =>
          handlers.authTenantSwitch(
            requestId,
            headers.authorization,
            body || {},
            getAuthorizationContext()
          ),
        requestId
      ),
    'GET /auth/tenant/member-admin/probe': async () =>
      runAuthRoute(
        () => handlers.authTenantMemberAdminProbe(requestId, headers.authorization),
        requestId
      ),
    'POST /auth/tenant/member-admin/provision-user': async () =>
      executeIdempotentAuthRoute({
        routeKey: 'POST /auth/tenant/member-admin/provision-user',
        execute: () =>
          runAuthRoute(
            () =>
              handlers.authTenantMemberAdminProvisionUser(
                requestId,
                headers.authorization,
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [TENANT_MEMBER_LIST_ROUTE_KEY]: async () =>
      runAuthRoute(
        () =>
          handlers.tenantListMembers(
            requestId,
            headers.authorization,
            getRouteQuery(),
            getAuthorizationContext()
          ),
        requestId
      ),
    [TENANT_MEMBER_CREATE_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: TENANT_MEMBER_CREATE_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.tenantCreateMember(
                requestId,
                headers.authorization,
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [TENANT_MEMBER_DETAIL_ROUTE_KEY]: async () =>
      runAuthRoute(
        () =>
          handlers.tenantGetMemberDetail(
            requestId,
            headers.authorization,
            getRouteParams(),
            getAuthorizationContext()
          ),
        requestId
      ),
    [TENANT_MEMBER_STATUS_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: TENANT_MEMBER_STATUS_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.tenantUpdateMemberStatus(
                requestId,
                headers.authorization,
                getRouteParams(),
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [TENANT_MEMBER_PROFILE_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: TENANT_MEMBER_PROFILE_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.tenantUpdateMemberProfile(
                requestId,
                headers.authorization,
                getRouteParams(),
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [TENANT_MEMBER_ROLE_BINDING_GET_ROUTE_KEY]: async () =>
      runAuthRoute(
        () =>
          handlers.tenantGetMemberRoles(
            requestId,
            headers.authorization,
            getRouteParams(),
            getAuthorizationContext()
          ),
        requestId
      ),
    [TENANT_MEMBER_ROLE_BINDING_PUT_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: TENANT_MEMBER_ROLE_BINDING_PUT_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.tenantReplaceMemberRoles(
                requestId,
                headers.authorization,
                getRouteParams(),
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [TENANT_ROLE_LIST_ROUTE_KEY]: async () =>
      runAuthRoute(
        () =>
          handlers.tenantListRoles(
            requestId,
            headers.authorization,
            getAuthorizationContext()
          ),
        requestId
      ),
    [TENANT_ROLE_CREATE_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: TENANT_ROLE_CREATE_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.tenantCreateRole(
                requestId,
                headers.authorization,
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [TENANT_ROLE_UPDATE_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: TENANT_ROLE_UPDATE_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.tenantUpdateRole(
                requestId,
                headers.authorization,
                getRouteParams(),
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [TENANT_ROLE_DELETE_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: TENANT_ROLE_DELETE_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.tenantDeleteRole(
                requestId,
                headers.authorization,
                getRouteParams(),
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [TENANT_ROLE_PERMISSION_GET_ROUTE_KEY]: async () =>
      runAuthRoute(
        () =>
          handlers.tenantGetRolePermissions(
            requestId,
            headers.authorization,
            getRouteParams(),
            getAuthorizationContext()
          ),
        requestId
      ),
    [TENANT_ROLE_PERMISSION_PUT_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: TENANT_ROLE_PERMISSION_PUT_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.tenantReplaceRolePermissions(
                requestId,
                headers.authorization,
                getRouteParams(),
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    'GET /auth/platform/member-admin/probe': async () =>
      runAuthRoute(
        () => handlers.authPlatformMemberAdminProbe(requestId, headers.authorization),
        requestId
      ),
    'POST /auth/platform/member-admin/provision-user': async () =>
      executeIdempotentAuthRoute({
        routeKey: 'POST /auth/platform/member-admin/provision-user',
        execute: () =>
          runAuthRoute(
            () =>
              handlers.authPlatformMemberAdminProvisionUser(
                requestId,
                headers.authorization,
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [PLATFORM_ORG_CREATE_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: PLATFORM_ORG_CREATE_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.platformCreateOrg(
                requestId,
                headers.authorization,
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [PLATFORM_ORG_STATUS_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: PLATFORM_ORG_STATUS_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.platformUpdateOrgStatus(
                requestId,
                headers.authorization,
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [PLATFORM_ORG_OWNER_TRANSFER_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: PLATFORM_ORG_OWNER_TRANSFER_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.platformOwnerTransfer(
                requestId,
                headers.authorization,
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [PLATFORM_ROLE_LIST_ROUTE_KEY]: async () =>
      runAuthRoute(
        () =>
          handlers.platformListRoles(
            requestId,
            headers.authorization,
            getAuthorizationContext()
          ),
        requestId
      ),
    [PLATFORM_ROLE_CREATE_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: PLATFORM_ROLE_CREATE_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.platformCreateRole(
                requestId,
                headers.authorization,
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [PLATFORM_ROLE_UPDATE_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: PLATFORM_ROLE_UPDATE_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.platformUpdateRole(
                requestId,
                headers.authorization,
                getRouteParams(),
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [PLATFORM_ROLE_DELETE_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: PLATFORM_ROLE_DELETE_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.platformDeleteRole(
                requestId,
                headers.authorization,
                getRouteParams(),
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [PLATFORM_ROLE_PERMISSION_GET_ROUTE_KEY]: async () =>
      runAuthRoute(
        () =>
          handlers.platformGetRolePermissions(
            requestId,
            headers.authorization,
            getRouteParams(),
            getAuthorizationContext()
          ),
        requestId
      ),
    [PLATFORM_ROLE_PERMISSION_PUT_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: PLATFORM_ROLE_PERMISSION_PUT_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.platformReplaceRolePermissions(
                requestId,
                headers.authorization,
                getRouteParams(),
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [PLATFORM_USER_CREATE_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: PLATFORM_USER_CREATE_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.platformCreateUser(
                requestId,
                headers.authorization,
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    [PLATFORM_USER_STATUS_ROUTE_KEY]: async () =>
      executeIdempotentAuthRoute({
        routeKey: PLATFORM_USER_STATUS_ROUTE_KEY,
        execute: () =>
          runAuthRoute(
            () =>
              handlers.platformUpdateUserStatus(
                requestId,
                headers.authorization,
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    'POST /auth/refresh': async () =>
      runAuthRoute(() => handlers.authRefresh(requestId, body || {}), requestId),
    'POST /auth/logout': async () =>
      runAuthRoute(
        () =>
          handlers.authLogout(
            requestId,
            headers.authorization,
            getAuthorizationContext()
          ),
        requestId
      ),
    'POST /auth/change-password': async () =>
      runAuthRoute(
        () =>
          handlers.authChangePassword(
            requestId,
            headers.authorization,
            body || {},
            getAuthorizationContext()
          ),
        requestId
      ),
    'POST /auth/platform/role-facts/replace': async () =>
      executeIdempotentAuthRoute({
        routeKey: 'POST /auth/platform/role-facts/replace',
        execute: () =>
          runAuthRoute(
            () =>
              handlers.authReplacePlatformRoleFacts(
                requestId,
                headers.authorization,
                body || {},
                getAuthorizationContext()
              ),
            requestId
          )
      }),
    'GET /smoke': async () => {
      const payload = await handlers.smoke(requestId);
      return responseJson(payload.ok ? 200 : 503, payload);
    }
  };
};

const authorizeProtectedRoute = async ({
  routeDefinition,
  handlers,
  requestId,
  headers
}) => {
  if (!routeDefinition || routeDefinition.access !== 'protected') {
    return {
      authorizationContext: null
    };
  }

  if (typeof handlers?.authorizeRoute !== 'function') {
    return {
      authorizationFailure: responseJson(
        500,
        buildProblemDetails({
          status: 500,
          title: 'Internal Server Error',
          detail: 'Authorization handler not available for protected route',
          requestId,
          extensions: { error_code: 'AUTH-500-AUTHORIZE-HANDLER-MISSING' }
        }),
        'application/problem+json'
      )
    };
  }

  const normalizedAuthorization = normalizeAuthorizationHeader(headers);
  if (normalizedAuthorization.invalid) {
    return {
      authorizationFailure: authProblemResponse(
        new AuthProblemError({
          status: 401,
          title: 'Unauthorized',
          detail: '当前会话无效，请重新登录',
          errorCode: 'AUTH-401-INVALID-ACCESS'
        }),
        requestId
      )
    };
  }

  try {
    const authorizationContext = await handlers.authorizeRoute({
      requestId,
      authorization: normalizedAuthorization.value,
      permissionCode: routeDefinition.permission_code,
      scope: routeDefinition.scope
    });
    return {
      authorizationContext: markRoutePreauthorizedContext({
        authorizationContext,
        permissionCode: routeDefinition?.permission_code,
        scope: routeDefinition?.scope
      })
    };
  } catch (error) {
    if (error instanceof AuthProblemError) {
      return {
        authorizationFailure: authProblemResponse(error, requestId)
      };
    }
    throw error;
  }
};

const listExecutableRouteKeys = () =>
  Object.keys(
    createRouteTable({
      handlers: {},
      requestId: 'route-discovery',
      headers: {},
      body: {}
    })
  );

const listProtectedRouteKeys = (routeDefinitions = []) =>
  routeDefinitions
    .filter((routeDefinition) => routeDefinition?.access === 'protected')
    .map((routeDefinition) => {
      const method = asMethod(routeDefinition.method);
      const path = normalizePathname(String(routeDefinition.path || '/'));
      return `${method} ${path}`;
    });

const ensureAuthorizeRouteCapabilityOrThrow = ({
  routeDefinitions = ROUTE_DEFINITIONS,
  handlers
} = {}) => {
  const protectedRouteKeys = listProtectedRouteKeys(routeDefinitions);
  if (protectedRouteKeys.length === 0) {
    return;
  }
  if (typeof handlers?.authorizeRoute === 'function') {
    return;
  }
  throw new Error(
    `Route authorization preflight failed: missing authorizeRoute handler for protected routes: ${protectedRouteKeys.join(', ')}`
  );
};

const ensureAuthorizeRouteCapabilityWithCache = ({
  routeDefinitions = ROUTE_DEFINITIONS,
  handlers
} = {}) => {
  const routeDefinitionSnapshot = toRouteDefinitionsSnapshot(routeDefinitions);
  const handlersAreObject = handlers && typeof handlers === 'object';
  let validatedHandlers = AUTHORIZE_ROUTE_PREFLIGHT_CACHE.get(routeDefinitionSnapshot);

  if (
    handlersAreObject
    && validatedHandlers
    && validatedHandlers.has(handlers)
    && typeof handlers.authorizeRoute === 'function'
  ) {
    return;
  }

  ensureAuthorizeRouteCapabilityOrThrow({
    routeDefinitions: routeDefinitionSnapshot,
    handlers
  });

  if (!handlersAreObject) {
    return;
  }
  if (!validatedHandlers) {
    validatedHandlers = new WeakSet();
    AUTHORIZE_ROUTE_PREFLIGHT_CACHE.set(routeDefinitionSnapshot, validatedHandlers);
  }
  validatedHandlers.add(handlers);
};

const createRouteDeclarationLookup = (routeDefinitionSnapshot) =>
  (() => {
    const routeDefinitionMap = createRouteDefinitionMap(routeDefinitionSnapshot);
    const declaredRoutePaths = listDeclaredRoutePaths(routeDefinitionSnapshot);
    const declaredParameterizedRouteDefinitions = routeDefinitionSnapshot.filter(
      (routeDefinition) => String(routeDefinition?.path || '').includes(':')
    );
    const declaredMethodsByPath = new Map();
    for (const routeDefinition of routeDefinitionSnapshot) {
      const declaredPath = normalizePathname(routeDefinition.path);
      const declaredMethod = asMethod(routeDefinition.method);
      let pathMethods = declaredMethodsByPath.get(declaredPath);
      if (!pathMethods) {
        pathMethods = new Set();
        declaredMethodsByPath.set(declaredPath, pathMethods);
      }
      pathMethods.add(declaredMethod);
      if (declaredMethod === 'GET') {
        pathMethods.add('HEAD');
      }
    }
    return Object.freeze({
      [ROUTE_DECLARATION_LOOKUP_TOKEN]: true,
      routeDefinitions: routeDefinitionSnapshot,
      findRouteDefinition: ({ method, path }) =>
        findRouteDefinitionInMap(routeDefinitionMap, { method, path }),
      hasDeclaredRoutePath: (path) => {
        const normalizedPath = normalizePathname(path);
        if (declaredRoutePaths.has(normalizedPath)) {
          return true;
        }
        return declaredParameterizedRouteDefinitions.some((routeDefinition) =>
          isRoutePathMatch(routeDefinition.path, normalizedPath)
        );
      },
      listDeclaredMethodsForPath: (path) => {
        const normalizedPath = normalizePathname(path);
        const declaredMethods = new Set(
          declaredMethodsByPath.get(normalizedPath) || []
        );
        for (const routeDefinition of declaredParameterizedRouteDefinitions) {
          if (!isRoutePathMatch(routeDefinition.path, normalizedPath)) {
            continue;
          }
          const declaredMethod = asMethod(routeDefinition.method);
          declaredMethods.add(declaredMethod);
          if (declaredMethod === 'GET') {
            declaredMethods.add('HEAD');
          }
        }
        return [...declaredMethods];
      }
    });
  })();

const isRouteDeclarationLookupForSnapshot = (
  routeDeclarationLookup,
  routeDefinitionSnapshot
) =>
  Boolean(
    routeDeclarationLookup
    && routeDeclarationLookup[ROUTE_DECLARATION_LOOKUP_TOKEN] === true
    && routeDeclarationLookup.routeDefinitions === routeDefinitionSnapshot
    && typeof routeDeclarationLookup.findRouteDefinition === 'function'
    && typeof routeDeclarationLookup.hasDeclaredRoutePath === 'function'
    && typeof routeDeclarationLookup.listDeclaredMethodsForPath === 'function'
  );

const resolveRouteDeclarationLookup = ({
  routeDefinitions = ROUTE_DEFINITIONS,
  routeDeclarationLookup = null
} = {}) => {
  const routeDefinitionSnapshot = toRouteDefinitionsSnapshot(routeDefinitions);
  if (
    isRouteDeclarationLookupForSnapshot(routeDeclarationLookup, routeDefinitionSnapshot)
  ) {
    ROUTE_DECLARATION_LOOKUP_CACHE.set(routeDefinitionSnapshot, routeDeclarationLookup);
    return routeDeclarationLookup;
  }
  const cachedRouteDeclarationLookup =
    ROUTE_DECLARATION_LOOKUP_CACHE.get(routeDefinitionSnapshot);
  if (cachedRouteDeclarationLookup) {
    return cachedRouteDeclarationLookup;
  }
  const nextRouteDeclarationLookup = createRouteDeclarationLookup(routeDefinitionSnapshot);
  ROUTE_DECLARATION_LOOKUP_CACHE.set(
    routeDefinitionSnapshot,
    nextRouteDeclarationLookup
  );
  return nextRouteDeclarationLookup;
};

const dispatchApiRoute = async ({
  pathname,
  method = 'GET',
  headers = {},
  body = {},
  requestId,
  handlers,
  routeDefinitions = ROUTE_DEFINITIONS,
  routeDeclarationLookup = null,
  corsPolicy = DEFAULT_CORS_POLICY
}) => {
  const routeDefinitionSnapshot = toRouteDefinitionsSnapshot(routeDefinitions);
  const resolvedRouteDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions: routeDefinitionSnapshot,
    routeDeclarationLookup
  });
  const resolvedRequestId = resolveRequestId({
    requestId,
    headers
  });
  const corsOptions = {
    corsPolicy,
    requestOrigin: headers.origin
  };
  const parsedRoutePath = parseRequestPath(pathname);
  const routePath = parsedRoutePath.pathname;
  const rawRoutePath = String(parsedRoutePath.rawPathname || routePath);
  const normalizedMethod = asMethod(method);
  const routeDispatchMethod = normalizedMethod === 'HEAD' ? 'GET' : normalizedMethod;
  const finalizeResponse = (routeResponse) => {
    if (normalizedMethod !== 'HEAD') {
      return routeResponse;
    }
    return {
      ...routeResponse,
      body: ''
    };
  };
  if (hasNonCanonicalRoutePathSlashes(rawRoutePath)) {
    return finalizeResponse(responseJson(
      404,
      buildProblemDetails({
        status: 404,
        title: 'Not Found',
        detail: `No route for ${rawRoutePath}`,
        requestId: resolvedRequestId,
        extensions: { error_code: 'AUTH-404-NOT-FOUND' }
      }),
      'application/problem+json',
      corsOptions
    ));
  }
  const routeKey = `${routeDispatchMethod} ${routePath}`;
  const routeDefinition = resolvedRouteDeclarationLookup.findRouteDefinition({
    method: routeDispatchMethod,
    path: routePath
  });
  const routeDefinitionRouteKey = routeDefinition
    ? `${routeDispatchMethod} ${normalizePathname(routeDefinition.path)}`
    : routeKey;
  const extractedRouteParams = routeDefinition
    ? (extractRoutePathParams(routeDefinition.path, routePath) || {})
    : {};
  const routeParams = normalizeRouteParamsForRoute({
    routeKey: routeDefinitionRouteKey,
    routeParams: extractedRouteParams
  });
  const routeQuery = parseRequestQuery(parsedRoutePath.search);
  let authorizationContext = null;

  if (
    normalizedMethod === 'OPTIONS'
    && resolvedRouteDeclarationLookup.hasDeclaredRoutePath(routePath)
  ) {
    return finalizeResponse(
      responseNoContent(
        204,
        preflightCorsHeaders(
          resolvedRouteDeclarationLookup.listDeclaredMethodsForPath(routePath),
          corsOptions
        ),
        corsOptions
      )
    );
  }

  const routeTable = createRouteTable({
    handlers,
    requestId: resolvedRequestId,
    headers,
    body,
    getAuthorizationContext: () => authorizationContext,
    getRouteParams: () => routeParams,
    getRouteQuery: () => routeQuery
  });
  const routeHandler = routeTable[routeKey] || routeTable[routeDefinitionRouteKey];
  if (routeHandler) {
    if (!routeDefinition) {
      return finalizeResponse(responseJson(
        500,
        buildProblemDetails({
          status: 500,
          title: 'Internal Server Error',
          detail: `Route declaration missing for ${routeKey}`,
          requestId: resolvedRequestId,
          extensions: { error_code: 'AUTH-500-ROUTE-DECLARATION-MISSING' }
        }),
        'application/problem+json',
        corsOptions
      ));
    }
    const {
      authorizationFailure,
      authorizationContext: resolvedAuthorizationContext
    } = await authorizeProtectedRoute({
      routeDefinition,
      handlers,
      requestId: resolvedRequestId,
      headers
    });
    if (authorizationFailure) {
      const routeSpecificAuthorizationFailure = withOwnerTransferParseProblemContract({
        problemResponse: authorizationFailure,
        routePath
      });
      return finalizeResponse(routeSpecificAuthorizationFailure);
    }
    authorizationContext = resolvedAuthorizationContext;
    const routeResponse = await routeHandler();
    return finalizeResponse(routeResponse);
  }

  if (resolvedRouteDeclarationLookup.hasDeclaredRoutePath(routePath)) {
    const allowMethods = toCorsAllowMethods(
      resolvedRouteDeclarationLookup.listDeclaredMethodsForPath(routePath)
    );
    const methodNotAllowedResponse = responseJson(
      405,
      buildProblemDetails({
        status: 405,
        title: 'Method Not Allowed',
        detail: `Method ${normalizedMethod} not allowed for ${routePath}`,
        requestId: resolvedRequestId,
        extensions: { error_code: 'AUTH-405-METHOD-NOT-ALLOWED' }
      }),
      'application/problem+json',
      corsOptions
    );
    methodNotAllowedResponse.headers.allow = allowMethods;
    return finalizeResponse(methodNotAllowedResponse);
  }

  return finalizeResponse(responseJson(
    404,
    buildProblemDetails({
      status: 404,
      title: 'Not Found',
      detail: `No route for ${routePath}`,
      requestId: resolvedRequestId,
      extensions: { error_code: 'AUTH-404-NOT-FOUND' }
    }),
    'application/problem+json',
    corsOptions
  ));
};

const handleApiRoute = async (
  { pathname, method = 'GET', headers = {}, body = {} },
  config = readConfig(),
  options = {}
) => {
  const dependencyProbe = options.dependencyProbe || checkDependencies;
  const authService = options.authService;
  const routeDefinitions = toRouteDefinitionsSnapshot(
    Array.isArray(options.routeDefinitions)
      ? options.routeDefinitions
      : ROUTE_DEFINITIONS
  );
  const routeDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions,
    routeDeclarationLookup: options.routeDeclarationLookup || null
  });
  if (options.validateRouteDefinitions !== false) {
    ensureRoutePermissionDeclarationsOrThrow(routeDefinitions, {
      executableRouteKeys: options.executableRouteKeys || listExecutableRouteKeys(),
      supportedPermissionCodes: options.supportedPermissionCodes || listSupportedRoutePermissionCodes(),
      supportedPermissionScopes:
        options.supportedPermissionScopes || listSupportedRoutePermissionScopes()
    });
  }
  const requestId = resolveRequestId({ headers });
  const handlers = options.handlers || createRouteHandlers(config, {
    dependencyProbe,
    authService,
    authIdempotencyStore: options.authIdempotencyStore || null
  });
  ensureAuthorizeRouteCapabilityWithCache({
    routeDefinitions,
    handlers
  });

  return dispatchApiRoute({
    pathname,
    method,
    headers,
    body,
    requestId,
    handlers,
    routeDefinitions,
    routeDeclarationLookup,
    corsPolicy: options.corsPolicy || createCorsPolicy(config)
  });
};

const createServer = (config, options = {}) => {
  const dependencyProbe = options.dependencyProbe || checkDependencies;
  const authService = options.authService;
  const routeDefinitions = toRouteDefinitionsSnapshot(
    Array.isArray(options.routeDefinitions)
      ? options.routeDefinitions
      : ROUTE_DEFINITIONS
  );
  const executableRouteKeys = listExecutableRouteKeys();
  const supportedPermissionCodes =
    options.supportedPermissionCodes || listSupportedRoutePermissionCodes();
  const supportedPermissionScopes =
    options.supportedPermissionScopes || listSupportedRoutePermissionScopes();
  const routeDeclarationLookup = resolveRouteDeclarationLookup({ routeDefinitions });
  ensureRoutePermissionDeclarationsOrThrow(routeDefinitions, {
    executableRouteKeys,
    supportedPermissionCodes,
    supportedPermissionScopes
  });
  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService,
    authIdempotencyStore: options.authIdempotencyStore || null
  });
  ensureAuthorizeRouteCapabilityOrThrow({
    routeDefinitions,
    handlers
  });
  const jsonBodyLimitBytes = resolveJsonBodyLimitBytes(
    config.API_JSON_BODY_LIMIT_BYTES
  );
  const corsPolicy = createCorsPolicy(config);

  return http.createServer(async (req, res) => {
    const requestId = requestIdFrom(req);
    req.headers['x-request-id'] = requestId;

    const bodyResult = await readJsonBody(req, jsonBodyLimitBytes);
    if (bodyResult.error) {
      const parsedBodyRoutePath = parseRequestPath(req.url || '/');
      const routeSpecificBodyError = withOwnerTransferParseProblemContract({
        problemResponse: bodyResult.error,
        routePath: parsedBodyRoutePath.pathname
      });

      res.statusCode = routeSpecificBodyError.status;
      const responseHeaders = applyCorsPolicyToHeaders(
        routeSpecificBodyError.headers,
        corsPolicy,
        req.headers.origin
      );
      for (const [header, value] of Object.entries(responseHeaders)) {
        res.setHeader(header, value);
      }
      if (String(responseHeaders.connection || '').toLowerCase() === 'close') {
        res.once('finish', () => {
          if (typeof req.destroy === 'function' && !req.destroyed) {
            req.destroy();
          }
        });
      }
      res.end(routeSpecificBodyError.body);
      return;
    }
    const body = bodyResult.body || {};

    let route;
    try {
      route = await handleApiRoute(
        {
          pathname: req.url || '/',
          method: req.method || 'GET',
          headers: req.headers,
          body
        },
        config,
        {
          dependencyProbe,
          authService,
          handlers,
          routeDefinitions,
          routeDeclarationLookup,
          executableRouteKeys,
          supportedPermissionCodes,
          supportedPermissionScopes,
          corsPolicy,
          validateRouteDefinitions: false
        }
      );
    } catch (error) {
      console.error('[api] unhandled route error', {
        request_id: requestId,
        error_summary: summarizeErrorForLog(error)
      });
      route = buildInternalServerProblem(requestId);
    }

    res.statusCode = route.status;
    const routeHeaders = applyCorsPolicyToHeaders(
      route.headers,
      corsPolicy,
      req.headers.origin
    );
    for (const [header, value] of Object.entries(routeHeaders)) {
      res.setHeader(header, value);
    }
    res.end(route.body);
  });
};

module.exports = {
  createServer,
  handleApiRoute,
  requestIdFrom,
  dispatchApiRoute,
  createRouteTable,
  listExecutableRouteKeys,
  resolveRouteDeclarationLookup,
  ensureAuthorizeRouteCapabilityOrThrow,
  createCorsPolicy,
  applyCorsPolicyToHeaders
};

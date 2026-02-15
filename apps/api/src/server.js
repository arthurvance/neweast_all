const http = require('node:http');
const { randomUUID } = require('node:crypto');
const { readConfig } = require('./config/env');
const { createRouteHandlers } = require('./http-routes');
const { checkDependencies } = require('./infrastructure/connectivity');
const { buildProblemDetails } = require('./common/problem-details');
const { AuthProblemError } = require('./modules/auth/auth.routes');
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
  ensureRoutePermissionDeclarationsOrThrow
} = require('./route-permissions');
const ROUTE_DECLARATION_LOOKUP_CACHE = new WeakMap();
const AUTHORIZE_ROUTE_PREFLIGHT_CACHE = new WeakMap();
const ROUTE_DECLARATION_LOOKUP_TOKEN = Symbol('routeDeclarationLookup');

const requestIdFrom = (req) => req.headers['x-request-id'] || randomUUID();
const asMethod = (method) => String(method || 'GET').toUpperCase();

const normalizePathname = (pathname) => {
  if (!pathname || pathname === '/') {
    return '/';
  }
  return pathname.replace(/\/+$/, '') || '/';
};

const parseRequestPath = (inputPath) => {
  const raw = typeof inputPath === 'string' && inputPath.length > 0 ? inputPath : '/';
  try {
    const parsed = new URL(raw, 'http://localhost');
    return {
      pathname: normalizePathname(parsed.pathname),
      search: parsed.search || ''
    };
  } catch (_error) {
    const [pathnameOnly, ...queryParts] = raw.split('?');
    return {
      pathname: normalizePathname(pathnameOnly),
      search: queryParts.length > 0 ? `?${queryParts.join('?')}` : ''
    };
  }
};

const DEFAULT_JSON_BODY_LIMIT_BYTES = 1024 * 1024;

const resolveJsonBodyLimitBytes = (value) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_JSON_BODY_LIMIT_BYTES;
  }
  return Math.floor(parsed);
};

const CORS_WILDCARD_ORIGIN = '*';
const CORS_ALLOW_HEADERS = 'Authorization, Content-Type, X-Request-Id';
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
  getAuthorizationContext = () => null
}) => ({
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
  'GET /auth/platform/member-admin/probe': async () =>
    runAuthRoute(
      () => handlers.authPlatformMemberAdminProbe(requestId, headers.authorization),
      requestId
    ),
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
    runAuthRoute(
      () =>
        handlers.authReplacePlatformRoleFacts(
          requestId,
          headers.authorization,
          body || {},
          getAuthorizationContext()
        ),
      requestId
    ),
  'GET /smoke': async () => {
    const payload = await handlers.smoke(requestId);
    return responseJson(payload.ok ? 200 : 503, payload);
  }
});

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

  try {
    const authorizationContext = await handlers.authorizeRoute({
      requestId,
      authorization: headers.authorization,
      permissionCode: routeDefinition.permission_code,
      scope: routeDefinition.scope
    });
    return {
      authorizationContext: authorizationContext || null
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
      hasDeclaredRoutePath: (path) => declaredRoutePaths.has(path),
      listDeclaredMethodsForPath: (path) => {
        const normalizedPath = normalizePathname(path);
        const declaredMethods = declaredMethodsByPath.get(normalizedPath);
        return declaredMethods ? [...declaredMethods] : [];
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
  const resolvedRequestId = requestId || headers['x-request-id'] || randomUUID();
  const corsOptions = {
    corsPolicy,
    requestOrigin: headers.origin
  };
  const routePath = parseRequestPath(pathname).pathname;
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
  const routeKey = `${routeDispatchMethod} ${routePath}`;
  const routeDefinition = resolvedRouteDeclarationLookup.findRouteDefinition({
    method: routeDispatchMethod,
    path: routePath
  });
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
    getAuthorizationContext: () => authorizationContext
  });
  const routeHandler = routeTable[routeKey];
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
      return finalizeResponse(authorizationFailure);
    }
    authorizationContext = resolvedAuthorizationContext;
    const routeResponse = await routeHandler();
    return finalizeResponse(routeResponse);
  }

  return finalizeResponse(responseJson(
    404,
    buildProblemDetails({
      status: 404,
      title: 'Not Found',
      detail: `No route for ${routePath}`,
      requestId: resolvedRequestId
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
  const requestId = headers['x-request-id'] || randomUUID();
  const handlers = options.handlers || createRouteHandlers(config, {
    dependencyProbe,
    authService
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
    authService
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
    if (!req.headers['x-request-id']) {
      req.headers['x-request-id'] = requestId;
    }

    const bodyResult = await readJsonBody(req, jsonBodyLimitBytes);
    if (bodyResult.error) {
      res.statusCode = bodyResult.error.status;
      const responseHeaders = applyCorsPolicyToHeaders(
        bodyResult.error.headers,
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
      res.end(bodyResult.error.body);
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

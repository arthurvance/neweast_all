const http = require('node:http');
const { randomUUID } = require('node:crypto');
const { readConfig } = require('./config/env');
const { createRouteHandlers } = require('./http-routes');
const { checkDependencies } = require('./infrastructure/connectivity');
const { buildProblemDetails } = require('./common/problem-details');
const { AuthProblemError } = require('./modules/auth/auth.routes');

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

const CORS_ALLOW_ORIGIN = '*';
const CORS_ALLOW_HEADERS = 'Authorization, Content-Type, X-Request-Id';
const CORS_ALLOW_METHODS = 'GET,HEAD,POST,OPTIONS';
const CORS_MAX_AGE_SECONDS = '600';

const withCorsHeaders = (headers = {}) => ({
  'access-control-allow-origin': CORS_ALLOW_ORIGIN,
  ...headers
});

const preflightCorsHeaders = () =>
  withCorsHeaders({
    'access-control-allow-methods': CORS_ALLOW_METHODS,
    'access-control-allow-headers': CORS_ALLOW_HEADERS,
    'access-control-max-age': CORS_MAX_AGE_SECONDS,
    vary: 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers'
  });

const responseJson = (status, payload, contentType = 'application/json') => ({
  status,
  headers: withCorsHeaders({ 'content-type': contentType }),
  body: JSON.stringify(payload)
});

const responseNoContent = (status, headers = {}) => ({
  status,
  headers: withCorsHeaders({
    ...headers,
    'content-length': '0'
  }),
  body: ''
});

const asPositiveInteger = (value) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return null;
  }
  return Math.ceil(parsed);
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
      detail: `JSON payload exceeds ${maxBytes} bytes`,
      requestId,
      extensions: { error_code: 'AUTH-413-PAYLOAD-TOO-LARGE' }
    }),
    'application/problem+json'
    );
    response.headers.connection = 'close';
    return response;
  })();

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

const createRouteTable = ({ handlers, requestId, headers, body }) => ({
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
    runAuthRoute(() => handlers.authTenantOptions(requestId, headers.authorization), requestId),
  'POST /auth/tenant/select': async () =>
    runAuthRoute(
      () => handlers.authTenantSelect(requestId, headers.authorization, body || {}),
      requestId
    ),
  'POST /auth/tenant/switch': async () =>
    runAuthRoute(
      () => handlers.authTenantSwitch(requestId, headers.authorization, body || {}),
      requestId
    ),
  'POST /auth/refresh': async () =>
    runAuthRoute(() => handlers.authRefresh(requestId, body || {}), requestId),
  'POST /auth/logout': async () =>
    runAuthRoute(() => handlers.authLogout(requestId, headers.authorization), requestId),
  'POST /auth/change-password': async () =>
    runAuthRoute(
      () => handlers.authChangePassword(requestId, headers.authorization, body || {}),
      requestId
    ),
  'GET /smoke': async () => {
    const payload = await handlers.smoke(requestId);
    return responseJson(payload.ok ? 200 : 503, payload);
  }
});

const ROUTED_API_PATHS = new Set([
  '/health',
  '/openapi.json',
  '/auth/ping',
  '/auth/login',
  '/auth/otp/send',
  '/auth/otp/login',
  '/auth/tenant/options',
  '/auth/tenant/select',
  '/auth/tenant/switch',
  '/auth/refresh',
  '/auth/logout',
  '/auth/change-password',
  '/smoke'
]);

const dispatchApiRoute = async ({
  pathname,
  method = 'GET',
  headers = {},
  body = {},
  requestId,
  handlers
}) => {
  const resolvedRequestId = requestId || headers['x-request-id'] || randomUUID();
  const routePath = parseRequestPath(pathname).pathname;
  const normalizedMethod = asMethod(method);
  const routeKey = `${normalizedMethod} ${routePath}`;

  if (normalizedMethod === 'OPTIONS' && ROUTED_API_PATHS.has(routePath)) {
    return responseNoContent(204, preflightCorsHeaders());
  }

  const routeTable = createRouteTable({
    handlers,
    requestId: resolvedRequestId,
    headers,
    body
  });
  if (routeTable[routeKey]) {
    return routeTable[routeKey]();
  }

  return responseJson(
    404,
    buildProblemDetails({
      status: 404,
      title: 'Not Found',
      detail: `No route for ${routePath}`,
      requestId: resolvedRequestId
    }),
    'application/problem+json'
  );
};

const handleApiRoute = async (
  { pathname, method = 'GET', headers = {}, body = {} },
  config = readConfig(),
  options = {}
) => {
  const dependencyProbe = options.dependencyProbe || checkDependencies;
  const authService = options.authService;
  const requestId = headers['x-request-id'] || randomUUID();
  const handlers = options.handlers || createRouteHandlers(config, {
    dependencyProbe,
    authService
  });

  return dispatchApiRoute({
    pathname,
    method,
    headers,
    body,
    requestId,
    handlers
  });
};

const createServer = (config, options = {}) => {
  const dependencyProbe = options.dependencyProbe || checkDependencies;
  const authService = options.authService;
  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService
  });
  const jsonBodyLimitBytes = resolveJsonBodyLimitBytes(
    config.API_JSON_BODY_LIMIT_BYTES
  );

  return http.createServer(async (req, res) => {
    const bodyResult = await readJsonBody(req, jsonBodyLimitBytes);
    if (bodyResult.error) {
      res.statusCode = bodyResult.error.status;
      for (const [header, value] of Object.entries(bodyResult.error.headers)) {
        res.setHeader(header, value);
      }
      if (String(bodyResult.error.headers.connection || '').toLowerCase() === 'close') {
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

    const route = await handleApiRoute(
      {
        pathname: req.url || '/',
        method: req.method || 'GET',
        headers: req.headers,
        body
      },
      config,
      { dependencyProbe, authService, handlers }
    );

    res.statusCode = route.status;
    for (const [header, value] of Object.entries(route.headers)) {
      res.setHeader(header, value);
    }
    res.end(route.body);
  });
};

module.exports = { createServer, handleApiRoute, requestIdFrom, dispatchApiRoute };

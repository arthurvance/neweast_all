const http = require('node:http');
const { randomUUID } = require('node:crypto');
const { readConfig } = require('./config/env');
const { createRouteHandlers } = require('./http-routes');
const { checkDependencies } = require('./infrastructure/connectivity');
const { buildProblemDetails } = require('./common/problem-details');
const { AuthProblemError } = require('./modules/auth/auth.routes');

const requestIdFrom = (req) => req.headers['x-request-id'] || randomUUID();

const responseJson = (status, payload, contentType = 'application/json') => ({
  status,
  headers: { 'content-type': contentType },
  body: JSON.stringify(payload)
});

const authProblemResponse = (error, requestId) =>
  responseJson(
    error.status,
    buildProblemDetails({
      status: error.status,
      title: error.title,
      detail: error.detail,
      requestId,
      extensions: {
        error_code: error.errorCode
      }
    }),
    'application/problem+json'
  );

const handleApiRoute = async (
  { pathname, method = 'GET', headers = {}, body = {} },
  config = readConfig(),
  options = {}
) => {
  const dependencyProbe = options.dependencyProbe || checkDependencies;
  const authService = options.authService;
  const requestId = headers['x-request-id'] || randomUUID();
  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService
  });

  if (method === 'GET' && pathname === '/health') {
    const payload = await handlers.health(requestId);
    return responseJson(payload.ok ? 200 : 503, payload);
  }

  if (method === 'GET' && pathname === '/openapi.json') {
    return responseJson(200, handlers.openapi(requestId));
  }

  if (method === 'GET' && pathname === '/auth/ping') {
    return responseJson(200, handlers.authPing(requestId));
  }

  if (method === 'POST' && pathname === '/auth/login') {
    try {
      const payload = handlers.authLogin(requestId, body || {});
      return responseJson(200, payload);
    } catch (error) {
      if (error instanceof AuthProblemError) {
        return authProblemResponse(error, requestId);
      }
      throw error;
    }
  }

  if (method === 'POST' && pathname === '/auth/refresh') {
    try {
      const payload = handlers.authRefresh(requestId, body || {});
      return responseJson(200, payload);
    } catch (error) {
      if (error instanceof AuthProblemError) {
        return authProblemResponse(error, requestId);
      }
      throw error;
    }
  }

  if (method === 'POST' && pathname === '/auth/logout') {
    try {
      const payload = handlers.authLogout(requestId, headers.authorization);
      return responseJson(200, payload);
    } catch (error) {
      if (error instanceof AuthProblemError) {
        return authProblemResponse(error, requestId);
      }
      throw error;
    }
  }

  if (method === 'POST' && pathname === '/auth/change-password') {
    try {
      const payload = handlers.authChangePassword(
        requestId,
        headers.authorization,
        body || {}
      );
      return responseJson(200, payload);
    } catch (error) {
      if (error instanceof AuthProblemError) {
        return authProblemResponse(error, requestId);
      }
      throw error;
    }
  }

  if (method === 'GET' && pathname === '/smoke') {
    const payload = await handlers.smoke(requestId);
    return responseJson(payload.ok ? 200 : 503, payload);
  }

  return responseJson(
    404,
    buildProblemDetails({
      status: 404,
      title: 'Not Found',
      detail: `No route for ${pathname}`,
      requestId
    }),
    'application/problem+json'
  );
};

const createServer = (config, options = {}) => {
  const dependencyProbe = options.dependencyProbe || checkDependencies;
  const authService = options.authService;

  return http.createServer(async (req, res) => {
    let body = {};
    if (req.method === 'POST') {
      const chunks = [];
      for await (const chunk of req) {
        chunks.push(chunk);
      }
      const raw = Buffer.concat(chunks).toString('utf8');
      if (raw.length > 0) {
        try {
          body = JSON.parse(raw);
        } catch (_error) {
          const problem = responseJson(
            400,
            buildProblemDetails({
              status: 400,
              title: 'Bad Request',
              detail: 'Malformed JSON payload',
              requestId: requestIdFrom(req),
              extensions: { error_code: 'AUTH-400-INVALID-PAYLOAD' }
            }),
            'application/problem+json'
          );
          res.statusCode = problem.status;
          for (const [header, value] of Object.entries(problem.headers)) {
            res.setHeader(header, value);
          }
          res.end(problem.body);
          return;
        }
      }
    }

    const route = await handleApiRoute(
      {
        pathname: req.url || '/',
        method: req.method || 'GET',
        headers: req.headers,
        body
      },
      config,
      { dependencyProbe, authService }
    );

    res.statusCode = route.status;
    for (const [header, value] of Object.entries(route.headers)) {
      res.setHeader(header, value);
    }
    res.end(route.body);
  });
};

module.exports = { createServer, handleApiRoute, requestIdFrom };

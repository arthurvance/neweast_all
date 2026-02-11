require('reflect-metadata');

const { randomUUID } = require('node:crypto');
const { NestFactory } = require('@nestjs/core');
const { AppModule } = require('./app.module');
const { createRouteHandlers } = require('./http-routes');
const { checkDependencies } = require('./infrastructure/connectivity');
const { buildProblemDetails } = require('./common/problem-details');
const { log } = require('./common/logger');
const { AuthProblemError } = require('./modules/auth/auth.routes');

const createApiApp = async (config, options = {}) => {
  const dependencyProbe = options.dependencyProbe || checkDependencies;
  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService: options.authService
  });
  const app = await NestFactory.create(AppModule, { logger: false });
  const expressApp = app.getHttpAdapter().getInstance();

  expressApp.disable('x-powered-by');

  const respondAuthProblem = (error, req, res, next) => {
    if (!(error instanceof AuthProblemError)) {
      next(error);
      return;
    }

    const payload = buildProblemDetails({
      status: error.status,
      title: error.title,
      detail: error.detail,
      requestId: req.request_id,
      extensions: {
        error_code: error.errorCode
      }
    });

    res.status(error.status).type('application/problem+json').json(payload);
  };

  expressApp.use((req, _res, next) => {
    req.request_id = req.headers['x-request-id'] || randomUUID();
    next();
  });

  expressApp.get('/health', async (req, res, next) => {
    try {
      const payload = await handlers.health(req.request_id);
      res.status(payload.ok ? 200 : 503).json(payload);
    } catch (error) {
      next(error);
    }
  });

  expressApp.get('/openapi.json', (req, res) => {
    const payload = handlers.openapi(req.request_id);
    res.status(200).json(payload);
  });

  expressApp.get('/auth/ping', (req, res) => {
    const payload = handlers.authPing(req.request_id);
    res.status(200).json(payload);
  });

  expressApp.post('/auth/login', (req, res, next) => {
    try {
      const payload = handlers.authLogin(req.request_id, req.body || {});
      res.status(200).json(payload);
    } catch (error) {
      respondAuthProblem(error, req, res, next);
    }
  });

  expressApp.post('/auth/refresh', (req, res, next) => {
    try {
      const payload = handlers.authRefresh(req.request_id, req.body || {});
      res.status(200).json(payload);
    } catch (error) {
      respondAuthProblem(error, req, res, next);
    }
  });

  expressApp.post('/auth/logout', (req, res, next) => {
    try {
      const payload = handlers.authLogout(req.request_id, req.headers.authorization);
      res.status(200).json(payload);
    } catch (error) {
      respondAuthProblem(error, req, res, next);
    }
  });

  expressApp.post('/auth/change-password', (req, res, next) => {
    try {
      const payload = handlers.authChangePassword(
        req.request_id,
        req.headers.authorization,
        req.body || {}
      );
      res.status(200).json(payload);
    } catch (error) {
      respondAuthProblem(error, req, res, next);
    }
  });

  expressApp.get('/smoke', async (req, res, next) => {
    try {
      const payload = await handlers.smoke(req.request_id);
      res.status(payload.ok ? 200 : 503).json(payload);
    } catch (error) {
      next(error);
    }
  });

  expressApp.use((req, res) => {
    const payload = buildProblemDetails({
      status: 404,
      title: 'Not Found',
      detail: `No route for ${req.path}`,
      requestId: req.request_id
    });
    res.status(404).type('application/problem+json').json(payload);
  });

  expressApp.use((error, req, res, _next) => {
    log('error', 'Unhandled API error', {
      request_id: req.request_id || 'request_id_unset',
      detail: error.message
    });

    const payload = buildProblemDetails({
      status: 500,
      title: 'Internal Server Error',
      detail: 'Unexpected server failure',
      requestId: req.request_id
    });
    res.status(500).type('application/problem+json').json(payload);
  });

  return app;
};

module.exports = { createApiApp };

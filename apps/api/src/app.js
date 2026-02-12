require('reflect-metadata');

const { randomUUID } = require('node:crypto');
const Redis = require('ioredis');
const { NestFactory } = require('@nestjs/core');
const { AppModule } = require('./app.module');
const { createRouteHandlers } = require('./http-routes');
const { dispatchApiRoute } = require('./server');
const { checkDependencies } = require('./infrastructure/connectivity');
const { connectMySql } = require('./infrastructure/mysql-client');
const { buildProblemDetails } = require('./common/problem-details');
const { log } = require('./common/logger');
const { createAuthService } = require('./modules/auth/auth.service');
const { createMySqlAuthStore } = require('./modules/auth/auth.store.mysql');
const { createRedisOtpStore } = require('./modules/auth/auth.otp.store.redis');
const { createRedisRateLimitStore } = require('./modules/auth/auth.rate-limit.redis');

const normalizePem = (rawPem) => {
  if (typeof rawPem !== 'string') {
    return '';
  }
  return rawPem.replace(/\\n/g, '\n').trim();
};

const parseJsonBody = (rawBody) => {
  if (typeof rawBody !== 'string' || rawBody.length === 0) {
    return {};
  }
  return JSON.parse(rawBody);
};

const DEFAULT_JSON_BODY_LIMIT_BYTES = 1024 * 1024;

const resolveJsonBodyLimitBytes = (value) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_JSON_BODY_LIMIT_BYTES;
  }
  return Math.floor(parsed);
};

const createApiApp = async (config, options = {}) => {
  const dependencyProbe = options.dependencyProbe || checkDependencies;
  let authService = options.authService;
  let closeAuthResources = async () => {};
  const requirePersistentAuthStore = options.requirePersistentAuthStore === true;
  const connectDb = options.connectMySql || connectMySql;
  const createAuthServiceFactory = options.createAuthService || createAuthService;
  const createRedisClient =
    options.createRedisClient ||
    ((redisConfig) =>
      new Redis({
        host: redisConfig.host,
        port: redisConfig.port,
        connectTimeout: redisConfig.connectTimeout,
        lazyConnect: true,
        maxRetriesPerRequest: 1,
        enableOfflineQueue: false,
        enableReadyCheck: false
      }));

  if (!authService) {
    if (config.ALLOW_MOCK_BACKENDS && !requirePersistentAuthStore) {
      authService = createAuthServiceFactory({
        allowInMemoryOtpStores: true,
        requireSecureOtpStores: false
      });
    } else {
      let dbClient = null;
      let redisClient = null;
      const closeInfrastructureResources = async () => {
        if (redisClient) {
          if (redisClient.status === 'ready' || redisClient.status === 'connect') {
            await redisClient.quit().catch(() => {
              redisClient.disconnect();
            });
          } else {
            redisClient.disconnect();
          }
        }

        if (dbClient) {
          await dbClient.close();
        }
      };

      try {
        dbClient = await connectDb({
          host: config.DB_HOST,
          port: config.DB_PORT,
          user: config.DB_USER,
          password: config.DB_PASSWORD,
          database: config.DB_NAME,
          connectTimeoutMs: config.DB_CONNECT_TIMEOUT_MS
        });

        const authStore = createMySqlAuthStore({ dbClient });
        const privateKey = normalizePem(config.AUTH_JWT_PRIVATE_KEY);
        const publicKey = normalizePem(config.AUTH_JWT_PUBLIC_KEY);
        const hasExternalJwtKeys = privateKey.length > 0 && publicKey.length > 0;
        const jwtKeyPair = hasExternalJwtKeys ? { privateKey, publicKey } : undefined;
        let otpStore = null;
        let rateLimitStore = null;

        if (!config.ALLOW_MOCK_BACKENDS) {
          redisClient = createRedisClient({
            host: config.REDIS_HOST,
            port: config.REDIS_PORT,
            connectTimeout: config.REDIS_CONNECT_TIMEOUT_MS
          });
          await redisClient.connect();
          otpStore = createRedisOtpStore({ redis: redisClient });
          rateLimitStore = createRedisRateLimitStore({ redis: redisClient });
        }

        authService = createAuthServiceFactory({
          authStore,
          otpStore,
          rateLimitStore,
          jwtKeyPair,
          multiInstance: Boolean(config.AUTH_MULTI_INSTANCE),
          enforceExternalJwtKeys: Boolean(config.AUTH_MULTI_INSTANCE),
          requireSecureOtpStores: !config.ALLOW_MOCK_BACKENDS,
          allowInMemoryOtpStores: Boolean(config.ALLOW_MOCK_BACKENDS)
        });

        closeAuthResources = closeInfrastructureResources;
      } catch (error) {
        await closeInfrastructureResources().catch(() => {});
        throw error;
      }
    }
  }

  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService
  });
  const jsonBodyLimitBytes = resolveJsonBodyLimitBytes(
    config.API_JSON_BODY_LIMIT_BYTES
  );
  const app = await NestFactory.create(AppModule, { logger: false });
  const expressApp = app.getHttpAdapter().getInstance();

  expressApp.disable('x-powered-by');

  expressApp.use((req, _res, next) => {
    req.request_id = req.headers['x-request-id'] || randomUUID();
    next();
  });

  expressApp.use(async (req, res, next) => {
    const respondProblem = ({
      status,
      title,
      detail,
      errorCode,
      forceCloseConnection = false
    }) => {
      const payload = buildProblemDetails({
        status,
        title,
        detail,
        requestId: req.request_id,
        extensions: { error_code: errorCode }
      });
      if (forceCloseConnection) {
        res.setHeader('connection', 'close');
        res.once('finish', () => {
          if (typeof req.destroy === 'function' && !req.destroyed) {
            req.destroy();
          }
        });
      }
      res.status(status).type('application/problem+json').json(payload);
    };

    const method = String(req.method || 'GET').toUpperCase();
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
      if (!req.body || typeof req.body !== 'object') {
        req.body = {};
      }
      next();
      return;
    }

    if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
      next();
      return;
    }

    const contentType = String(req.headers['content-type'] || '').toLowerCase();
    if (!contentType.includes('application/json')) {
      req.body = {};
      next();
      return;
    }

    const contentLength = Number(req.headers['content-length']);
    if (Number.isFinite(contentLength) && contentLength > jsonBodyLimitBytes) {
      respondProblem({
        status: 413,
        title: 'Payload Too Large',
        detail: `JSON payload exceeds ${jsonBodyLimitBytes} bytes`,
        errorCode: 'AUTH-413-PAYLOAD-TOO-LARGE',
        forceCloseConnection: true
      });
      return;
    }

    const chunks = [];
    let bytesRead = 0;
    let settled = false;

    const cleanup = () => {
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onError);
      req.off('aborted', onAbort);
    };

    const onData = (chunk) => {
      if (settled) {
        return;
      }

      const bufferChunk = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytesRead += bufferChunk.length;

      if (bytesRead > jsonBodyLimitBytes) {
        settled = true;
        cleanup();
        req.pause();
        respondProblem({
          status: 413,
          title: 'Payload Too Large',
          detail: `JSON payload exceeds ${jsonBodyLimitBytes} bytes`,
          errorCode: 'AUTH-413-PAYLOAD-TOO-LARGE',
          forceCloseConnection: true
        });
        return;
      }

      chunks.push(bufferChunk);
    };

    const onEnd = () => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();

      const raw = chunks.length > 0 ? Buffer.concat(chunks).toString('utf8') : '';
      try {
        req.body = parseJsonBody(raw);
        next();
      } catch (_error) {
        respondProblem({
          status: 400,
          title: 'Bad Request',
          detail: 'Malformed JSON payload',
          errorCode: 'AUTH-400-INVALID-PAYLOAD'
        });
      }
    };

    const onError = () => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      respondProblem({
        status: 400,
        title: 'Bad Request',
        detail: 'Malformed JSON payload',
        errorCode: 'AUTH-400-INVALID-PAYLOAD'
      });
    };

    const onAbort = () => {
      onError();
    };

    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
    req.on('aborted', onAbort);
  });

  const dispatchRegisteredRoute = async (req, res, next) => {
    try {
      const route = await dispatchApiRoute({
        pathname: req.path,
        method: req.method,
        headers: req.headers,
        body: req.body || {},
        requestId: req.request_id,
        handlers
      });

      for (const [header, value] of Object.entries(route.headers || {})) {
        res.setHeader(header, value);
      }

      const contentType = route.headers?.['content-type'] || 'application/json';
      res.status(route.status);
      if (contentType) {
        res.type(contentType);
      }
      try {
        if (typeof route.body === 'string' && route.body.length === 0) {
          res.send('');
          return;
        }
        res.json(JSON.parse(route.body));
      } catch (_error) {
        res.send(route.body);
      }
    } catch (error) {
      next(error);
    }
  };

  const routeTable = [
    ['get', '/health'],
    ['get', '/openapi.json'],
    ['get', '/auth/ping'],
    ['post', '/auth/login'],
    ['post', '/auth/otp/send'],
    ['post', '/auth/otp/login'],
    ['post', '/auth/refresh'],
    ['post', '/auth/logout'],
    ['post', '/auth/change-password'],
    ['get', '/smoke']
  ];

  for (const [method, path] of routeTable) {
    expressApp[method](path, dispatchRegisteredRoute);
  }

  expressApp.use((req, res, next) => {
    if (String(req.method || 'GET').toUpperCase() !== 'OPTIONS') {
      next();
      return;
    }
    dispatchRegisteredRoute(req, res, next);
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

  const closeApp = app.close.bind(app);
  app.close = async () => {
    await closeAuthResources();
    await closeApp();
  };

  return app;
};

module.exports = { createApiApp };

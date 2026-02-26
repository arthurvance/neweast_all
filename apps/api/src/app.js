require('reflect-metadata');

const Redis = require('ioredis');
const { NestFactory } = require('@nestjs/core');
const { AppModule } = require('./app.module');
const { createRouteHandlers } = require('./http-routes');
const {
  dispatchApiRoute,
  requestIdFrom,
  listExecutableRouteKeys,
  resolveRouteDeclarationLookup,
  ensureAuthorizeRouteCapabilityOrThrow,
  createCorsPolicy,
  applyCorsPolicyToHeaders
} = require('./server');
const { checkDependencies } = require('./infrastructure/connectivity');
const { connectMySql } = require('./infrastructure/mysql-client');
const { buildProblemDetails } = require('./common/problem-details');
const { extract: extractTraceContext } = require('./common/trace-context');
const { log } = require('./common/logger');
const {
  createAuthService,
  listSupportedRoutePermissionCodes,
  listSupportedRoutePermissionScopes
} = require('./shared-kernel/auth/auth-facade');
const { createMySqlAuthStore } = require('./shared-kernel/auth/store/create-mysql-auth-store');
const { createRedisOtpStore } = require('./modules/auth/auth.otp.store.redis');
const { createRedisRateLimitStore } = require('./modules/auth/auth.rate-limit.redis');
const {
  createRedisAuthIdempotencyStore
} = require('./modules/auth/auth.idempotency.redis');
const {
  ROUTE_DEFINITIONS,
  toRouteDefinitionsSnapshot,
  ensureRoutePermissionDeclarationsOrThrow
} = require('./route-permissions');

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

const DEFAULT_PASSWORD_CONFIG_KEY = 'auth.default_password';
const normalizeRuntimeSensitiveConfigStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (!normalizedStatus || normalizedStatus === 'active' || normalizedStatus === 'enabled') {
    return 'active';
  }
  if (normalizedStatus === 'disabled') {
    return 'disabled';
  }
  return '';
};
const resolveRuntimeAuthStoreFromAuthService = (authService = null) => {
  const authStore = authService?._internals?.authStore;
  if (
    !authStore
    || typeof authStore.getSystemSensitiveConfig !== 'function'
  ) {
    return null;
  }
  return authStore;
};
const createEnvSensitiveConfigProvider = (config = {}, options = {}) => ({
  getEncryptedConfig: async (configKey) => {
    const normalizedConfigKey = String(configKey || '').trim();
    const fallbackEncryptedValue = String(config.AUTH_DEFAULT_PASSWORD_ENCRYPTED || '').trim();
    if (normalizedConfigKey !== DEFAULT_PASSWORD_CONFIG_KEY) {
      return '';
    }
    const runtimeAuthStoreResolver =
      typeof options.resolveAuthStore === 'function'
        ? options.resolveAuthStore
        : null;
    if (runtimeAuthStoreResolver) {
      const runtimeAuthStore = runtimeAuthStoreResolver();
      if (
        runtimeAuthStore
        && typeof runtimeAuthStore.getSystemSensitiveConfig === 'function'
      ) {
        try {
          const record = await runtimeAuthStore.getSystemSensitiveConfig({
            configKey: normalizedConfigKey
          });
          const normalizedRecordStatus = normalizeRuntimeSensitiveConfigStatus(
            record?.status
          );
          if (normalizedRecordStatus === 'disabled') {
            return fallbackEncryptedValue;
          }
          if (!normalizedRecordStatus) {
            log('warn', 'Runtime sensitive config status invalid; fallback to env', {
              config_key: normalizedConfigKey,
              status: String(record?.status || '').trim() || null
            });
            return fallbackEncryptedValue;
          }
          const encryptedValue = String(
            record?.encryptedValue ?? record?.encrypted_value ?? ''
          ).trim();
          if (encryptedValue) {
            return encryptedValue;
          }
        } catch (error) {
          log('warn', 'Runtime sensitive config lookup failed; fallback to env', {
            config_key: normalizedConfigKey,
            error: String(error?.message || error || '')
          });
        }
      }
    }
    return fallbackEncryptedValue;
  }
});

const DEFAULT_JSON_BODY_LIMIT_BYTES = 1024 * 1024;
const REQUIRED_AUTH_SCHEMA = {
  auth_sessions: [
    'session_id',
    'user_id',
    'session_version',
    'entry_domain',
    'active_tenant_id',
    'status',
    'revoked_reason',
    'updated_at'
  ],
  tenant_memberships: [
    'user_id',
    'tenant_id',
    'membership_id',
    'tenant_name',
    'status',
    'display_name',
    'department_name',
    'joined_at',
    'left_at',
    'can_view_user_management',
    'can_operate_user_management',
    'can_view_role_management',
    'can_operate_role_management'
  ],
  platform_user_roles: [
    'user_id',
    'role_id',
    'status',
    'can_view_user_management',
    'can_operate_user_management',
    'can_view_tenant_management',
    'can_operate_tenant_management',
    'updated_at'
  ],
  platform_users: [
    'user_id',
    'name',
    'department',
    'status',
    'created_at',
    'updated_at'
  ],
  platform_role_permission_grants: [
    'role_id',
    'permission_code',
    'created_by_user_id',
    'updated_by_user_id',
    'created_at',
    'updated_at'
  ]
};

const readInfoSchemaField = (row, fieldName) => {
  if (!row || typeof row !== 'object') {
    return '';
  }
  const lowerValue = row[fieldName];
  if (typeof lowerValue === 'string' && lowerValue.length > 0) {
    return lowerValue.trim();
  }
  const upperValue = row[String(fieldName).toUpperCase()];
  if (typeof upperValue === 'string' && upperValue.length > 0) {
    return upperValue.trim();
  }
  return '';
};

const resolveJsonBodyLimitBytes = (value) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_JSON_BODY_LIMIT_BYTES;
  }
  return Math.floor(parsed);
};

const resolveRequestTraceContext = (req) => {
  const requestId = requestIdFrom(req);
  const extractedTraceContext = extractTraceContext({
    source: req?.headers || {},
    channel: 'http',
    fallbackRequestId: requestId,
    generateTraceparentOnMissing: true
  });
  return {
    requestId,
    traceparent: extractedTraceContext.traceparent
  };
};

const applyTraceContextHeaders = (res, traceContext = {}) => {
  const requestId = String(traceContext?.requestId || '').trim();
  if (requestId) {
    res.setHeader('x-request-id', requestId);
  }
  const traceparent = String(traceContext?.traceparent || '').trim();
  if (traceparent) {
    res.setHeader('traceparent', traceparent);
    return;
  }
  res.removeHeader('traceparent');
};

const ensureAuthSchemaPreflight = async ({ dbClient }) => {
  const requiredTables = Object.keys(REQUIRED_AUTH_SCHEMA);
  const tablePlaceholders = requiredTables.map(() => '?').join(', ');
  const tableRows = await dbClient.query(
    `
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = DATABASE()
        AND table_name IN (${tablePlaceholders})
    `,
    requiredTables
  );
  const availableTables = new Set(
    (Array.isArray(tableRows) ? tableRows : []).map((row) =>
      readInfoSchemaField(row, 'table_name')
    )
  );
  const missingTables = requiredTables.filter((tableName) => !availableTables.has(tableName));
  if (missingTables.length > 0) {
    throw new Error(
      `Auth schema preflight failed: missing tables: ${missingTables.join(', ')}`
    );
  }

  for (const [tableName, requiredColumns] of Object.entries(REQUIRED_AUTH_SCHEMA)) {
    const placeholders = requiredColumns.map(() => '?').join(', ');
    const columnRows = await dbClient.query(
      `
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = ?
          AND column_name IN (${placeholders})
      `,
      [tableName, ...requiredColumns]
    );
    const availableColumns = new Set(
      (Array.isArray(columnRows) ? columnRows : []).map((row) =>
        readInfoSchemaField(row, 'column_name')
      )
    );
    const missingColumns = requiredColumns.filter(
      (columnName) => !availableColumns.has(columnName)
    );
    if (missingColumns.length > 0) {
      throw new Error(
        `Auth schema preflight failed: ${tableName} missing columns: ${missingColumns.join(', ')}`
      );
    }
  }
};

const createApiApp = async (config, options = {}) => {
  const dependencyProbe = options.dependencyProbe || checkDependencies;
  const routeDefinitions = toRouteDefinitionsSnapshot(
    Array.isArray(options.routeDefinitions)
      ? options.routeDefinitions
      : ROUTE_DEFINITIONS
  );
  const executableRouteKeys = Array.isArray(options.executableRouteKeys)
    ? options.executableRouteKeys
    : listExecutableRouteKeys();
  const supportedPermissionCodes =
    options.supportedPermissionCodes || listSupportedRoutePermissionCodes();
  const supportedPermissionScopes =
    options.supportedPermissionScopes || listSupportedRoutePermissionScopes();
  ensureRoutePermissionDeclarationsOrThrow(routeDefinitions, {
    executableRouteKeys,
    supportedPermissionCodes,
    supportedPermissionScopes
  });
  const routeDeclarationLookup = resolveRouteDeclarationLookup({ routeDefinitions });
  let authService = options.authService;
  let closeAuthResources = async () => {};
  const requirePersistentAuthStore = options.requirePersistentAuthStore === true;
  const connectDb = options.connectMySql || connectMySql;
  const createAuthServiceFactory = options.createAuthService || createAuthService;
  let authIdempotencyStore = options.authIdempotencyStore || null;
  let runtimeAuthStore = null;
  if (authService) {
    runtimeAuthStore = resolveRuntimeAuthStoreFromAuthService(authService);
  }
  const sensitiveConfigProvider = createEnvSensitiveConfigProvider(config, {
    resolveAuthStore: () => runtimeAuthStore
  });
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
        requireSecureOtpStores: false,
        sensitiveConfigProvider,
        sensitiveConfigDecryptionKey: config.AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY
      });
      runtimeAuthStore = resolveRuntimeAuthStoreFromAuthService(authService);
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
        await ensureAuthSchemaPreflight({ dbClient });

        const authStore = createMySqlAuthStore({ dbClient });
        runtimeAuthStore = authStore;
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
          if (!authIdempotencyStore) {
            authIdempotencyStore = createRedisAuthIdempotencyStore({
              redis: redisClient
            });
          }
        }

        authService = createAuthServiceFactory({
          authStore,
          otpStore,
          rateLimitStore,
          jwtKeyPair,
          multiInstance: Boolean(config.AUTH_MULTI_INSTANCE),
          enforceExternalJwtKeys: Boolean(config.AUTH_MULTI_INSTANCE),
          requireSecureOtpStores: !config.ALLOW_MOCK_BACKENDS,
          allowInMemoryOtpStores: Boolean(config.ALLOW_MOCK_BACKENDS),
          sensitiveConfigProvider,
          sensitiveConfigDecryptionKey: config.AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY
        });
        runtimeAuthStore =
          resolveRuntimeAuthStoreFromAuthService(authService) || runtimeAuthStore;

        closeAuthResources = closeInfrastructureResources;
      } catch (error) {
        await closeInfrastructureResources().catch(() => {});
        throw error;
      }
    }
  }

  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService,
    authIdempotencyStore
  });
  ensureAuthorizeRouteCapabilityOrThrow({
    routeDefinitions,
    handlers
  });
  const jsonBodyLimitBytes = resolveJsonBodyLimitBytes(
    config.API_JSON_BODY_LIMIT_BYTES
  );
  const corsPolicy = createCorsPolicy(config);
  const app = await NestFactory.create(AppModule, { logger: false });
  const expressApp = app.getHttpAdapter().getInstance();

  expressApp.disable('x-powered-by');

  expressApp.use((req, res, next) => {
    const traceContext = resolveRequestTraceContext(req);
    req.request_id = traceContext.requestId;
    req.traceparent = traceContext.traceparent;
    req.trace_context = traceContext;
    req.headers['x-request-id'] = req.request_id;
    if (req.traceparent) {
      req.headers.traceparent = req.traceparent;
    } else {
      delete req.headers.traceparent;
    }
    applyTraceContextHeaders(res, traceContext);
    next();
  });

  expressApp.use((req, res, next) => {
    const corsHeaders = applyCorsPolicyToHeaders({}, corsPolicy, req.headers.origin);
    for (const [header, value] of Object.entries(corsHeaders)) {
      res.setHeader(header, value);
    }
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
        traceparent: req.traceparent,
        extensions: { error_code: errorCode }
      });
      applyTraceContextHeaders(res, req.trace_context);
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
        detail: 'JSON payload exceeds allowed size',
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
          detail: 'JSON payload exceeds allowed size',
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
        traceContext: req.trace_context,
        handlers,
        routeDefinitions,
        routeDeclarationLookup
      });

      const routeHeaders = applyCorsPolicyToHeaders(
        route.headers || {},
        corsPolicy,
        req.headers.origin
      );
      for (const [header, value] of Object.entries(routeHeaders)) {
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

  for (const routeDefinition of routeDefinitions) {
    const method = String(routeDefinition.method || 'GET').trim().toLowerCase();
    const path = String(routeDefinition.path || '/');
    expressApp[method](path, dispatchRegisteredRoute);
  }

  expressApp.use((req, res, next) => {
    if (String(req.method || 'GET').toUpperCase() !== 'OPTIONS') {
      next();
      return;
    }
    dispatchRegisteredRoute(req, res, next);
  });

  expressApp.use((req, res, next) => {
    dispatchRegisteredRoute(req, res, next);
  });

  expressApp.use((error, req, res, _next) => {
    log('error', 'Unhandled API error', {
      request_id: req.request_id || 'request_id_unset',
      traceparent: req.traceparent,
      detail: error.message
    });

    const payload = buildProblemDetails({
      status: 500,
      title: 'Internal Server Error',
      detail: 'Unexpected server failure',
      requestId: req.request_id,
      traceparent: req.traceparent,
      extensions: {
        error_code: 'AUTH-500-INTERNAL'
      }
    });
    applyTraceContextHeaders(res, req.trace_context);
    res.status(500).type('application/problem+json').json(payload);
  });

  const closeApp = app.close.bind(app);
  app.close = async () => {
    await closeAuthResources();
    await closeApp();
  };

  return app;
};

module.exports = {
  createApiApp,
  _internals: {
    createEnvSensitiveConfigProvider,
    resolveRuntimeAuthStoreFromAuthService,
    DEFAULT_PASSWORD_CONFIG_KEY
  }
};

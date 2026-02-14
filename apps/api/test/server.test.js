const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { AuthProblemError } = require('../src/modules/auth/auth.routes');
const { readConfig } = require('../src/config/env');
const {
  createServer,
  handleApiRoute,
  dispatchApiRoute,
  resolveRouteDeclarationLookup
} = require('../src/server');
const { ROUTE_DEFINITIONS } = require('../src/route-permissions');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'false' });
const dependencyProbe = async () => ({
  db: { ok: true },
  redis: { ok: true }
});
const cloneRouteDefinitions = (routeDefinitions = []) =>
  routeDefinitions.map((routeDefinition) => ({
    ...routeDefinition
  }));

const startServer = async (overrides = {}, serverOptions = {}) => {
  const server = createServer(readConfig(overrides), {
    dependencyProbe,
    ...serverOptions
  });
  await new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', (error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: async () => {
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
    }
  };
};

test('openapi endpoint is exposed with auth placeholder', () => {
  const handlers = createRouteHandlers(config, {
    dependencyProbe
  });

  const payload = handlers.openapi('openapi-test');
  assert.equal(payload.openapi, '3.1.0');
  assert.ok(payload.paths['/auth/ping']);
  assert.ok(payload.paths['/health']);
  assert.ok(payload.paths['/auth/otp/send']);
  assert.ok(payload.paths['/auth/otp/login']);
  assert.ok(payload.paths['/auth/tenant/member-admin/probe']);
  assert.ok(payload.paths['/auth/login'].post.responses['400']);
  assert.ok(payload.paths['/auth/login'].post.responses['413']);
  assert.ok(payload.paths['/auth/login'].post.responses['429']);
  assert.ok(payload.paths['/auth/otp/send'].post.responses['413']);
  assert.ok(payload.paths['/auth/otp/login'].post.responses['413']);
  assert.ok(payload.paths['/auth/refresh'].post.responses['400']);
  assert.ok(payload.paths['/auth/refresh'].post.responses['413']);
  assert.ok(payload.paths['/auth/change-password'].post.responses['413']);
  assert.ok(
    payload.paths['/auth/tenant/member-admin/probe'].get.responses['403'].content[
      'application/problem+json'
    ].examples.no_domain
  );
  assert.equal(
    payload.paths['/auth/tenant/member-admin/probe'].get.responses['403'].content[
      'application/problem+json'
    ].examples.no_domain.value.error_code,
    'AUTH-403-NO-DOMAIN'
  );
  assert.equal(
    payload.components.schemas.ProblemDetails.properties.error_code.type,
    'string'
  );
  assert.equal(
    payload.components.schemas.ProblemDetails.properties.retry_after_seconds.type,
    'integer'
  );
  assert.equal(
    payload.components.schemas.ProblemDetails.properties.rate_limit_action.type,
    'string'
  );
  assert.equal(
    payload.paths['/auth/login'].post.responses['413'].content['application/problem+json'].examples
      .payload_too_large.value.error_code,
    'AUTH-413-PAYLOAD-TOO-LARGE'
  );
  assert.equal(
    payload.paths['/auth/refresh'].post.responses['413'].content['application/problem+json'].examples
      .payload_too_large.value.error_code,
    'AUTH-413-PAYLOAD-TOO-LARGE'
  );
  assert.equal('extensions' in payload.components.schemas.ProblemDetails.properties, false);
});

test('health returns degraded when backend connectivity fails', async () => {
  const handlers = createRouteHandlers(config, {
    dependencyProbe: async () => ({
      db: { ok: false, detail: 'db down' },
      redis: { ok: true, detail: 'redis up' }
    })
  });

  const body = await handlers.health('t-1');
  assert.equal(body.ok, false);
  assert.equal(body.request_id, 't-1');
  assert.equal(body.dependencies.db.ok, false);
});

test('smoke marks ok when db and redis are both connected', async () => {
  const handlers = createRouteHandlers(config, {
    dependencyProbe: async () => ({
      db: { ok: true, mode: 'mysql-native' },
      redis: { ok: true, mode: 'ioredis' }
    })
  });

  const body = await handlers.smoke('smoke-route');
  assert.equal(body.ok, true);
  assert.equal(body.chain, 'api -> db/redis');
  assert.equal(body.request_id, 'smoke-route');
});

test('createServer enforces json payload limit with AUTH-413-PAYLOAD-TOO-LARGE', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true',
    API_JSON_BODY_LIMIT_BYTES: '256'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/auth/login`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, application/problem+json'
      },
      body: JSON.stringify({
        phone: '13800000000',
        password: 'x'.repeat(1024)
      })
    });
    const payload = await response.json();
    assert.equal(response.status, 413);
    assert.equal(payload.error_code, 'AUTH-413-PAYLOAD-TOO-LARGE');
    assert.equal(String(response.headers.get('connection') || '').toLowerCase(), 'close');
  } finally {
    await harness.close();
  }
});

test('createServer handles auth routes with trailing slash path', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/auth/login/`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, application/problem+json'
      },
      body: JSON.stringify({
        phone: '13800000000',
        password: 'Passw0rd!'
      })
    });
    const payload = await response.json();
    assert.notEqual(response.status, 404);
    assert.equal(payload.error_code !== undefined || payload.access_token !== undefined, true);
  } finally {
    await harness.close();
  }
});

test('createServer supports CORS preflight for API routes', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true',
    API_CORS_ALLOWED_ORIGINS: 'https://example.test'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/auth/login`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://example.test',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type,authorization,x-request-id'
      }
    });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get('access-control-allow-origin'), 'https://example.test');
    const allowMethods = new Set(
      String(response.headers.get('access-control-allow-methods') || '')
        .split(',')
        .map((method) => method.trim().toUpperCase())
        .filter((method) => method.length > 0)
    );
    assert.deepEqual([...allowMethods], ['POST', 'OPTIONS']);
    assert.ok(
      String(response.headers.get('access-control-allow-headers') || '').includes(
        'Content-Type'
      )
    );
  } finally {
    await harness.close();
  }
});

test('createServer CORS preflight includes HEAD when route is declared as GET', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true',
    API_CORS_ALLOWED_ORIGINS: 'https://example.test'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/health`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://example.test',
        'access-control-request-method': 'HEAD'
      }
    });
    assert.equal(response.status, 204);
    const allowMethods = new Set(
      String(response.headers.get('access-control-allow-methods') || '')
        .split(',')
        .map((method) => method.trim().toUpperCase())
        .filter((method) => method.length > 0)
    );
    assert.deepEqual([...allowMethods], ['GET', 'HEAD', 'OPTIONS']);
  } finally {
    await harness.close();
  }
});

test('createServer CORS preflight does not reflect origins outside allowlist', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true',
    API_CORS_ALLOWED_ORIGINS: 'https://allowed.example'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/auth/login`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://blocked.example',
        'access-control-request-method': 'POST'
      }
    });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get('access-control-allow-origin'), null);
  } finally {
    await harness.close();
  }
});

test('dispatchApiRoute reuses GET handler semantics for HEAD routes', async () => {
  let healthCalls = 0;
  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'HEAD',
    requestId: 'req-head-health',
    handlers: {
      health: async () => {
        healthCalls += 1;
        return { ok: true };
      }
    }
  });

  assert.equal(route.status, 200);
  assert.equal(route.body, '');
  assert.equal(route.headers['content-type'], 'application/json');
  assert.equal(healthCalls, 1);
});

test('dispatchApiRoute returns empty body for HEAD not-found responses', async () => {
  const route = await dispatchApiRoute({
    pathname: '/not-found',
    method: 'HEAD',
    requestId: 'req-head-not-found',
    handlers: {}
  });

  assert.equal(route.status, 404);
  assert.equal(route.body, '');
});

test('dispatchApiRoute returns empty body for HEAD authorization failures', async () => {
  let healthCalls = 0;
  const customRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const routeDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions: customRouteDefinitions
  });

  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'HEAD',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    requestId: 'req-head-forbidden',
    handlers: {
      health: async () => {
        healthCalls += 1;
        return { ok: true };
      },
      authorizeRoute: async () => {
        throw new AuthProblemError({
          status: 403,
          title: 'Forbidden',
          detail: '当前操作无权限',
          errorCode: 'AUTH-403-FORBIDDEN'
        });
      }
    },
    routeDefinitions: customRouteDefinitions,
    routeDeclarationLookup
  });

  assert.equal(route.status, 403);
  assert.equal(route.body, '');
  assert.equal(healthCalls, 0);
});

test('dispatchApiRoute honors injected routeDefinitions as authorization source', async () => {
  let authorizeRouteCalls = 0;
  const customRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const routeDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions: customRouteDefinitions
  });

  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'GET',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    requestId: 'req-route-def-source',
    handlers: {
      health: async () => ({ ok: true }),
      authorizeRoute: async () => {
        authorizeRouteCalls += 1;
      }
    },
    routeDefinitions: customRouteDefinitions,
    routeDeclarationLookup
  });

  assert.equal(route.status, 200);
  assert.equal(authorizeRouteCalls, 1);
});

test('dispatchApiRoute ignores injected declaration lookup when it conflicts with routeDefinitions', async () => {
  let authorizeRouteCalls = 0;
  const protectedRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const injectedRouteDeclarationLookup = {
    routeDefinitions: protectedRouteDefinitions,
    routeDefinitionMap: new Map([
      [
        'GET /health',
        {
          method: 'GET',
          path: '/health',
          access: 'public',
          permission_code: '',
          scope: 'public'
        }
      ]
    ]),
    declaredRoutePaths: new Set(['/health'])
  };

  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'GET',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    requestId: 'req-route-def-bypass-attempt',
    handlers: {
      health: async () => ({ ok: true, bypass: true }),
      authorizeRoute: async () => {
        authorizeRouteCalls += 1;
        throw new AuthProblemError({
          status: 403,
          title: 'Forbidden',
          detail: '当前操作无权限',
          errorCode: 'AUTH-403-FORBIDDEN'
        });
      }
    },
    routeDefinitions: protectedRouteDefinitions,
    routeDeclarationLookup: injectedRouteDeclarationLookup
  });

  assert.equal(authorizeRouteCalls, 1);
  assert.equal(route.status, 403);
  assert.equal(JSON.parse(route.body).error_code, 'AUTH-403-FORBIDDEN');
});

test('handleApiRoute ignores injected declaration lookup when it conflicts with routeDefinitions', async () => {
  let authorizeRouteCalls = 0;
  const protectedRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const injectedRouteDeclarationLookup = {
    routeDefinitions: protectedRouteDefinitions,
    routeDefinitionMap: new Map([
      [
        'GET /health',
        {
          method: 'GET',
          path: '/health',
          access: 'public',
          permission_code: '',
          scope: 'public'
        }
      ]
    ]),
    declaredRoutePaths: new Set(['/health'])
  };

  const route = await handleApiRoute(
    {
      pathname: '/health',
      method: 'GET',
      headers: {
        authorization: 'Bearer fake-access-token'
      }
    },
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe,
      handlers: {
        health: async () => ({ ok: true, bypass: true }),
        authorizeRoute: async () => {
          authorizeRouteCalls += 1;
          throw new AuthProblemError({
            status: 403,
            title: 'Forbidden',
            detail: '当前操作无权限',
            errorCode: 'AUTH-403-FORBIDDEN'
          });
        }
      },
      routeDefinitions: protectedRouteDefinitions,
      routeDeclarationLookup: injectedRouteDeclarationLookup,
      validateRouteDefinitions: false
    }
  );

  assert.equal(authorizeRouteCalls, 1);
  assert.equal(route.status, 403);
  assert.equal(JSON.parse(route.body).error_code, 'AUTH-403-FORBIDDEN');
});

test('dispatchApiRoute passes authorizeRoute context as object payload', async () => {
  const customRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const routeDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions: customRouteDefinitions
  });
  let authorizeRoutePayload = null;

  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'GET',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    requestId: 'req-authorize-signature',
    handlers: {
      health: async () => ({ ok: true }),
      authorizeRoute: async (payload) => {
        authorizeRoutePayload = payload;
      }
    },
    routeDefinitions: customRouteDefinitions,
    routeDeclarationLookup
  });

  assert.equal(route.status, 200);
  assert.deepEqual(authorizeRoutePayload, {
    requestId: 'req-authorize-signature',
    authorization: 'Bearer fake-access-token',
    permissionCode: 'auth.session.logout',
    scope: 'session'
  });
});

test('dispatchApiRoute returns structured 500 when authorizeRoute handler is missing', async () => {
  const customRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const routeDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions: customRouteDefinitions
  });

  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'GET',
    headers: { authorization: 'Bearer fake-token' },
    requestId: 'req-no-authorize-handler',
    handlers: {
      health: async () => ({ ok: true })
    },
    routeDefinitions: customRouteDefinitions,
    routeDeclarationLookup
  });

  assert.equal(route.status, 500);
  const body = JSON.parse(route.body);
  assert.equal(body.error_code, 'AUTH-500-AUTHORIZE-HANDLER-MISSING');
  assert.equal(body.request_id, 'req-no-authorize-handler');
});

test('handleApiRoute fails fast when authService lacks authorizeRoute capability for protected routes', async () => {
  const customRouteDefinitions = [
    {
      method: 'POST',
      path: '/auth/logout',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];

  await assert.rejects(
    () =>
      handleApiRoute(
        {
          pathname: '/auth/logout',
          method: 'POST',
          headers: {
            authorization: 'Bearer fake-access-token'
          },
          body: {}
        },
        readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
        {
          dependencyProbe,
          authService: {
            logout: async () => ({ ok: true })
          },
          routeDefinitions: customRouteDefinitions,
          validateRouteDefinitions: false
        }
      ),
    /Route authorization preflight failed: missing authorizeRoute handler for protected routes: POST \/auth\/logout/
  );
});

test('createServer fails fast when protected routes exist but authService lacks authorizeRoute capability', () => {
  assert.throws(
    () =>
      createServer(readConfig({ ALLOW_MOCK_BACKENDS: 'true' }), {
        dependencyProbe,
        authService: {
          logout: async () => ({ ok: true })
        }
      }),
    /Route authorization preflight failed: missing authorizeRoute handler for protected routes:/
  );
});

test('createServer fails fast when route declarations are incomplete', () => {
  assert.throws(
    () =>
      createServer(readConfig({ ALLOW_MOCK_BACKENDS: 'true' }), {
        dependencyProbe,
        routeDefinitions: [
          {
            method: 'GET',
            path: '/health',
            access: 'public',
            permission_code: '',
            scope: 'public'
          }
        ]
      }),
    /executable routes missing declarations/
  );
});

test('resolveRouteDeclarationLookup reuses cached lookup for identical routeDefinitions source', () => {
  const customRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'public',
      permission_code: '',
      scope: 'public'
    },
    {
      method: 'POST',
      path: '/auth/logout',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];

  const firstLookup = resolveRouteDeclarationLookup({
    routeDefinitions: customRouteDefinitions
  });
  const secondLookup = resolveRouteDeclarationLookup({
    routeDefinitions: customRouteDefinitions
  });

  assert.equal(firstLookup, secondLookup);
});

test('dispatchApiRoute resists lookup poisoning via resolved declaration cache object mutation attempts', async () => {
  let authorizeRouteCalls = 0;
  const protectedRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const routeDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions: protectedRouteDefinitions
  });

  if (routeDeclarationLookup.routeDefinitionMap instanceof Map) {
    routeDeclarationLookup.routeDefinitionMap.set('GET /health', {
      method: 'GET',
      path: '/health',
      access: 'public',
      permission_code: '',
      scope: 'public'
    });
  }
  if (routeDeclarationLookup.declaredRoutePaths instanceof Set) {
    routeDeclarationLookup.declaredRoutePaths.add('/health');
  }

  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'GET',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    requestId: 'req-route-declaration-lookup-poisoning',
    handlers: {
      health: async () => ({ ok: true, poisoned: true }),
      authorizeRoute: async () => {
        authorizeRouteCalls += 1;
        throw new AuthProblemError({
          status: 403,
          title: 'Forbidden',
          detail: '当前操作无权限',
          errorCode: 'AUTH-403-FORBIDDEN'
        });
      }
    },
    routeDefinitions: protectedRouteDefinitions,
    routeDeclarationLookup
  });

  assert.equal(authorizeRouteCalls, 1);
  assert.equal(route.status, 403);
  assert.equal(JSON.parse(route.body).error_code, 'AUTH-403-FORBIDDEN');
});

test('createServer uses immutable snapshot for custom routeDefinitions at startup', async () => {
  const customRouteDefinitions = cloneRouteDefinitions(ROUTE_DEFINITIONS);
  const protectedProbeRoute = customRouteDefinitions.find(
    (routeDefinition) =>
      routeDefinition.method === 'GET'
      && routeDefinition.path === '/auth/tenant/member-admin/probe'
  );
  assert.ok(protectedProbeRoute);

  const harness = await startServer(
    { ALLOW_MOCK_BACKENDS: 'true' },
    {
      dependencyProbe,
      routeDefinitions: customRouteDefinitions
    }
  );

  protectedProbeRoute.access = 'public';
  protectedProbeRoute.permission_code = '';
  protectedProbeRoute.scope = 'public';

  try {
    const response = await fetch(`${harness.baseUrl}/auth/tenant/member-admin/probe`, {
      headers: {
        accept: 'application/problem+json'
      }
    });
    const payload = await response.json();

    assert.equal(response.status, 401);
    assert.equal(payload.error_code, 'AUTH-401-INVALID-ACCESS');
  } finally {
    await harness.close();
  }
});

test('handleApiRoute fails fast when route declarations are incomplete', async () => {
  await assert.rejects(
    () =>
      handleApiRoute(
        {
          pathname: '/health',
          method: 'GET',
          headers: {}
        },
        readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
        {
          dependencyProbe,
          routeDefinitions: [
            {
              method: 'GET',
              path: '/health',
              access: 'public',
              permission_code: '',
              scope: 'public'
            }
          ]
        }
      ),
    /executable routes missing declarations/
  );
});

test('handleApiRoute fails preflight when route declaration uses HEAD method', async () => {
  await assert.rejects(
    () =>
      handleApiRoute(
        {
          pathname: '/health',
          method: 'HEAD',
          headers: {}
        },
        readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
        {
          dependencyProbe,
          routeDefinitions: [
            {
              method: 'HEAD',
              path: '/health',
              access: 'public',
              permission_code: '',
              scope: 'public'
            }
          ]
        }
      ),
    /invalid route declaration fields: HEAD \/health \(invalid method: HEAD\)/
  );
});

test('handleApiRoute re-evaluates mutable route definitions for authorization preflight', async () => {
  const mutableRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'public',
      permission_code: '',
      scope: 'public'
    }
  ];
  const handlers = {
    health: async () => ({ ok: true })
  };

  const firstRoute = await handleApiRoute(
    {
      pathname: '/health',
      method: 'GET',
      headers: {}
    },
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe,
      handlers,
      routeDefinitions: mutableRouteDefinitions,
      validateRouteDefinitions: false
    }
  );
  assert.equal(firstRoute.status, 200);

  mutableRouteDefinitions[0].access = 'protected';
  mutableRouteDefinitions[0].permission_code = 'auth.session.logout';
  mutableRouteDefinitions[0].scope = 'session';

  await assert.rejects(
    () =>
      handleApiRoute(
        {
          pathname: '/health',
          method: 'GET',
          headers: {
            authorization: 'Bearer fake-access-token'
          }
        },
        readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
        {
          dependencyProbe,
          handlers,
          routeDefinitions: mutableRouteDefinitions,
          validateRouteDefinitions: false
        }
      ),
    /Route authorization preflight failed: missing authorizeRoute handler for protected routes: GET \/health/
  );
});

test('createServer wraps unexpected route errors as Problem Details 500', async () => {
  const originalConsoleError = console.error;
  const capturedConsoleErrors = [];
  console.error = (...args) => {
    capturedConsoleErrors.push(args);
  };

  const harness = await startServer(
    { ALLOW_MOCK_BACKENDS: 'true' },
    {
      dependencyProbe: async () => {
        throw new Error('db probe exploded');
      }
    }
  );

  try {
    const response = await fetch(`${harness.baseUrl}/health`, {
      signal: AbortSignal.timeout(3000),
      headers: {
        accept: 'application/problem+json',
        'x-request-id': 'req-create-server-internal'
      }
    });
    const payload = await response.json();
    assert.equal(response.status, 500);
    assert.match(String(response.headers.get('content-type') || ''), /application\/problem\+json/i);
    assert.equal(payload.error_code, 'AUTH-500-INTERNAL');
    assert.equal(payload.request_id, 'req-create-server-internal');
    assert.ok(
      capturedConsoleErrors.some(
        ([message, details]) =>
          message === '[api] unhandled route error'
          && details?.request_id === 'req-create-server-internal'
          && String(details?.error_summary || '').includes('db probe exploded')
      )
    );
  } finally {
    console.error = originalConsoleError;
    await harness.close();
  }
});

test('createServer keeps request_id stable when unexpected route errors occur without x-request-id header', async () => {
  const originalConsoleError = console.error;
  const capturedConsoleErrors = [];
  console.error = (...args) => {
    capturedConsoleErrors.push(args);
  };

  let dependencyProbeRequestId = null;
  const harness = await startServer(
    { ALLOW_MOCK_BACKENDS: 'true' },
    {
      dependencyProbe: async (_config, requestId) => {
        dependencyProbeRequestId = requestId;
        throw new Error('db probe exploded');
      }
    }
  );

  try {
    const response = await fetch(`${harness.baseUrl}/health`, {
      signal: AbortSignal.timeout(3000),
      headers: {
        accept: 'application/problem+json'
      }
    });
    const payload = await response.json();

    assert.equal(response.status, 500);
    assert.ok(dependencyProbeRequestId);
    assert.equal(payload.request_id, dependencyProbeRequestId);
    assert.ok(
      capturedConsoleErrors.some(
        ([message, details]) =>
          message === '[api] unhandled route error'
          && details?.request_id === dependencyProbeRequestId
      )
    );
  } finally {
    console.error = originalConsoleError;
    await harness.close();
  }
});

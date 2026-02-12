const http = require('node:http');
const { existsSync, readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { randomUUID } = require('node:crypto');

const fallbackHtml = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Neweast Bootstrap</title>
  </head>
  <body>
    <main>
      <h1>Neweast Bootstrap</h1>
      <p>React + Vite client is not built yet.</p>
    </main>
  </body>
</html>`;

const problem = (status, title, detail, requestId) => ({
  type: 'about:blank',
  title,
  status,
  detail,
  request_id: requestId
});

const readClientHtml = () => {
  const distCandidate = resolve(process.cwd(), 'dist/apps/web/client/index.html');
  const sourceCandidate = resolve(process.cwd(), 'apps/web/index.html');

  if (existsSync(distCandidate)) {
    return readFileSync(distCandidate, 'utf8');
  }

  if (existsSync(sourceCandidate)) {
    return readFileSync(sourceCandidate, 'utf8');
  }

  return fallbackHtml;
};

const createApiTransport = ({ apiBaseUrl, apiClient }) =>
  apiClient ||
  (async (path, requestHeaders, requestOptions = {}) => {
    const upstream = await fetch(`${apiBaseUrl}${path}`, {
      method: requestOptions.method || 'GET',
      headers: requestHeaders,
      body: requestOptions.body
    });

    const rawPayload = await upstream.text();
    let payload = rawPayload;
    try {
      payload = rawPayload.length > 0 ? JSON.parse(rawPayload) : {};
    } catch (_error) {
      payload = rawPayload;
    }

    return {
      status: upstream.status,
      payload,
      headers: {
        'content-type': upstream.headers.get('content-type') || 'application/json'
      }
    };
  });

const selectHeader = (headers, key) => headers[key] || headers[key.toLowerCase()] || headers[key.toUpperCase()];

const forwardableHeaders = (headers, requestId) => {
  const forwarded = { 'x-request-id': requestId };
  const allowlist = ['authorization', 'content-type', 'accept'];

  for (const key of allowlist) {
    const value = selectHeader(headers, key);
    if (typeof value === 'string' && value.length > 0) {
      forwarded[key] = value;
    }
  }

  return forwarded;
};

const parseRequestPath = (inputPath) => {
  const raw = typeof inputPath === 'string' && inputPath.length > 0 ? inputPath : '/';
  try {
    const parsed = new URL(raw, 'http://localhost');
    return {
      pathname: parsed.pathname || '/',
      search: parsed.search || ''
    };
  } catch (_error) {
    const [pathnameOnly, ...queryParts] = raw.split('?');
    return {
      pathname: pathnameOnly || '/',
      search: queryParts.length > 0 ? `?${queryParts.join('?')}` : ''
    };
  }
};

const handleWebRoute = async (
  { pathname, method = 'GET', headers = {}, body = '' },
  { apiBaseUrl, apiClient = null }
) => {
  const requestId = headers['x-request-id'] || randomUUID();
  const transport = createApiTransport({ apiBaseUrl, apiClient });
  const parsedPath = parseRequestPath(pathname);
  const routePath = parsedPath.pathname;
  const routeQuery = parsedPath.search;

  if (routePath === '/health') {
    return {
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ok: true, service: 'web', request_id: requestId })
    };
  }

  if (routePath === '/smoke') {
    try {
      const upstream = await transport(
        '/health',
        { 'x-request-id': requestId },
        { method: 'GET' }
      );
      const payload = upstream.payload;
      const ok =
        upstream.status >= 200 &&
        upstream.status < 300 &&
        payload.dependencies?.db?.ok &&
        payload.dependencies?.redis?.ok;

      return {
        status: ok ? 200 : 503,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          ok,
          chain: 'web -> api -> db/redis',
          request_id: requestId,
          upstream: payload
        })
      };
    } catch (error) {
      return {
        status: 503,
        headers: { 'content-type': 'application/problem+json' },
        body: JSON.stringify(
          problem(503, 'Dependency Unavailable', `Unable to reach API health endpoint: ${error.message}`, requestId)
        )
      };
    }
  }

  if (routePath.startsWith('/api/')) {
    try {
      const apiPath = `${routePath.slice('/api'.length)}${routeQuery}`;
      const upstream = await transport(apiPath, forwardableHeaders(headers, requestId), {
        method,
        body:
          typeof body === 'string' && body.length > 0 && method !== 'GET' && method !== 'HEAD'
            ? body
            : undefined
      });

      return {
        status: upstream.status,
        headers: {
          'content-type': upstream.headers?.['content-type'] || 'application/json'
        },
        body:
          typeof upstream.payload === 'string'
            ? upstream.payload
            : JSON.stringify(upstream.payload || {})
      };
    } catch (error) {
      return {
        status: 503,
        headers: { 'content-type': 'application/problem+json' },
        body: JSON.stringify(
          problem(
            503,
            'Dependency Unavailable',
            `Unable to reach API endpoint: ${error.message}`,
            requestId
          )
        )
      };
    }
  }

  if (routePath === '/' || routePath === '/index.html') {
    return {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
      body: readClientHtml()
    };
  }

  return {
    status: 404,
    headers: { 'content-type': 'application/problem+json' },
    body: JSON.stringify(problem(404, 'Not Found', `No route for ${pathname}`, requestId))
  };
};

const createWebServer = ({ apiBaseUrl }) =>
  http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const body = chunks.length > 0 ? Buffer.concat(chunks).toString('utf8') : '';

    const route = await handleWebRoute(
      {
        pathname: req.url || '/',
        method: req.method || 'GET',
        headers: req.headers,
        body
      },
      { apiBaseUrl }
    );
    res.statusCode = route.status;
    for (const [name, value] of Object.entries(route.headers)) {
      res.setHeader(name, value);
    }
    res.end(route.body);
  });

module.exports = { createWebServer, handleWebRoute };

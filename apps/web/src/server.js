const http = require('node:http');
const { existsSync, readFileSync, statSync } = require('node:fs');
const { extname, posix, resolve, sep } = require('node:path');
const { randomUUID } = require('node:crypto');

const WORKSPACE_ROOT = resolve(__dirname, '../../..');
const CLIENT_DIST_ROOT = resolve(WORKSPACE_ROOT, 'dist/apps/web/client');
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

const CONTENT_TYPE_BY_EXTENSION = Object.freeze({
  '.avif': 'image/avif',
  '.css': 'text/css; charset=utf-8',
  '.gif': 'image/gif',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.pdf': 'application/pdf',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.wasm': 'application/wasm',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.xml': 'application/xml; charset=utf-8'
});
const IMMUTABLE_ASSET_PATTERN = /-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+$/;
const asHttpDate = (value) => new Date(value).toUTCString();
const asWeakEtag = (stat) => `W/"${stat.size}-${Math.floor(stat.mtimeMs)}"`;

const problem = (status, title, detail, requestId) => ({
  type: 'about:blank',
  title,
  status,
  detail,
  request_id: requestId
});

const resolveClientFile = (requestPath) => {
  if (!existsSync(CLIENT_DIST_ROOT)) {
    return null;
  }

  let decodedPath = null;
  try {
    decodedPath = decodeURIComponent(String(requestPath || '/'));
  } catch (_error) {
    return null;
  }

  if (!decodedPath.startsWith('/') || decodedPath.includes('\0') || decodedPath.includes('\\')) {
    return null;
  }

  const segments = decodedPath.split('/');
  if (segments.some((segment) => segment === '..')) {
    return null;
  }

  const normalizedPath = posix.normalize(decodedPath);
  const relativePath = normalizedPath.replace(/^\/+/, '');
  if (!relativePath) {
    return null;
  }

  const absolutePath = resolve(CLIENT_DIST_ROOT, relativePath);
  const allowedPrefix = `${CLIENT_DIST_ROOT}${sep}`;
  if (absolutePath !== CLIENT_DIST_ROOT && !absolutePath.startsWith(allowedPrefix)) {
    return null;
  }

  if (!existsSync(absolutePath)) {
    return null;
  }

  let fileStat = null;
  try {
    fileStat = statSync(absolutePath);
    if (!fileStat.isFile()) {
      return null;
    }
  } catch (_error) {
    return null;
  }

  return { absolutePath, relativePath, stat: fileStat };
};

const resolveContentType = (filePath) =>
  CONTENT_TYPE_BY_EXTENSION[extname(filePath).toLowerCase()] || 'application/octet-stream';

const buildFileRoute = ({
  resolvedFile,
  method = 'GET',
  cacheControl = 'no-cache'
}) => {
  const normalizedMethod = String(method || 'GET').toUpperCase();
  const isHead = normalizedMethod === 'HEAD';
  const stat = resolvedFile.stat;

  return {
    status: 200,
    headers: {
      'content-type': resolveContentType(resolvedFile.absolutePath),
      'cache-control': cacheControl,
      'content-length': String(stat.size),
      etag: asWeakEtag(stat),
      'last-modified': asHttpDate(stat.mtimeMs)
    },
    body: isHead ? '' : readFileSync(resolvedFile.absolutePath)
  };
};

const buildClientShellRoute = ({
  method = 'GET',
  allowFallbackHtml = true
}) => {
  const clientIndex = resolveClientFile('/index.html');
  if (clientIndex) {
    return buildFileRoute({
      resolvedFile: clientIndex,
      method,
      cacheControl: 'no-cache'
    });
  }

  if (!allowFallbackHtml) {
    return null;
  }

  const normalizedMethod = String(method || 'GET').toUpperCase();
  const isHead = normalizedMethod === 'HEAD';
  return {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-cache',
      'content-length': String(Buffer.byteLength(fallbackHtml, 'utf8'))
    },
    body: isHead ? '' : fallbackHtml
  };
};

const buildStaticRoute = (requestPath, method = 'GET') => {
  const normalizedMethod = String(method || 'GET').toUpperCase();
  if (normalizedMethod !== 'GET' && normalizedMethod !== 'HEAD') {
    return null;
  }

  const resolved = resolveClientFile(requestPath);
  if (!resolved) {
    return null;
  }

  const isImmutableAsset =
    resolved.relativePath.startsWith('assets/') &&
    IMMUTABLE_ASSET_PATTERN.test(resolved.relativePath);

  return buildFileRoute({
    resolvedFile: resolved,
    method: normalizedMethod,
    cacheControl: isImmutableAsset
      ? 'public, max-age=31536000, immutable'
      : 'no-cache'
  });
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

const shouldServeSpaFallback = ({ method, routePath, headers }) => {
  const normalizedMethod = String(method || 'GET').toUpperCase();
  if (normalizedMethod !== 'GET' && normalizedMethod !== 'HEAD') {
    return false;
  }

  if (extname(routePath).length > 0) {
    return false;
  }

  const acceptHeader = selectHeader(headers, 'accept');
  if (typeof acceptHeader !== 'string' || acceptHeader.length === 0) {
    return false;
  }

  return acceptHeader.includes('text/html');
};

const handleWebRoute = async (
  { pathname, method = 'GET', headers = {}, body = '' },
  { apiBaseUrl, apiClient = null }
) => {
  const normalizedMethod = String(method || 'GET').toUpperCase();
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
        method: normalizedMethod,
        body:
          typeof body === 'string' &&
          body.length > 0 &&
          normalizedMethod !== 'GET' &&
          normalizedMethod !== 'HEAD'
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

  if (
    (routePath === '/' || routePath === '/index.html')
    && (normalizedMethod === 'GET' || normalizedMethod === 'HEAD')
  ) {
    return buildClientShellRoute({
      method: normalizedMethod,
      allowFallbackHtml: true
    });
  }

  const staticRoute = buildStaticRoute(routePath, normalizedMethod);
  if (staticRoute) {
    return staticRoute;
  }

  if (shouldServeSpaFallback({ method, routePath, headers })) {
    const clientShellRoute = buildClientShellRoute({
      method: normalizedMethod,
      allowFallbackHtml: false
    });
    if (clientShellRoute) {
      return clientShellRoute;
    }

    return {
      status: 503,
      headers: { 'content-type': 'application/problem+json' },
      body: JSON.stringify(
        problem(
          503,
          'Client Build Missing',
          'Client entrypoint index.html is missing from dist/apps/web/client',
          requestId
        )
      )
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
    if ((req.method || 'GET').toUpperCase() === 'HEAD') {
      res.end();
      return;
    }

    res.end(route.body);
  });

module.exports = { createWebServer, handleWebRoute };

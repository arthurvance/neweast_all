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

const handleWebRoute = async (
  { pathname, headers = {} },
  { apiBaseUrl, apiClient = null }
) => {
  const requestId = headers['x-request-id'] || randomUUID();

  if (pathname === '/health') {
    return {
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ok: true, service: 'web', request_id: requestId })
    };
  }

  if (pathname === '/smoke') {
    try {
      const transport =
        apiClient ||
        (async (path, requestHeaders) => {
          const response = await fetch(`${apiBaseUrl}${path}`, {
            headers: requestHeaders
          });
          const payload = await response.json();
          return { status: response.status, payload };
        });

      const upstream = await transport('/health', { 'x-request-id': requestId });
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

  if (pathname === '/' || pathname === '/index.html') {
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
    const route = await handleWebRoute(
      { pathname: req.url || '/', headers: req.headers },
      { apiBaseUrl }
    );
    res.statusCode = route.status;
    for (const [name, value] of Object.entries(route.headers)) {
      res.setHeader(name, value);
    }
    res.end(route.body);
  });

module.exports = { createWebServer, handleWebRoute };

const { createWebServer } = require('./src/server');

const WEB_PORT = Number(process.env.WEB_PORT || 4173);
const WEB_HOST = process.env.WEB_HOST || '0.0.0.0';
const API_BASE_URL = process.env.API_BASE_URL || 'http://api:3000';

const server = createWebServer({ apiBaseUrl: API_BASE_URL });
server.listen(WEB_PORT, WEB_HOST, () => {
  process.stdout.write(
    `${JSON.stringify({
      ts: new Date().toISOString(),
      level: 'info',
      message: 'Web server started',
      host: WEB_HOST,
      port: WEB_PORT,
      api_base_url: API_BASE_URL
    })}\n`
  );
});

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
});

process.on('SIGINT', () => {
  server.close(() => process.exit(0));
});

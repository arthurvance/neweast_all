const { createApiApp } = require('./app');
const { readConfig } = require('./config/env');
const { log } = require('./common/logger');

const bootstrap = async () => {
  const config = readConfig();
  const app = await createApiApp(config);

  await app.listen(config.API_PORT, config.API_HOST);

  log('info', 'API server started (NestJS)', {
    request_id: 'request_id_unset',
    host: config.API_HOST,
    port: config.API_PORT
  });

  const shutdown = async () => {
    await app.close();
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
};

bootstrap().catch((error) => {
  log('error', 'API bootstrap failed', {
    request_id: 'request_id_unset',
    detail: error.message
  });
  process.exit(1);
});

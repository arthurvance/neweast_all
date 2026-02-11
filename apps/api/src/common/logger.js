const log = (level, message, extra = {}) => {
  const entry = {
    ts: new Date().toISOString(),
    level,
    message,
    request_id: extra.request_id ?? 'request_id_unset',
    ...extra
  };
  process.stdout.write(`${JSON.stringify(entry)}\n`);
};

module.exports = { log };

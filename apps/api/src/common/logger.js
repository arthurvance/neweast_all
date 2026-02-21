const { normalizeRequestId, normalizeTraceparent } = require('./trace-context');

const log = (level, message, extra = {}) => {
  const normalizedRequestId =
    normalizeRequestId(extra.request_id) || 'request_id_unset';
  const normalizedTraceparent = normalizeTraceparent(extra.traceparent);
  const entry = {
    ts: new Date().toISOString(),
    level,
    message,
    ...extra,
    request_id: normalizedRequestId,
    traceparent: normalizedTraceparent
  };
  process.stdout.write(`${JSON.stringify(entry)}\n`);
};

module.exports = { log };

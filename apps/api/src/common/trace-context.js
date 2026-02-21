const { randomBytes, randomUUID } = require('node:crypto');

const TRACEPARENT_PATTERN = /^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/i;
const REQUEST_ID_MAX_LENGTH = 128;
const REQUEST_ID_CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/g;

const normalizeRequestId = (value) => {
  if (value === null || value === undefined) {
    return '';
  }
  if (
    typeof value !== 'string'
    && typeof value !== 'number'
    && typeof value !== 'bigint'
    && typeof value !== 'boolean'
  ) {
    return '';
  }
  const normalized = String(value)
    .replace(REQUEST_ID_CONTROL_CHAR_PATTERN, ' ')
    .trim();
  if (!normalized) {
    return '';
  }
  return normalized.slice(0, REQUEST_ID_MAX_LENGTH);
};

const normalizeTraceparent = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  const normalized = String(value).trim().toLowerCase();
  if (!normalized || !TRACEPARENT_PATTERN.test(normalized)) {
    return null;
  }
  const [version = '', traceId = '', parentId = '', traceFlags = ''] = normalized.split('-');
  if (
    /^0+$/.test(traceId)
    || /^0+$/.test(parentId)
    || version === 'ff'
    || traceFlags.length !== 2
  ) {
    return null;
  }
  return normalized;
};

const createTraceHex = (bytes) => randomBytes(bytes).toString('hex');

const createTraceparent = ({ sampled = true } = {}) => {
  let traceId = createTraceHex(16);
  while (/^0+$/.test(traceId)) {
    traceId = createTraceHex(16);
  }
  let parentId = createTraceHex(8);
  while (/^0+$/.test(parentId)) {
    parentId = createTraceHex(8);
  }
  return `00-${traceId}-${parentId}-${sampled ? '01' : '00'}`;
};

const readHeaderValues = (headers = {}, headerName = '') => {
  const normalizedHeaderName = String(headerName || '').trim().toLowerCase();
  if (!normalizedHeaderName) {
    return [];
  }
  const collectedValues = [];
  for (const [key, value] of Object.entries(headers || {})) {
    if (String(key || '').trim().toLowerCase() !== normalizedHeaderName) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        collectedValues.push(String(item ?? ''));
      }
      continue;
    }
    collectedValues.push(String(value ?? ''));
  }
  return collectedValues;
};

const hasHeader = (headers = {}, headerName = '') => {
  const normalizedHeaderName = String(headerName || '').trim().toLowerCase();
  if (!normalizedHeaderName) {
    return false;
  }
  return Object.keys(headers || {}).some(
    (key) => String(key || '').trim().toLowerCase() === normalizedHeaderName
  );
};

const removeHeadersCaseInsensitive = (headers = {}, headerNames = []) => {
  const normalizedHeaderNames = new Set(
    (Array.isArray(headerNames) ? headerNames : [])
      .map((headerName) => String(headerName || '').trim().toLowerCase())
      .filter((headerName) => headerName.length > 0)
  );
  const nextHeaders = {};
  for (const [key, value] of Object.entries(headers || {})) {
    const normalizedKey = String(key || '').trim().toLowerCase();
    if (normalizedHeaderNames.has(normalizedKey)) {
      continue;
    }
    nextHeaders[key] = value;
  }
  return nextHeaders;
};

const mergeReplayTraceContext = ({ original = {}, replay = {} } = {}) => {
  const originalRequestId =
    normalizeRequestId(
      original.request_id
      || original.requestId
      || original.request_id
    ) || 'request_id_unset';
  const originalTraceparent = normalizeTraceparent(
    original.traceparent
  );
  const replayRequestId = normalizeRequestId(
    replay.request_id
    || replay.requestId
  );
  const replayTraceparent = normalizeTraceparent(replay.traceparent);
  return {
    request_id: originalRequestId,
    traceparent: originalTraceparent,
    replay_request_id:
      replayRequestId && replayRequestId !== originalRequestId
        ? replayRequestId
        : null,
    replay_traceparent:
      replayTraceparent && replayTraceparent !== originalTraceparent
        ? replayTraceparent
        : null
  };
};

const extract = ({
  source = {},
  channel = 'http',
  fallbackRequestId = 'request_id_unset',
  generateTraceparentOnMissing = false
} = {}) => {
  const normalizedChannel = String(channel || 'http').trim().toLowerCase();
  let requestId = '';
  let traceparent = null;
  let traceparentProvided = false;

  if (normalizedChannel === 'http') {
    const requestIdValues = readHeaderValues(source, 'x-request-id');
    const normalizedRequestIdValues = requestIdValues
      .map((value) => normalizeRequestId(value))
      .filter((value) => value.length > 0);
    const hasAmbiguousRequestId =
      requestIdValues.length > 1
      || normalizedRequestIdValues.some((value) => value.includes(','))
      || normalizedRequestIdValues.length !== 1;
    requestId = hasAmbiguousRequestId ? '' : normalizedRequestIdValues[0];

    traceparentProvided = hasHeader(source, 'traceparent');
    const traceparentValues = readHeaderValues(source, 'traceparent');
    const hasAmbiguousTraceparent =
      traceparentValues.length > 1
      || traceparentValues.some((value) => String(value || '').includes(','));
    traceparent = hasAmbiguousTraceparent
      ? null
      : normalizeTraceparent(traceparentValues[0]);
  } else {
    requestId = normalizeRequestId(source?.request_id || source?.requestId);
    traceparentProvided =
      Object.prototype.hasOwnProperty.call(source || {}, 'traceparent');
    traceparent = normalizeTraceparent(source?.traceparent);
  }

  if (!requestId) {
    requestId = normalizeRequestId(fallbackRequestId) || 'request_id_unset';
  }
  if (
    !traceparent
    && generateTraceparentOnMissing
    && !traceparentProvided
  ) {
    traceparent = createTraceparent();
  }

  return {
    requestId,
    traceparent
  };
};

const inject = ({
  traceContext = {},
  target = {},
  channel = 'http',
  schemaVersion = '1',
  eventId = randomUUID(),
  occurredAt = new Date().toISOString(),
  replayContext = null
} = {}) => {
  const normalizedChannel = String(channel || 'http').trim().toLowerCase();
  const requestId =
    normalizeRequestId(traceContext.requestId || traceContext.request_id)
    || 'request_id_unset';
  const traceparent = normalizeTraceparent(traceContext.traceparent);

  if (normalizedChannel === 'http') {
    const headers = removeHeadersCaseInsensitive(target, [
      'x-request-id',
      'traceparent'
    ]);
    headers['x-request-id'] = requestId;
    if (traceparent) {
      headers.traceparent = traceparent;
    }
    return headers;
  }

  const envelope = {
    ...(target || {}),
    event_id: String(eventId || '').trim() || randomUUID(),
    request_id: requestId,
    traceparent,
    occurred_at: String(occurredAt || '').trim() || new Date().toISOString(),
    schema_version: String(schemaVersion || '1').trim() || '1'
  };
  if (replayContext && typeof replayContext === 'object') {
    const replayTrace = mergeReplayTraceContext({
      original: envelope,
      replay: replayContext
    });
    envelope.request_id = replayTrace.request_id;
    envelope.traceparent = replayTrace.traceparent;
    envelope.replay_request_id = replayTrace.replay_request_id;
    envelope.replay_traceparent = replayTrace.replay_traceparent;
  }
  return envelope;
};

module.exports = {
  TRACEPARENT_PATTERN,
  normalizeRequestId,
  normalizeTraceparent,
  createTraceparent,
  extract,
  inject,
  mergeReplayTraceContext
};

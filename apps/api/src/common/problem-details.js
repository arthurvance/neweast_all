const { normalizeRequestId, normalizeTraceparent } = require('./trace-context');

const buildProblemDetails = ({
  type = 'about:blank',
  title,
  status,
  detail,
  requestId,
  traceparent = null,
  extensions = {}
}) => {
  const normalizedExtensions = {
    ...extensions
  };
  if (typeof normalizedExtensions.retryable !== 'boolean') {
    normalizedExtensions.retryable = false;
  }
  const normalizedRequestId =
    normalizeRequestId(requestId) || 'request_id_unset';
  const normalizedTraceparent = normalizeTraceparent(traceparent);

  return {
    type,
    title,
    status,
    detail,
    ...normalizedExtensions,
    request_id: normalizedRequestId,
    traceparent: normalizedTraceparent
  };
};

const sendProblemDetails = (res, payload) => {
  const body = JSON.stringify(buildProblemDetails(payload));
  res.statusCode = payload.status;
  res.setHeader('content-type', 'application/problem+json');
  res.end(body);
};

module.exports = { buildProblemDetails, sendProblemDetails };

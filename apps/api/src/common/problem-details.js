const buildProblemDetails = ({
  type = 'about:blank',
  title,
  status,
  detail,
  requestId,
  extensions = {}
}) => {
  const normalizedExtensions = {
    ...extensions
  };
  if (typeof normalizedExtensions.retryable !== 'boolean') {
    normalizedExtensions.retryable = false;
  }

  return {
    type,
    title,
    status,
    detail,
    request_id: requestId || 'request_id_unset',
    ...normalizedExtensions
  };
};

const sendProblemDetails = (res, payload) => {
  const body = JSON.stringify(buildProblemDetails(payload));
  res.statusCode = payload.status;
  res.setHeader('content-type', 'application/problem+json');
  res.end(body);
};

module.exports = { buildProblemDetails, sendProblemDetails };

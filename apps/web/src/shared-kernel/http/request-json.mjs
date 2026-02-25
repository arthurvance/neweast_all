const API_BASE_URL = String(import.meta?.env?.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
const RETRY_SUFFIX = '请稍后重试';

export const readJsonSafely = async (response) => {
  const contentType = response.headers.get('content-type') || '';
  if (
    contentType.includes('application/json')
    || contentType.includes('application/problem+json')
  ) {
    try {
      return await response.json();
    } catch (_error) {
      return {};
    }
  }

  const text = await response.text();
  return {
    detail: text || '请求失败'
  };
};

export const toSearch = (query = {}) => {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === null || value === undefined || value === '') {
      continue;
    }
    searchParams.set(key, String(value));
  }
  const search = searchParams.toString();
  return search ? `?${search}` : '';
};

export const toProblemMessage = (error, fallback = '操作失败') => {
  const detail = String(error?.payload?.detail || error?.message || fallback || '').trim();
  if (!detail) {
    return `${fallback}，${RETRY_SUFFIX}`;
  }
  if (detail.includes(RETRY_SUFFIX)) {
    return detail;
  }
  return `${detail}，${RETRY_SUFFIX}`;
};

export const createApiRequest = ({
  accessToken: defaultAccessToken,
  apiBaseUrl = API_BASE_URL
} = {}) =>
  async ({
    path,
    method = 'GET',
    payload,
    idempotencyKey = null,
    accessToken = defaultAccessToken
  }) => {
    const headers = {
      Accept: 'application/json, application/problem+json'
    };

    if (accessToken) {
      headers.Authorization = `Bearer ${accessToken}`;
    }
    if (payload !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    if (idempotencyKey) {
      headers['Idempotency-Key'] = String(idempotencyKey);
    }

    const response = await fetch(`${apiBaseUrl}${path}`, {
      method,
      headers,
      body: payload === undefined ? undefined : JSON.stringify(payload)
    });

    const body = await readJsonSafely(response);
    if (response.ok) {
      return body;
    }

    const error = new Error(body?.detail || '请求失败');
    error.status = response.status;
    error.payload = body || {};
    throw error;
  };

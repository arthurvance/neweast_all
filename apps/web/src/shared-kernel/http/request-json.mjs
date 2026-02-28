const API_BASE_URL = String(import.meta?.env?.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
const RETRY_SUFFIX = '请稍后重试';
const AUTH_INVALID_ACCESS_ERROR_CODE = 'AUTH-401-INVALID-ACCESS';
const AUTO_REFRESH_EXCLUDED_PATH_SET = new Set([
  '/auth/login',
  '/auth/otp/send',
  '/auth/otp/login',
  '/auth/refresh'
]);

const AUTH_REQUEST_HOOKS = {
  getAccessToken: null,
  refreshAccessToken: null
};

const normalizeErrorCode = (payload = {}) =>
  String(payload?.error_code || payload?.errorCode || '').trim().toUpperCase();

const normalizePathnameForAuthPolicy = (path = '') => {
  const normalizedPath = String(path || '').trim();
  if (!normalizedPath) {
    return '';
  }
  const queryIndex = normalizedPath.indexOf('?');
  const pathname = queryIndex >= 0 ? normalizedPath.slice(0, queryIndex) : normalizedPath;
  return pathname.toLowerCase();
};

const shouldSkipAutoRefreshForPath = (path = '') =>
  AUTO_REFRESH_EXCLUDED_PATH_SET.has(normalizePathnameForAuthPolicy(path));

const readHookAccessToken = () => {
  if (typeof AUTH_REQUEST_HOOKS.getAccessToken !== 'function') {
    return '';
  }
  try {
    return String(AUTH_REQUEST_HOOKS.getAccessToken() || '').trim();
  } catch (_error) {
    return '';
  }
};

export const configureAuthRequestHooks = ({
  getAccessToken = null,
  refreshAccessToken = null
} = {}) => {
  AUTH_REQUEST_HOOKS.getAccessToken =
    typeof getAccessToken === 'function' ? getAccessToken : null;
  AUTH_REQUEST_HOOKS.refreshAccessToken =
    typeof refreshAccessToken === 'function' ? refreshAccessToken : null;
};

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
  async (requestOptions = {}) => {
    const {
      path,
      method = 'GET',
      payload,
      idempotencyKey = null
    } = requestOptions;
    const hasExplicitAccessToken = Object.prototype.hasOwnProperty.call(
      requestOptions,
      'accessToken'
    );
    const explicitAccessToken = hasExplicitAccessToken
      ? requestOptions.accessToken
      : undefined;
    const resolvedDefaultAccessToken = hasExplicitAccessToken
      ? explicitAccessToken
      : (
        typeof defaultAccessToken === 'function'
          ? defaultAccessToken()
          : defaultAccessToken
      );
    const normalizedDefaultAccessToken = String(
      resolvedDefaultAccessToken || ''
    ).trim();
    const hookAccessToken = hasExplicitAccessToken
      ? ''
      : readHookAccessToken();
    const baseAccessToken = normalizedDefaultAccessToken && hookAccessToken
      ? (normalizedDefaultAccessToken === hookAccessToken
        ? normalizedDefaultAccessToken
        : hookAccessToken)
      : (normalizedDefaultAccessToken || hookAccessToken);

    const executeRequest = async (resolvedAccessToken) => {
      const headers = {
        Accept: 'application/json, application/problem+json'
      };

      if (resolvedAccessToken) {
        headers.Authorization = `Bearer ${resolvedAccessToken}`;
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
      return {
        response,
        body
      };
    };

    let activeAccessToken = baseAccessToken;
    let { response, body } = await executeRequest(activeAccessToken);

    const canAttemptAutoRefresh = Boolean(
      activeAccessToken
      && response.status === 401
      && normalizeErrorCode(body) === AUTH_INVALID_ACCESS_ERROR_CODE
      && !shouldSkipAutoRefreshForPath(path)
      && typeof AUTH_REQUEST_HOOKS.refreshAccessToken === 'function'
    );
    if (canAttemptAutoRefresh) {
      try {
        const nextAccessTokenCandidate = await AUTH_REQUEST_HOOKS.refreshAccessToken({
          reason: 'invalid-access',
          path: String(path || ''),
          method: String(method || 'GET').toUpperCase(),
          previousAccessToken: activeAccessToken
        });
        const nextAccessToken = String(
          nextAccessTokenCandidate || readHookAccessToken() || ''
        ).trim();
        if (nextAccessToken) {
          activeAccessToken = nextAccessToken;
          ({ response, body } = await executeRequest(activeAccessToken));
        }
      } catch (_error) {
        // Keep original response semantics when refresh fails.
      }
    }

    if (response.ok) {
      return body;
    }

    const error = new Error(body?.detail || '请求失败');
    error.status = response.status;
    error.payload = body || {};
    throw error;
  };
